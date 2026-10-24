//! One HTTPS request over one proof-gated tunnel.
//!
//! TLS terminates here, end to end with the destination: the node sees only the target host and
//! encrypted bytes. HTTP/1.1, `Connection: close`, one tunnel per request. Callers that want
//! connection reuse should use the local proxy with a keep-alive client instead.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio_rustls::TlsConnector;

use crate::{Client, Error};

/// Largest response body [`Client::fetch`] returns by default.
pub const DEFAULT_MAX_BYTES: usize = 2_000_000;

const SNIFF_BYTES: usize = 64 * 1024;
/// Markers that only count when the status already says the request was refused: many ordinary
/// pages carry a reCAPTCHA comment form or an article about "checking your browser".
const CHALLENGE_MARKERS: [&str; 5] = [
    "cf-chl",
    "<title>just a moment...</title>",
    "checking your browser",
    "enable javascript and cookies to continue",
    "ddos-guard",
];
const CAPTCHA_MARKERS: [&str; 6] = [
    "g-recaptcha",
    "h-captcha",
    "/sorry/index",
    "unusual traffic from your computer",
    "anomaly-modal",
    "are you a robot",
];
/// A 2xx body at most this long that shows a CAPTCHA widget and an interstitial phrase is a
/// CAPTCHA wall rather than a page with a form on it.
const INTERSTITIAL_MAX_BYTES: usize = 16 * 1024;
const CAPTCHA_WIDGETS: [&str; 3] = ["g-recaptcha", "h-captcha", "cf-turnstile"];
const INTERSTITIAL_PHRASES: [&str; 4] = [
    "are you a robot",
    "verify you are human",
    "checking your browser",
    "unusual traffic from your computer",
];

/// Why a site turned a request away, in the categories of `docs/exit-blocking-benchmark.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Block {
    AccessDenied,
    RateLimited,
    Captcha,
    Challenge,
    /// The connection itself failed.
    Unreachable,
}

impl Block {
    /// The block a response shows, if any. A refused status (non-2xx) is read with broad
    /// markers. A 2xx counts as a block only on signals specific to an interstitial: the
    /// Cloudflare challenge page, Google's `/sorry/` page, or a short page that is little more
    /// than a CAPTCHA widget and a "prove you are human" line.
    #[must_use]
    pub fn classify(status: u16, body: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(&body[..body.len().min(SNIFF_BYTES)]).to_lowercase();
        let has = |markers: &[&str]| markers.iter().any(|marker| text.contains(marker));
        if (200..300).contains(&status) {
            if text.contains("<title>just a moment...</title>")
                && has(&["cf-chl", "challenge-platform"])
            {
                return Some(Self::Challenge);
            }
            if text.contains("/sorry/index") && text.contains("unusual traffic from your computer")
            {
                return Some(Self::Captcha);
            }
            if body.len() <= INTERSTITIAL_MAX_BYTES
                && has(&CAPTCHA_WIDGETS)
                && has(&INTERSTITIAL_PHRASES)
            {
                return Some(Self::Captcha);
            }
            return None;
        }
        if has(&CHALLENGE_MARKERS) {
            return Some(Self::Challenge);
        }
        if has(&CAPTCHA_MARKERS) {
            return Some(Self::Captcha);
        }
        match status {
            403 => Some(Self::AccessDenied),
            429 => Some(Self::RateLimited),
            _ => None,
        }
    }
}

/// An HTTPS request.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Response bodies longer than this are truncated.
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl FetchRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: None,
            max_bytes: DEFAULT_MAX_BYTES,
            timeout: Duration::from_secs(120),
        }
    }
}

/// The response and the tunnel that carried it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(skip)]
    pub body: Vec<u8>,
    pub truncated: bool,
    pub gateway: String,
    pub epoch: u64,
}

/// Split an https URL into (host, port, path-and-query). Other schemes are refused: nodes egress
/// HTTPS only, and plain HTTP through a tunnel would hand the node the cleartext.
pub fn parse_https(raw: &str) -> Result<(String, u16, String), Error> {
    let url = url::Url::parse(raw).map_err(|e| Error::Config(format!("bad URL {raw:?}: {e}")))?;
    if url.scheme() != "https" {
        return Err(Error::Config(format!(
            "only https URLs are supported (got {})",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(
            "URLs with credentials are not supported".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::Config(format!("URL {raw:?} has no host")))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok((host, port, path))
}

/// [`parse_https`], and also refuse targets on this machine or its local network: `localhost`,
/// `*.localhost`, `*.local`, and literal loopback, private, link-local, shared (CGNAT),
/// unique-local and unspecified addresses. Used before a request that goes out over this
/// machine's own connection and may then be handed to an exit, so neither route reaches an
/// internal service. Names that resolve to such addresses are not caught here.
pub fn parse_public_https(raw: &str) -> Result<(String, u16, String), Error> {
    let parsed = parse_https(raw)?;
    let url = url::Url::parse(raw).map_err(|e| Error::Config(format!("bad URL {raw:?}: {e}")))?;
    let local = match url.host() {
        Some(url::Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local")
        }
        Some(url::Host::Ipv4(ip)) => local_v4(ip),
        Some(url::Host::Ipv6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => local_v4(v4),
            None => {
                let first = ip.segments()[0];
                ip.is_loopback()
                    || ip.is_unspecified()
                    || first & 0xfe00 == 0xfc00 // unique local fc00::/7
                    || first & 0xffc0 == 0xfe80 // link-local fe80::/10
            }
        },
        None => true,
    };
    if local {
        return Err(Error::Config(format!(
            "refusing {raw:?}: a local or private address"
        )));
    }
    Ok(parsed)
}

fn local_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || (a == 100 && (64..128).contains(&b)) // shared address space 100.64.0.0/10
}

/// Whether a request with this method may be sent a second time: only GET, HEAD and OPTIONS.
/// A retry of anything else could repeat a side effect the first attempt already caused.
#[must_use]
pub fn safe_to_retry(method: &str) -> bool {
    ["GET", "HEAD", "OPTIONS"]
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
}

fn tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

impl Client {
    /// Fetch an https URL through ShadeNet.
    pub async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, Error> {
        let timeout = request.timeout;
        tokio::time::timeout(timeout, self.fetch_inner(request))
            .await
            .map_err(|_| {
                Error::Transport(format!("fetch timed out after {}s", timeout.as_secs()))
            })?
    }

    async fn fetch_inner(&self, request: FetchRequest) -> Result<FetchResponse, Error> {
        let (host, port, path) = parse_https(&request.url)?;
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let tunnel = self.connect(&target).await?;
        let gateway = tunnel.gateway.clone();
        let epoch = tunnel.epoch;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| Error::Config(format!("bad TLS server name {host}: {e}")))?;
        let tls = tls_connector()
            .connect(server_name, tunnel.into_stream())
            .await
            .map_err(|e| Error::Transport(format!("TLS with {host}: {e}")))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| Error::Transport(format!("HTTP handshake with {host}: {e}")))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let host_header = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut builder = http::Request::builder()
            .method(request.method.as_str())
            .uri(path)
            .header(http::header::HOST, host_header)
            .header(http::header::CONNECTION, "close");
        let mut has_user_agent = false;
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("connection") {
                continue;
            }
            has_user_agent |= name.eq_ignore_ascii_case("user-agent");
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !has_user_agent {
            builder = builder.header(
                http::header::USER_AGENT,
                concat!("shadenet/", env!("CARGO_PKG_VERSION")),
            );
        }
        let body = Full::new(Bytes::from(request.body.unwrap_or_default()));
        let http_request = builder
            .body(body)
            .map_err(|e| Error::Config(format!("bad request: {e}")))?;
        let response = sender
            .send_request(http_request)
            .await
            .map_err(|e| Error::Transport(format!("request to {host}: {e}")))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let mut limited = Limited::new(response.into_body(), request.max_bytes);
        let mut body = Vec::new();
        let mut truncated = false;
        loop {
            match limited.frame().await {
                None => break,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        body.extend_from_slice(&data);
                    }
                }
                Some(Err(error)) => {
                    if error.is::<http_body_util::LengthLimitError>() {
                        truncated = true;
                        break;
                    }
                    return Err(Error::Transport(format!("read body from {host}: {error}")));
                }
            }
        }
        driver.abort();
        Ok(FetchResponse {
            status,
            headers,
            body,
            truncated,
            gateway,
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_pass() {
        assert_eq!(
            parse_https("https://example.com/a?b=1").unwrap(),
            ("example.com".into(), 443, "/a?b=1".into())
        );
        assert_eq!(
            parse_https("https://example.com:8443").unwrap(),
            ("example.com".into(), 8443, "/".into())
        );
        assert!(parse_https("http://example.com").is_err());
        assert!(parse_https("https://user:pw@example.com").is_err());
        assert!(parse_https("not a url").is_err());
    }

    #[test]
    fn local_targets_are_refused() {
        for url in [
            "https://localhost/",
            "https://api.localhost:8443/",
            "https://printer.local/",
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://192.168.1.1/",
            "https://172.16.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.100.100.100/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
            "http://example.com/",
        ] {
            assert!(parse_public_https(url).is_err(), "{url} should be refused");
        }
        for url in [
            "https://example.com/",
            "https://1.1.1.1/",
            "https://[2606:4700::1111]/",
        ] {
            assert!(parse_public_https(url).is_ok(), "{url} should pass");
        }
    }

    #[test]
    fn only_safe_methods_are_retried() {
        assert!(safe_to_retry("GET") && safe_to_retry("head") && safe_to_retry("OPTIONS"));
        assert!(!safe_to_retry("POST") && !safe_to_retry("PUT") && !safe_to_retry("DELETE"));
        assert!(!safe_to_retry("PATCH"));
    }

    #[test]
    fn blocks_are_classified() {
        assert_eq!(Block::classify(200, b"<html>results</html>"), None);
        assert_eq!(Block::classify(404, b"not found"), None);
        assert_eq!(Block::classify(403, b""), Some(Block::AccessDenied));
        assert_eq!(Block::classify(429, b""), Some(Block::RateLimited));
        assert_eq!(
            Block::classify(403, b"<title>Just a moment...</title>"),
            Some(Block::Challenge)
        );
        assert_eq!(
            Block::classify(
                200,
                b"<title>Are you a robot?</title><div class=\"g-recaptcha\"></div>"
            ),
            Some(Block::Captcha)
        );
        assert_eq!(
            Block::classify(429, b"<form action=\"/sorry/index\">"),
            Some(Block::Captcha)
        );
    }

    #[test]
    fn ordinary_pages_with_challenge_words_are_not_blocks() {
        let mut blog = String::from("<html><head><title>Notes on tunnels</title></head><body>");
        blog.push_str(&"<p>A long article about onion routing and exit policy.</p>".repeat(400));
        blog.push_str(
            "<form id=\"comment\"><div class=\"g-recaptcha\" data-sitekey=\"x\"></div>\
             <p>Are you a robot? Tick the box to comment.</p></form></body></html>",
        );
        assert_eq!(Block::classify(200, blog.as_bytes()), None);
        let article = b"<html><title>Why sites say checking your browser</title>\
            <p>Cloudflare shows a page with cf-chl in its scripts while checking your browser;\
            DDoS-Guard does the same.</p></html>";
        assert_eq!(Block::classify(200, article), None);
        assert_eq!(
            Block::classify(200, b"<p>Google shows /sorry/index when it is unhappy.</p>"),
            None
        );
    }

    #[test]
    fn real_interstitials_are_blocks() {
        let cloudflare = b"<!DOCTYPE html><html><head><title>Just a moment...</title>\
            <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\"></script>\
            </head><body><div id=\"cf-chl-widget\"></div></body></html>";
        assert_eq!(Block::classify(200, cloudflare), Some(Block::Challenge));
        assert_eq!(Block::classify(403, cloudflare), Some(Block::Challenge));
        let sorry = b"<html><body><form action=\"/sorry/index\">Our systems have detected \
            unusual traffic from your computer network.</form></body></html>";
        assert_eq!(Block::classify(200, sorry), Some(Block::Captcha));
        assert_eq!(Block::classify(429, sorry), Some(Block::Captcha));
        assert_eq!(
            Block::classify(429, b"Too Many Requests"),
            Some(Block::RateLimited)
        );
    }
}
