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
}
