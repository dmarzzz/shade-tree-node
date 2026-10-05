//! The local HTTP CONNECT proxy that agents, SearXNG and browsers point at.
//!
//! Every connection is its own task: tunnels are never pinned to prover workers, so long-lived
//! keep-alive tunnels do not starve new ones. Proving is bounded by the client's prover, tunnel
//! setup by `max_setups`, and open tunnels by `max_tunnels`.
//!
//! Local API (all authenticated with the proxy token):
//! - `CONNECT host:port` opens a proof-gated tunnel. With the budget queue on (the default,
//!   ADR 0013) a spent budget holds the request for the next epoch; the `200` then carries
//!   `X-ShadeNet-Queued: <seconds waited>`. Failures answer with a status code, an
//!   `X-ShadeNet-Error` code, `Retry-After` when waiting helps, `X-ShadeNet-ETA` (seconds until
//!   a slot is expected, queue included) on `429`, and a JSON body.
//! - `GET /_shadenet/status` returns [`crate::Status`] as JSON.
//! - `GET /_shadenet/plan?count=N` returns a [`crate::Plan`] for `N` tunnels (ADR 0013).
//! - A target outside `targets` (when set) is refused at once with `403 target_not_allowed`,
//!   spending nothing: an allow-list for agents whose runtimes open connections of their own.
//! - `GET /_shadenet/health` (and the legacy `/_shade_tree/health`) returns 204.
//! - `GET /_shadenet/metrics` returns Prometheus text.
//!
//! Credentials: `Proxy-Authorization: Basic base64(shadenet:<token>)` (the user `shade-tree` is
//! accepted for one minor release), or `Authorization: Bearer <token>` on the GET endpoints.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::{Client, Error};

/// Proxy settings.
#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: String,
    pub token: Zeroizing<String>,
    /// Bind a non-loopback address. The token is still required; say so explicitly.
    pub allow_non_loopback: bool,
    /// Open tunnels at once. Beyond this, CONNECT answers 503 `busy`.
    pub max_tunnels: usize,
    /// Tunnels being set up (canopy, proof, onion rendezvous) at once; others wait.
    pub max_setups: usize,
    /// Serve one CONNECT, then return (tests).
    pub once: bool,
    /// Allowed destination hosts: exact names, or `.suffix` for a domain and its subdomains.
    /// Empty allows every host. A refused target spends nothing (ADR 0013, #230).
    pub targets: Vec<String>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen", &self.listen)
            .field("token", &"<redacted>")
            .field("allow_non_loopback", &self.allow_non_loopback)
            .field("max_tunnels", &self.max_tunnels)
            .field("max_setups", &self.max_setups)
            .field("once", &self.once)
            .finish()
    }
}

impl ProxyConfig {
    pub fn new(listen: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
            token: Zeroizing::new(token.into()),
            allow_non_loopback: false,
            max_tunnels: 64,
            max_setups: 16,
            once: false,
            targets: Vec::new(),
        }
    }
}

/// Whether `host` (no port) is allowed by `targets`: exact match, or a `.suffix` entry matches
/// the domain itself and any subdomain. Case-insensitive; an empty list allows everything.
pub fn target_allowed(targets: &[String], host: &str) -> bool {
    if targets.is_empty() {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    targets.iter().any(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        match pattern.strip_prefix('.') {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == pattern,
        }
    })
}

/// Minimum token length. The token is the only thing between other local users and the member's
/// budget.
pub const MIN_TOKEN_LEN: usize = 32;

/// Reject short or non-URL-safe tokens.
pub fn validate_token(token: &str) -> Result<(), Error> {
    if !(MIN_TOKEN_LEN..=256).contains(&token.len())
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~')
    {
        return Err(Error::Config(format!(
            "proxy token must be {MIN_TOKEN_LEN}..=256 URL-safe characters (generate one with `shadenet proxy-token`)"
        )));
    }
    Ok(())
}

/// Bind the listener, refusing non-loopback addresses unless explicitly allowed.
pub async fn bind(config: &ProxyConfig) -> Result<TcpListener, Error> {
    validate_token(&config.token)?;
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|e| Error::Config(format!("bind {}: {e}", config.listen)))?;
    let address = listener
        .local_addr()
        .map_err(|e| Error::Config(format!("inspect {}: {e}", config.listen)))?;
    check_bind(address, config.allow_non_loopback)?;
    Ok(listener)
}

fn check_bind(address: SocketAddr, allow_non_loopback: bool) -> Result<(), Error> {
    if address.ip().is_loopback() {
        return Ok(());
    }
    if !allow_non_loopback {
        return Err(Error::Config(format!(
            "refusing non-loopback proxy listener {address}; pass --allow-non-loopback (token still required) or share the proxy's network namespace"
        )));
    }
    tracing::warn!(%address, "proxy listening on a non-loopback address; anyone who can reach it and holds the token spends this member's budget");
    Ok(())
}

/// Serve until the listener fails (or after one CONNECT with `once`).
pub async fn serve(
    client: Arc<Client>,
    listener: TcpListener,
    config: ProxyConfig,
) -> Result<(), Error> {
    let shared = Arc::new(Shared {
        client,
        expected: expected_credentials(&config.token),
        bearer: format!("Bearer {}", config.token.as_str()),
        tunnels: Arc::new(Semaphore::new(config.max_tunnels.max(1))),
        max_tunnels: config.max_tunnels.max(1),
        setups: Arc::new(Semaphore::new(config.max_setups.max(1))),
        targets: config.targets.clone(),
    });
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| Error::Internal(format!("accept: {e}")))?;
        stream.set_nodelay(true).ok();
        if config.once {
            match handle(Arc::clone(&shared), stream).await {
                Handled::Tunnel(result) => return result,
                Handled::Local => continue,
            }
        }
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Handled::Tunnel(Err(error)) = handle(shared, stream).await {
                tracing::info!(%peer, code = error.code(), %error, "CONNECT refused");
            }
        });
    }
}

struct Shared {
    client: Arc<Client>,
    expected: [Zeroizing<String>; 2],
    bearer: String,
    tunnels: Arc<Semaphore>,
    max_tunnels: usize,
    setups: Arc<Semaphore>,
    targets: Vec<String>,
}

enum Handled {
    /// A CONNECT was attempted.
    Tunnel(Result<(), Error>),
    /// A local request (status, health, auth failure, bad request).
    Local,
}

fn expected_credentials(token: &str) -> [Zeroizing<String>; 2] {
    let encode = |user: &str| {
        Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
        ))
    };
    [encode("shadenet"), encode("shade-tree")]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (l, r)| difference | (l ^ r))
        == 0
}

/// A parsed request head.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub method: String,
    pub target: String,
    pub proxy_auth: Vec<String>,
    pub auth: Vec<String>,
    /// Bytes after the header block (early tunnel data).
    pub rest: Vec<u8>,
}

pub(crate) fn parse_head(bytes: &[u8]) -> Result<Option<Head>, String> {
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&bytes[..end])
        .map_err(|_| "request headers are not UTF-8".to_string())?;
    let mut lines = header.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut fields = first.split_whitespace();
    let method = fields.next().unwrap_or("").to_string();
    let target = fields.next().unwrap_or("").to_string();
    if !fields
        .next()
        .is_some_and(|version| version.starts_with("HTTP/1."))
    {
        return Err("expected an HTTP/1.x request line".into());
    }
    let mut proxy_auth = Vec::new();
    let mut auth = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("Proxy-Authorization") {
                proxy_auth.push(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("Authorization") {
                auth.push(value.trim().to_string());
            }
        }
    }
    Ok(Some(Head {
        method,
        target,
        proxy_auth,
        auth,
        rest: bytes[end + 4..].to_vec(),
    }))
}

/// Basic proxy credentials on any request; a bearer token only on the local GET endpoints.
fn authorized(expected: &[Zeroizing<String>; 2], bearer: &str, head: &Head) -> bool {
    if head.proxy_auth.len() == 1 {
        let presented = head.proxy_auth[0].as_bytes();
        return expected
            .iter()
            .any(|expected| constant_time_eq(presented, expected.as_bytes()));
    }
    head.method == "GET"
        && head.proxy_auth.is_empty()
        && head.auth.len() == 1
        && constant_time_eq(head.auth[0].as_bytes(), bearer.as_bytes())
}

async fn read_head(stream: &mut TcpStream) -> Result<Option<Head>, String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let read = async {
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read request: {e}"))?;
            if n == 0 {
                return if bytes.is_empty() {
                    Ok(None)
                } else {
                    Err("client closed before the request completed".to_string())
                };
            }
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(head) = parse_head(&bytes)? {
                return Ok(Some(head));
            }
            if bytes.len() > 16 * 1024 {
                return Err("request headers exceeded 16KiB".into());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .map_err(|_| "request headers timed out".to_string())?
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

/// Serialize a JSON error response.
pub(crate) fn error_response(error: &Error) -> String {
    let mut response = json_error_response(
        error.http_status(),
        error.code(),
        error.retry_after().map(|d| d.as_secs().max(1)),
        &error.to_json(),
    );
    if let Error::BudgetExhausted { retry_after, .. } = error {
        // The queue-aware ETA (ADR 0013): the same number as Retry-After once queued requests
        // ahead are counted, under a name agents can read without parsing the body.
        let marker = "\r\nRetry-After: ";
        if let Some(at) = response.find(marker) {
            let line_end = response[at + 2..]
                .find("\r\n")
                .map(|i| at + 2 + i)
                .unwrap_or(at);
            response.insert_str(
                line_end,
                &format!("\r\nX-ShadeNet-ETA: {}", retry_after.as_secs().max(1)),
            );
        }
    }
    response
}

/// One header line's worth of a cause: no CR/LF, ASCII only, bounded.
fn header_safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                ' '
            }
        })
        .take(240)
        .collect::<String>()
        .trim()
        .to_string()
}

fn json_error_response(
    status: u16,
    code: &str,
    retry_after: Option<u64>,
    body: &serde_json::Value,
) -> String {
    let cause = body["error"]["cause"].as_str().map(header_safe);
    let body = format!("{body}\n");
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nX-ShadeNet-Error: {code}\r\nConnection: close\r\nContent-Length: {}\r\n",
        reason_phrase(status),
        body.len()
    );
    // The cause rides as a header too, so an agent that only sees headers (a CONNECT failure
    // through most HTTP clients) still learns why. The body carries the full `cause` and `fix`.
    if let Some(cause) = cause.filter(|c| !c.is_empty()) {
        response.push_str(&format!("X-ShadeNet-Cause: {cause}\r\n"));
    }
    if let Some(seconds) = retry_after {
        response.push_str(&format!("Retry-After: {seconds}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&body);
    response
}

fn local_error(status: u16, code: &str, message: &str) -> String {
    json_error_response(
        status,
        code,
        (status == 503).then_some(1),
        &serde_json::json!({ "error": { "code": code, "message": message } }),
    )
}

async fn handle(shared: Arc<Shared>, mut stream: TcpStream) -> Handled {
    let head = match read_head(&mut stream).await {
        Ok(Some(head)) => head,
        // A bare connect-and-close is a port probe; answer nothing.
        Ok(None) => return Handled::Local,
        Err(message) => {
            let _ = stream
                .write_all(local_error(400, "bad_request", &message).as_bytes())
                .await;
            return Handled::Local;
        }
    };
    if !authorized(&shared.expected, &shared.bearer, &head) {
        let body = r#"{"error":{"code":"proxy_auth_required","message":"send Proxy-Authorization: Basic base64(shadenet:<token>)"}}"#;
        let response = format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"shadenet\"\r\nContent-Type: application/json\r\nX-ShadeNet-Error: proxy_auth_required\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}\n",
            body.len() + 1
        );
        let _ = stream.write_all(response.as_bytes()).await;
        return Handled::Local;
    }
    match (head.method.as_str(), head.target.as_str()) {
        ("GET", "/_shadenet/health") | ("GET", "/_shade_tree/health") => {
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await;
            Handled::Local
        }
        ("GET", "/_shadenet/status") => {
            let status = shared.client.status().await;
            let body = serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".into()) + "\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            Handled::Local
        }
        ("GET", target) if target.starts_with("/_shadenet/plan") => {
            let count = target
                .split_once('?')
                .map(|(_, query)| query)
                .unwrap_or("")
                .split('&')
                .find_map(|pair| pair.strip_prefix("count="))
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(1);
            let plan = shared.client.plan(count);
            let body = serde_json::to_string_pretty(&plan).unwrap_or_else(|_| "{}".into()) + "\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            Handled::Local
        }
        ("GET", "/_shadenet/metrics") => {
            let body = prometheus(&shared);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            Handled::Local
        }
        ("CONNECT", target) => {
            let target = target.to_string();
            let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target);
            if !target_allowed(&shared.targets, host.trim_matches(|c| c == '[' || c == ']')) {
                let _ = stream
                    .write_all(
                        local_error(
                            403,
                            "target_not_allowed",
                            "this host is not in the proxy's --targets allow-list; nothing was spent",
                        )
                        .as_bytes(),
                    )
                    .await;
                return Handled::Local;
            }
            Handled::Tunnel(tunnel(shared, stream, target, head.rest).await)
        }
        ("GET", _) => {
            let _ = stream
                .write_all(local_error(404, "not_found", "unknown local endpoint").as_bytes())
                .await;
            Handled::Local
        }
        _ => {
            let _ = stream
                .write_all(
                    local_error(
                        405,
                        "method_not_allowed",
                        "only HTTP CONNECT is supported (ShadeNet nodes egress HTTPS only)",
                    )
                    .as_bytes(),
                )
                .await;
            Handled::Local
        }
    }
}

async fn tunnel(
    shared: Arc<Shared>,
    mut stream: TcpStream,
    target: String,
    early: Vec<u8>,
) -> Result<(), Error> {
    let Ok(_tunnel_permit) = Arc::clone(&shared.tunnels).try_acquire_owned() else {
        let _ = stream
            .write_all(local_error(503, "busy", "too many open tunnels; retry shortly").as_bytes())
            .await;
        return Err(Error::Transport("too many open tunnels".into()));
    };
    // The budget queue (ADR 0013) runs before a setup permit is taken, so queued requests never
    // crowd out the ones whose budget is available.
    let mut queued_for = Duration::ZERO;
    if let Some(max_wait) = shared.client.config().queue_max_wait {
        match shared.client.wait_for_budget(max_wait).await {
            Ok(waited) => queued_for = waited,
            Err(error) => {
                let _ = stream.write_all(error_response(&error).as_bytes()).await;
                return Err(error);
            }
        }
    }
    let setup_permit = match tokio::time::timeout(
        Duration::from_secs(60),
        Arc::clone(&shared.setups).acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => {
            let _ = stream
                .write_all(
                    local_error(503, "busy", "tunnel setup queue is full; retry shortly")
                        .as_bytes(),
                )
                .await;
            return Err(Error::Transport("tunnel setup queue is full".into()));
        }
    };
    // The time already spent in the queue above counts: the whole hold honours `--max-wait`,
    // and `X-ShadeNet-Queued` is the total.
    let connect = match shared.client.config().queue_max_wait {
        Some(max_wait) => {
            shared
                .client
                .connect_after_wait(&target, max_wait, queued_for)
                .await
        }
        None => shared.client.connect(&target).await,
    };
    let tunnel = match connect {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let _ = stream.write_all(error_response(&error).as_bytes()).await;
            return Err(error);
        }
    };
    drop(setup_permit);
    let gateway = tunnel.gateway.clone();
    let waited = tunnel.waited;
    let mut remote = tunnel.into_stream();
    let relay = async {
        if !early.is_empty() {
            remote.write_all(&early).await?;
            remote.flush().await?;
        }
        let established = if waited.is_zero() {
            "HTTP/1.1 200 Connection Established\r\nProxy-Agent: shadenet-rust\r\n\r\n".to_string()
        } else {
            format!(
                "HTTP/1.1 200 Connection Established\r\nProxy-Agent: shadenet-rust\r\nX-ShadeNet-Queued: {}\r\n\r\n",
                waited.as_secs()
            )
        };
        stream.write_all(established.as_bytes()).await?;
        stream.flush().await?;
        tokio::io::copy_bidirectional(&mut stream, &mut remote).await
    };
    match relay.await {
        Ok((up, down)) => {
            tracing::debug!(%gateway, %target, up, down, "tunnel closed");
        }
        // After 200 the exchange cannot become an HTTP error; a relay error only ends the tunnel.
        Err(error) => tracing::debug!(%gateway, %target, %error, "tunnel ended with an error"),
    }
    Ok(())
}

fn prometheus(shared: &Shared) -> String {
    let m = shared.client.metrics();
    let mut out = String::new();
    let mut counter = |name: &str, help: &str, value: u64| {
        out.push_str(&format!(
            "# HELP shadenet_{name} {help}\n# TYPE shadenet_{name} counter\nshadenet_{name} {value}\n"
        ));
    };
    counter(
        "tunnels_opened_total",
        "Tunnels accepted by a node.",
        m.tunnels_opened,
    );
    counter(
        "tunnels_failed_total",
        "Tunnel attempts that failed.",
        m.tunnels_failed,
    );
    counter(
        "canopy_refreshes_total",
        "Canopy refresh attempts.",
        m.canopy_refreshes,
    );
    counter(
        "canopy_refresh_failures_total",
        "Canopy refreshes that fell back to the copy in use.",
        m.canopy_refresh_failures,
    );
    counter(
        "member_fetches_total",
        "Member-set fetches over JSON-RPC.",
        m.member_fetches,
    );
    counter(
        "member_fetch_failures_total",
        "Member-set fetches that failed.",
        m.member_fetch_failures,
    );
    out.push_str("# HELP shadenet_errors_total Tunnel failures by error code.\n# TYPE shadenet_errors_total counter\n");
    for (code, count) in m.errors {
        out.push_str(&format!(
            "shadenet_errors_total{{code=\"{code}\"}} {count}\n"
        ));
    }
    out.push_str(&format!(
        "# HELP shadenet_tor_bootstrapped Embedded Tor bootstrapped.\n# TYPE shadenet_tor_bootstrapped gauge\nshadenet_tor_bootstrapped {}\n",
        u8::from(shared.client.tor_bootstraps() > 0)
    ));
    out.push_str(&format!(
        "# HELP shadenet_tunnels_open Tunnels open now.\n# TYPE shadenet_tunnels_open gauge\nshadenet_tunnels_open {}\n",
        shared
            .max_tunnels
            .saturating_sub(shared.tunnels.available_permits())
    ));
    let queue = shared.client.queue_status();
    out.push_str(&format!(
        "# HELP shadenet_queue_depth Tunnels waiting for the next epoch's budget.\n# TYPE shadenet_queue_depth gauge\nshadenet_queue_depth {}\n",
        queue.depth
    ));
    out.push_str(&format!(
        "# HELP shadenet_queue_next_slot_seconds Seconds until a new tunnel could open.\n# TYPE shadenet_queue_next_slot_seconds gauge\nshadenet_queue_next_slot_seconds {}\n",
        queue.next_slot_in_seconds
    ));
    out.push_str(&format!(
        "# HELP shadenet_queued_total Tunnels that waited in the budget queue.\n# TYPE shadenet_queued_total counter\nshadenet_queued_total {}\n",
        queue.queued_total
    ));
    out.push_str(&format!(
        "# HELP shadenet_queue_wait_seconds_total Seconds tunnels spent in the budget queue.\n# TYPE shadenet_queue_wait_seconds_total counter\nshadenet_queue_wait_seconds_total {}\n",
        queue.waited_seconds_total
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_parse_with_credentials_and_early_bytes() {
        let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic abc\r\n\r\nEARLY";
        let head = parse_head(raw).unwrap().unwrap();
        assert_eq!(head.method, "CONNECT");
        assert_eq!(head.target, "example.com:443");
        assert_eq!(head.proxy_auth, vec!["Basic abc".to_string()]);
        assert_eq!(head.rest, b"EARLY");
        assert!(parse_head(b"CONNECT x:443 HTTP/1.1\r\n").unwrap().is_none());
        assert!(parse_head(b"CONNECT x:443 SPDY\r\n\r\n").is_err());
    }

    #[test]
    fn target_allow_list_matches_exact_and_suffix() {
        let targets = vec![".example.org".to_string(), "api.ipify.org".to_string()];
        assert!(target_allowed(&[], "anything.test"));
        assert!(target_allowed(&targets, "example.org"));
        assert!(target_allowed(&targets, "www.Example.ORG"));
        assert!(!target_allowed(&targets, "notexample.org"));
        assert!(target_allowed(&targets, "api.ipify.org"));
        assert!(!target_allowed(&targets, "www.api.ipify.org"));
        assert!(!target_allowed(&targets, "api.anthropic.com"));
    }

    #[test]
    fn tokens_must_be_long_and_url_safe() {
        assert!(validate_token("short").is_err());
        assert!(validate_token(&"a".repeat(32)).is_ok());
        assert!(validate_token(&format!("{}:", "a".repeat(32))).is_err());
    }

    #[test]
    fn non_loopback_binds_need_explicit_opt_in() {
        let loopback: SocketAddr = "127.0.0.1:8118".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8118".parse().unwrap();
        assert!(check_bind(loopback, false).is_ok());
        assert!(check_bind(any, false).is_err());
        assert!(check_bind(any, true).is_ok());
    }

    #[test]
    fn error_responses_carry_code_retry_after_and_json() {
        let error = Error::BudgetExhausted {
            detail: "used 1/1".into(),
            retry_after: Duration::from_secs(17),
        };
        let response = error_response(&error);
        assert!(response.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(response.contains("X-ShadeNet-Error: budget_exhausted\r\n"));
        assert!(
            response.contains("X-ShadeNet-Cause: the per-epoch budget is spent"),
            "{response}"
        );
        assert!(response.contains("\"fix\":"));
        assert!(response.contains("Retry-After: 17\r\n"));
        assert!(response.contains("\r\nX-ShadeNet-ETA: 17\r\n"));
        let (head, _) = response.split_once("\r\n\r\n").unwrap();
        assert!(head
            .lines()
            .all(|line| line.is_empty() || line.contains(':') || line.starts_with("HTTP/1.1")));
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let json: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(json["error"]["code"], "budget_exhausted");
        let refused = Error::NodeRefused {
            gateway: "x.onion:80".into(),
            reason: "invalid-proof".into(),
            ack: Box::new(serde_json::json!({"ok": false})),
        };
        assert!(error_response(&refused).starts_with("HTTP/1.1 502 Bad Gateway"));
        let port = Error::PortNotAllowed {
            port: 80,
            allowed: "443".into(),
        };
        assert!(error_response(&port).starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn both_basic_users_and_bearer_are_accepted() {
        let token = "t".repeat(32);
        let expected = expected_credentials(&token);
        let bearer = format!("Bearer {token}");
        let head = |method: &str, proxy: Vec<String>, auth: Vec<String>| Head {
            method: method.into(),
            target: "/_shadenet/status".into(),
            proxy_auth: proxy,
            auth,
            rest: vec![],
        };
        let ok = |h: &Head| authorized(&expected, &bearer, h);
        assert!(ok(&head("CONNECT", vec![expected[0].to_string()], vec![])));
        assert!(ok(&head("CONNECT", vec![expected[1].to_string()], vec![])));
        assert!(!ok(&head("CONNECT", vec!["Basic eDp5".into()], vec![])));
        assert!(!ok(&head(
            "CONNECT",
            vec![expected[0].to_string(), expected[0].to_string()],
            vec![]
        )));
        assert!(ok(&head("GET", vec![], vec![bearer.clone()])));
        assert!(!ok(&head("CONNECT", vec![], vec![bearer.clone()])));
        assert!(!ok(&head("GET", vec![], vec!["Bearer nope".into()])));
    }
}
