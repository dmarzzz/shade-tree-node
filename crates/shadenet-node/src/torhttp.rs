//! Plain HTTP/1.1 requests to an onion through the local Tor SOCKS port
//! (`packages/node/bootnode/fetch.mjs`), and the same exchange to a bare `host:port` peer.
//! Each request is one connection: the onion layer already encrypts and authenticates, the
//! reply is read to end of stream under a byte cap, and a 4xx other than 408 or 429 is an
//! answer (a refusal) rather than a transport failure to retry.

use std::fmt;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) const DEFAULT_MAX_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const DEFAULT_ATTEMPTS: u32 = 4;

#[derive(Debug)]
pub(crate) enum Error {
    /// The peer spoke HTTP and declined; `reply` is its JSON body when it had one.
    Refusal {
        status: u16,
        reply: Option<Value>,
        body: String,
    },
    Transport(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refusal { status, body, .. } => {
                write!(
                    f,
                    "bootnode HTTP {status}: {}",
                    body.chars().take(200).collect::<String>()
                )
            }
            Self::Transport(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// A refusal is an answer: asking again gets the same one. 408 and 429 stay retryable.
    fn is_refusal(&self) -> bool {
        matches!(self, Self::Refusal { status, .. } if (400..500).contains(status) && *status != 408 && *status != 429)
    }
}

/// Where the local Tor SOCKS port is.
#[derive(Clone)]
pub(crate) struct Socks {
    pub(crate) host: String,
    pub(crate) port: u16,
}

pub(crate) struct Request<'a> {
    pub(crate) method: &'static str,
    pub(crate) path: &'a str,
    pub(crate) body: Option<&'a [u8]>,
    pub(crate) authorization: Option<&'a str>,
    pub(crate) timeout: Duration,
    pub(crate) max_bytes: usize,
}

impl<'a> Request<'a> {
    pub(crate) fn get(path: &'a str) -> Self {
        Self {
            method: "GET",
            path,
            body: None,
            authorization: None,
            timeout: DEFAULT_TIMEOUT,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    pub(crate) fn post(path: &'a str, body: &'a [u8]) -> Self {
        Self {
            method: "POST",
            path,
            body: Some(body),
            authorization: None,
            timeout: DEFAULT_TIMEOUT,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

fn normalize_onion(onion: &str) -> String {
    let base = onion.trim().trim_end_matches(".onion");
    format!("{base}.onion")
}

/// A request to `onion:port` over Tor, retried through onion cold start.
pub(crate) async fn request_over_tor(
    socks: &Socks,
    onion: &str,
    destination_port: u16,
    request: &Request<'_>,
    attempts: u32,
) -> Result<Value, Error> {
    let host = normalize_onion(onion);
    let mut last = String::new();
    for attempt in 0..attempts.max(1) {
        let dial = async {
            let proxy = TcpStream::connect((socks.host.as_str(), socks.port))
                .await
                .map_err(|e| Error::Transport(format!("tor socks unreachable: {e}")))?;
            let stream = socks5_connect(proxy, &host, destination_port).await?;
            exchange(stream, &host, destination_port, request).await
        };
        match tokio::time::timeout(request.timeout, dial).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(e)) if e.is_refusal() => return Err(e),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "timeout".into(),
        }
        if attempt + 1 < attempts {
            let backoff = Duration::from_millis((1000 * u64::from(attempt + 1)).min(4000));
            tokio::time::sleep(backoff).await;
        }
    }
    Err(Error::Transport(format!(
        "bootnode {} failed after {} attempts: {last}",
        request.method,
        attempts.max(1)
    )))
}

/// The same request to a plain `host:port` peer (a private network or a test).
pub(crate) async fn request_plain(
    host: &str,
    port: u16,
    request: &Request<'_>,
) -> Result<Value, Error> {
    let dial = async {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| Error::Transport(format!("connect {host}:{port}: {e}")))?;
        exchange(stream, host, port, request).await
    };
    match tokio::time::timeout(request.timeout, dial).await {
        Ok(result) => result,
        Err(_) => Err(Error::Transport("timeout".into())),
    }
}

/// SOCKS5 CONNECT with no authentication and a domain-name destination, as Tor expects.
async fn socks5_connect(mut proxy: TcpStream, host: &str, port: u16) -> Result<TcpStream, Error> {
    let fail = |message: String| Error::Transport(format!("tor socks: {message}"));
    proxy
        .write_all(&[5, 1, 0])
        .await
        .map_err(|e| fail(e.to_string()))?;
    let mut greeting = [0_u8; 2];
    proxy
        .read_exact(&mut greeting)
        .await
        .map_err(|e| fail(e.to_string()))?;
    if greeting != [5, 0] {
        return Err(fail("no acceptable authentication method".into()));
    }
    if host.len() > 255 {
        return Err(fail("destination name too long".into()));
    }
    let mut connect = vec![5, 1, 0, 3, host.len() as u8];
    connect.extend_from_slice(host.as_bytes());
    connect.extend_from_slice(&port.to_be_bytes());
    proxy
        .write_all(&connect)
        .await
        .map_err(|e| fail(e.to_string()))?;
    let mut head = [0_u8; 4];
    proxy
        .read_exact(&mut head)
        .await
        .map_err(|e| fail(e.to_string()))?;
    if head[1] != 0 {
        return Err(fail(format!(
            "connect refused ({})",
            match head[1] {
                1 => "general failure",
                2 => "not allowed",
                3 => "network unreachable",
                4 => "host unreachable",
                5 => "connection refused",
                6 => "ttl expired",
                _ => "unknown reply",
            }
        )));
    }
    let bound = match head[3] {
        1 => 4 + 2,
        3 => {
            let mut len = [0_u8; 1];
            proxy
                .read_exact(&mut len)
                .await
                .map_err(|e| fail(e.to_string()))?;
            usize::from(len[0]) + 2
        }
        4 => 16 + 2,
        _ => return Err(fail("bad bound address".into())),
    };
    let mut rest = vec![0_u8; bound];
    proxy
        .read_exact(&mut rest)
        .await
        .map_err(|e| fail(e.to_string()))?;
    Ok(proxy)
}

/// One HTTP/1.1 exchange on an open stream; the reply is read to end of stream.
async fn exchange(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    request: &Request<'_>,
) -> Result<Value, Error> {
    let authority = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n",
        request.method, request.path
    );
    if let Some(body) = request.body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    if let Some(authorization) = request.authorization {
        head.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    head.push_str("\r\n");
    let transport = |e: std::io::Error| Error::Transport(e.to_string());
    stream.write_all(head.as_bytes()).await.map_err(transport)?;
    if let Some(body) = request.body {
        stream.write_all(body).await.map_err(transport)?;
    }
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.map_err(transport)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > request.max_bytes {
            return Err(Error::Transport(format!(
                "bootnode response exceeded {} bytes",
                request.max_bytes
            )));
        }
    }
    parse_response(&raw)
}

/// Split status line, headers and body; a non-200 is a refusal carrying the parsed body.
pub(crate) fn parse_response(raw: &[u8]) -> Result<Value, Error> {
    let separator = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Transport("no HTTP header terminator".into()))?;
    let head = String::from_utf8_lossy(&raw[..separator]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = String::from_utf8_lossy(&raw[separator + 4..]).to_string();
    if status != 200 {
        return Err(Error::Refusal {
            status,
            reply: serde_json::from_str(&body).ok(),
            body,
        });
    }
    serde_json::from_str(&body).map_err(|e| Error::Transport(format!("invalid JSON reply: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn responses_split_into_answers_and_refusals() {
        let ok = parse_response(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"ok\":true}",
        )
        .unwrap();
        assert_eq!(ok, json!({"ok": true}));
        let refused =
            parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\n{\"ok\":false,\"err\":\"not-staked\"}")
                .unwrap_err();
        assert!(refused.is_refusal());
        assert!(
            matches!(&refused, Error::Refusal { status: 403, reply: Some(reply), .. } if reply["err"] == "not-staked")
        );
        let throttled = parse_response(b"HTTP/1.1 429 Too Many\r\n\r\n").unwrap_err();
        assert!(!throttled.is_refusal());
        assert!(parse_response(b"garbage").is_err());
    }

    #[tokio::test]
    async fn a_request_goes_through_a_socks5_proxy() {
        // a fake tor: accept the socks handshake, then answer the http request itself
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            socket.write_all(&[5, 0]).await.unwrap();
            let mut head = [0_u8; 5];
            socket.read_exact(&mut head).await.unwrap();
            let mut name = vec![0_u8; usize::from(head[4]) + 2];
            socket.read_exact(&mut name).await.unwrap();
            assert_eq!(&name[..name.len() - 2], b"abc.onion");
            socket
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !request.ends_with(b"{\"v\":1}") {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0, "request ended early");
                request.extend_from_slice(&chunk[..n]);
            }
            let text = String::from_utf8_lossy(&request).to_string();
            assert!(text.starts_with("POST /announce HTTP/1.1\r\nHost: abc.onion\r\n"));
            assert!(text.ends_with("\r\n\r\n{\"v\":1}"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true,\"ttl\":900}")
                .await
                .unwrap();
        });
        let socks = Socks {
            host: "127.0.0.1".into(),
            port,
        };
        let reply = request_over_tor(
            &socks,
            "abc",
            80,
            &Request::post("/announce", b"{\"v\":1}"),
            1,
        )
        .await
        .unwrap();
        assert_eq!(reply["ttl"], 900);
    }
}
