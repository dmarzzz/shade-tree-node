//! The cross-fleet spent-nullifier tally (`packages/node/gateway/fleet-tally.mjs`): peers
//! share `(nullifier, epoch)` pairs, nothing else, over an authenticated one-hop HTTP push,
//! so an envelope captured and fanned out across nodes is refused once the first node's
//! announcement has arrived. Best effort and fail-open: any tally trouble degrades to the
//! per-node replay defense, never to a refusal.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use num_bigint::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::torhttp::{self, Request, Socks};

pub(crate) const MAX_PEERS: usize = 64;
pub(crate) const DEFAULT_PATH: &str = "/fleet-tally";
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 4_000;
pub(crate) const DEFAULT_MAX_PER_EPOCH: usize = 50_000;
pub(crate) const DEFAULT_MAX_EPOCHS: usize = 4;
pub(crate) const DEFAULT_MAX_TOTAL: usize = 100_000;
const WIRE_MAX_BYTES: usize = 8 * 1024;
const MAX_IN_FLIGHT_PER_PEER: usize = 4;
const MAX_IN_FLIGHT_TOTAL: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const FIELD: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// A canonical decimal BN254 field element, the only spelling the wire accepts.
pub(crate) fn canonical_field(value: &str) -> Option<&str> {
    let canonical = value == "0"
        || (!value.is_empty()
            && value.len() <= 77
            && !value.starts_with('0')
            && value.bytes().all(|b| b.is_ascii_digit()));
    if !canonical {
        return None;
    }
    let n = BigUint::parse_bytes(value.as_bytes(), 10)?;
    let field = BigUint::parse_bytes(FIELD.as_bytes(), 10)?;
    (n < field).then_some(value)
}

/// 32..256 printable, non-space characters.
pub(crate) fn valid_token(value: &str) -> bool {
    (32..=256).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `host:port` or a `.onion[:port]`; a URL scheme is refused so the bearer token never
/// silently crosses plain HTTP to a peer spelled `https://`.
pub(crate) fn valid_peer(peer: &str) -> bool {
    (1..=320).contains(&peer.len())
        && !peer.bytes().any(|b| b.is_ascii_whitespace())
        && !peer.contains("://")
}

fn bearer_matches(header: Option<&str>, token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let expected = format!("Bearer {token}");
    if header.len() != expected.len() {
        return false;
    }
    // constant time over the whole header, so a prefix match leaks nothing
    header
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) peers: Vec<String>,
    pub(crate) token: String,
    pub(crate) listen: SocketAddr,
    pub(crate) path: String,
    pub(crate) timeout: Duration,
    pub(crate) max_per_epoch: usize,
    pub(crate) max_epochs: usize,
    pub(crate) max_total: usize,
    pub(crate) ttl: Duration,
    pub(crate) socks: Socks,
}

/// `SHADE_TREE_FLEET_TALLY_LISTEN` (`host:port` or `port`), default `127.0.0.1:0`.
pub(crate) fn parse_listen(raw: Option<&str>) -> SocketAddr {
    let fallback: SocketAddr = ([127, 0, 0, 1], 0).into();
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback;
    };
    if let Ok(port) = raw.parse::<u16>() {
        return ([127, 0, 0, 1], port).into();
    }
    raw.parse().unwrap_or(fallback)
}

struct Bucket {
    set: HashSet<String>,
    at: Instant,
}

struct State {
    buckets: BTreeMap<String, Bucket>,
    total: usize,
}

pub(crate) struct Tally {
    settings: Settings,
    state: Mutex<State>,
    in_flight_total: AtomicUsize,
    in_flight: Mutex<BTreeMap<String, usize>>,
}

impl Tally {
    pub(crate) fn new(settings: Settings) -> Self {
        Self {
            settings,
            state: Mutex::new(State {
                buckets: BTreeMap::new(),
                total: 0,
            }),
            in_flight_total: AtomicUsize::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
        }
    }

    fn prune(&self, state: &mut State) {
        let now = Instant::now();
        let ttl = self.settings.ttl;
        state.buckets.retain(|_, bucket| {
            let keep = now.duration_since(bucket.at) < ttl;
            if !keep {
                state.total -= bucket.set.len();
            }
            keep
        });
    }

    /// The single mutation path, for local records and peer announcements alike. Reaching a
    /// bound drops the evidence (fail-open) rather than refusing a tunnel.
    fn ingest(&self, nullifier: &str, epoch: &str) -> bool {
        let (Some(n), Some(k)) = (canonical_field(nullifier), canonical_field(epoch)) else {
            return false;
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.prune(&mut state);
        let settings = &self.settings;
        if !state.buckets.contains_key(k) {
            if state.buckets.len() >= settings.max_epochs || state.total >= settings.max_total {
                return false;
            }
            state.buckets.insert(
                k.to_string(),
                Bucket {
                    set: HashSet::new(),
                    at: Instant::now(),
                },
            );
        }
        let total = state.total;
        let Some(bucket) = state.buckets.get_mut(k) else {
            return false;
        };
        if bucket.set.contains(n) {
            return true;
        }
        if bucket.set.len() >= settings.max_per_epoch || total >= settings.max_total {
            return false;
        }
        bucket.set.insert(n.to_string());
        state.total += 1;
        true
    }

    /// Did a peer already establish this nullifier in this epoch?
    pub(crate) fn has(&self, nullifier: &str, epoch: &str) -> bool {
        let (Some(n), Some(k)) = (canonical_field(nullifier), canonical_field(epoch)) else {
            return false;
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.prune(&mut state);
        state.buckets.get(k).is_some_and(|b| b.set.contains(n))
    }

    /// Record a nullifier this node established and tell every peer, fire and forget.
    pub(crate) fn record(self: &Arc<Self>, nullifier: &str, epoch: &str) {
        let (Some(n), Some(k)) = (canonical_field(nullifier), canonical_field(epoch)) else {
            return;
        };
        self.ingest(n, k);
        let body = format!("{{\"nullifier\":\"{n}\",\"epoch\":\"{k}\"}}");
        for peer in &self.settings.peers {
            let pending = {
                let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
                let pending = in_flight.entry(peer.clone()).or_insert(0);
                if *pending >= MAX_IN_FLIGHT_PER_PEER
                    || self.in_flight_total.load(Ordering::Relaxed) >= MAX_IN_FLIGHT_TOTAL
                {
                    tracing::warn!(
                        peer,
                        "fleet-tally push backlog full; dropping announcements fail-open"
                    );
                    continue;
                }
                *pending += 1;
                *pending
            };
            let _ = pending;
            self.in_flight_total.fetch_add(1, Ordering::Relaxed);
            let this = Arc::clone(self);
            let peer = peer.clone();
            let body = body.clone();
            tokio::spawn(async move {
                if let Err(e) = this.push(&peer, &body).await {
                    tracing::warn!("fleet-tally push to peer failed (fail-open, per-gateway defense holds): {e}");
                }
                let mut in_flight = this.in_flight.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(pending) = in_flight.get_mut(&peer) {
                    *pending = pending.saturating_sub(1);
                    if *pending == 0 {
                        in_flight.remove(&peer);
                    }
                }
                this.in_flight_total.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    async fn push(&self, peer: &str, body: &str) -> Result<(), String> {
        let authorization = format!("Bearer {}", self.settings.token);
        let request = Request {
            method: "POST",
            path: &self.settings.path,
            body: Some(body.as_bytes()),
            authorization: Some(&authorization),
            timeout: self.settings.timeout,
            max_bytes: WIRE_MAX_BYTES,
        };
        let outcome = match peer.rsplit_once(".onion") {
            Some((_, rest)) if rest.is_empty() || rest.starts_with(':') => {
                let onion = peer.trim_end_matches(rest);
                let port = rest.trim_start_matches(':').parse().unwrap_or(80);
                torhttp::request_over_tor(&self.settings.socks, onion, port, &request, 1).await
            }
            _ => {
                let (host, port) = peer.rsplit_once(':').unwrap_or((peer, "80"));
                let host = if host.is_empty() { "127.0.0.1" } else { host };
                torhttp::request_plain(host, port.parse().unwrap_or(80), &request).await
            }
        };
        outcome.map(|_| ()).map_err(|e| e.to_string())
    }

    /// Serve peer announcements on the inbound endpoint until the task is dropped.
    pub(crate) async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = tokio::time::timeout(REQUEST_TIMEOUT, this.respond(stream)).await;
            });
        }
    }

    async fn respond(&self, mut stream: TcpStream) {
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 1024];
        let head_end = loop {
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if raw.len() > WIRE_MAX_BYTES {
                return;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap_or("").split(' ');
        let method = request_line.next().unwrap_or("");
        let path = request_line
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");
        let mut authorization = None;
        let mut content_length = 0_usize;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("authorization") {
                    authorization = Some(value.trim().to_string());
                } else if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let reply = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let status = if method != "POST" || path != self.settings.path {
            reply("404 Not Found", "")
        } else if !bearer_matches(authorization.as_deref(), &self.settings.token) {
            "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
        } else if content_length > WIRE_MAX_BYTES {
            reply("413 Payload Too Large", "")
        } else {
            let mut body = raw[head_end + 4..].to_vec();
            while body.len() < content_length {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
                if body.len() > WIRE_MAX_BYTES {
                    break;
                }
            }
            let message: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
            let nullifier = message
                .as_ref()
                .and_then(|m| m.get("nullifier"))
                .and_then(serde_json::Value::as_str)
                .and_then(canonical_field);
            let epoch = message
                .as_ref()
                .and_then(|m| m.get("epoch"))
                .and_then(serde_json::Value::as_str)
                .and_then(canonical_field);
            match (nullifier, epoch) {
                (Some(nullifier), Some(epoch)) => {
                    // only these two fields are ever read; anything else a peer sends dies here
                    self.ingest(nullifier, epoch);
                    reply("200 OK", "{\"ok\":true}")
                }
                _ => reply("400 Bad Request", ""),
            }
        };
        let _ = stream.write_all(status.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(peers: Vec<String>) -> Settings {
        Settings {
            peers,
            token: "x".repeat(40),
            listen: ([127, 0, 0, 1], 0).into(),
            path: DEFAULT_PATH.into(),
            timeout: Duration::from_secs(2),
            max_per_epoch: 3,
            max_epochs: 2,
            max_total: 5,
            ttl: Duration::from_secs(60),
            socks: Socks {
                host: "127.0.0.1".into(),
                port: 1,
            },
        }
    }

    #[test]
    fn wire_fields_are_canonical_field_elements_and_state_is_bounded() {
        assert_eq!(canonical_field("0"), Some("0"));
        assert_eq!(canonical_field("12"), Some("12"));
        assert!(canonical_field("012").is_none());
        assert!(canonical_field("").is_none());
        assert!(
            canonical_field(FIELD).is_none(),
            "the modulus itself is out of range"
        );
        assert!(valid_token(&"a".repeat(32)));
        assert!(!valid_token("short"));
        assert!(valid_peer("peer.onion:8444"));
        assert!(!valid_peer("https://peer"));
        assert!(bearer_matches(Some("Bearer abc"), "abc"));
        assert!(!bearer_matches(Some("Bearer abd"), "abc"));
        assert_eq!(parse_listen(Some("8444")).port(), 8444);
        assert_eq!(parse_listen(None).port(), 0);

        let tally = Tally::new(settings(Vec::new()));
        assert!(tally.ingest("1", "100"));
        assert!(tally.ingest("1", "100"), "idempotent");
        assert!(tally.has("1", "100"));
        assert!(!tally.has("2", "100"));
        assert!(tally.ingest("2", "100"));
        assert!(tally.ingest("3", "100"));
        assert!(!tally.ingest("4", "100"), "per-epoch cap");
        assert!(tally.ingest("4", "101"));
        assert!(!tally.ingest("5", "102"), "epoch bucket cap");
        assert!(!tally.ingest("x", "100"));
    }

    #[tokio::test]
    async fn a_plain_peer_learns_the_nullifier_and_refuses_bad_tokens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let receiver = Arc::new(Tally::new(settings(Vec::new())));
        tokio::spawn(Arc::clone(&receiver).serve(listener));
        let sender = Arc::new(Tally::new(settings(vec![addr.to_string()])));
        sender.record("7", "100");
        for _ in 0..50 {
            if receiver.has("7", "100") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(receiver.has("7", "100"));
        let bad = Request {
            method: "POST",
            path: DEFAULT_PATH,
            body: Some(b"{\"nullifier\":\"8\",\"epoch\":\"100\",\"share\":\"never read\"}"),
            authorization: Some("Bearer wrong"),
            timeout: Duration::from_secs(2),
            max_bytes: 1024,
        };
        let refused = torhttp::request_plain("127.0.0.1", addr.port(), &bad)
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            torhttp::Error::Refusal { status: 401, .. }
        ));
        assert!(!receiver.has("8", "100"));
    }
}
