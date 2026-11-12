//! The relay after the acknowledgement (`gateway.mjs` `establishTunnel`, `makePayloadBudget`,
//! `payloadTransform`): both directions share one combined byte allowance per admitted
//! `(externalNullifier, nullifier)` slot, one idle timer covers both, and the boundary chunk
//! is delivered before the tunnel closes at the limit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::telemetry::{self, Traffic};

const CHUNK: usize = 16 * 1024;

struct Allowance {
    used: u64,
    active: usize,
    idle_since: Instant,
}

/// Combined payload allowance per slot. Entries outlive their last tunnel by `ttl` so a retry
/// on the same slot shares what remains.
pub(crate) struct Budget {
    max_bytes: u64,
    ttl: Duration,
    entries: Mutex<HashMap<String, Allowance>>,
}

/// Holds one slot's allowance open for the life of a tunnel.
pub(crate) struct Hold {
    budget: Arc<Budget>,
    key: String,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut entries = self
            .budget
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(&self.key) {
            entry.active = entry.active.saturating_sub(1);
            if entry.active == 0 {
                entry.idle_since = Instant::now();
            }
        }
    }
}

impl Budget {
    /// `max_bytes == 0` means unlimited.
    pub(crate) fn new(max_bytes: u64, epoch_seconds: u64) -> Self {
        Self {
            max_bytes,
            ttl: Duration::from_secs(2 * epoch_seconds),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn key(external_nullifier: &str, nullifier: &str) -> String {
        format!("{external_nullifier}\0{nullifier}")
    }

    /// Open the slot for one more tunnel. `None` when the allowance is already spent.
    pub(crate) fn acquire(self: &Arc<Self>, key: String) -> Option<Hold> {
        if self.max_bytes == 0 {
            return Some(Hold {
                budget: Arc::clone(self),
                key,
            });
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        entries.retain(|_, e| e.active > 0 || now.duration_since(e.idle_since) < self.ttl);
        let entry = entries.entry(key.clone()).or_insert(Allowance {
            used: 0,
            active: 0,
            idle_since: now,
        });
        entry.active += 1;
        if entry.used >= self.max_bytes {
            drop(entries);
            drop(Hold {
                budget: Arc::clone(self),
                key,
            });
            return None;
        }
        Some(Hold {
            budget: Arc::clone(self),
            key,
        })
    }

    /// Admit up to `requested` bytes. Returns how many may be forwarded and whether the slot
    /// is now exhausted.
    fn take(&self, key: &str, requested: usize) -> (usize, bool) {
        if self.max_bytes == 0 {
            return (requested, false);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get_mut(key) else {
            return (0, true);
        };
        let remaining = self.max_bytes.saturating_sub(entry.used);
        let allowed = usize::try_from(remaining).map_or(requested, |r| r.min(requested));
        entry.used += allowed as u64;
        (allowed, entry.used >= self.max_bytes)
    }
}

/// A token bucket: `take(n)` is how long `n` bytes must wait before they may pass.
struct TokenBucket {
    tokens: f64,
    at: Instant,
    rate: f64,
    burst: f64,
}

impl TokenBucket {
    fn new(bytes_per_second: u64, burst_bytes: u64) -> Self {
        Self {
            tokens: burst_bytes as f64,
            at: Instant::now(),
            rate: bytes_per_second as f64,
            burst: burst_bytes as f64,
        }
    }

    fn take(&mut self, n: usize) -> Duration {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate).min(self.burst);
        self.at = now;
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

/// Per-book shaping (ADR 0011): one bucket per direction shared by every stream of the book,
/// so opening six streams never multiplies the advertised rate, plus the book's payload clock.
pub(crate) struct Shaping {
    up: Mutex<TokenBucket>,
    down: Mutex<TokenBucket>,
    last_payload: Mutex<Instant>,
}

impl Shaping {
    pub(crate) fn new(up_rate: u64, up_burst: u64, down_rate: u64, down_burst: u64) -> Self {
        Self {
            up: Mutex::new(TokenBucket::new(up_rate, up_burst)),
            down: Mutex::new(TokenBucket::new(down_rate, down_burst)),
            last_payload: Mutex::new(Instant::now()),
        }
    }

    fn delay(&self, direction: Direction, bytes: usize) -> Duration {
        let bucket = match direction {
            Direction::AgentToDestination => &self.up,
            Direction::DestinationToAgent => &self.down,
        };
        bucket.lock().unwrap_or_else(|e| e.into_inner()).take(bytes)
    }

    fn touch(&self) {
        *self.last_payload.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    pub(crate) fn last_payload(&self) -> Instant {
        *self.last_payload.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How an established tunnel ended, for the close log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Close {
    /// A side reached end of stream. Neither socket allows half-open: like the JavaScript
    /// node's, a FIN from either peer ends the whole tunnel.
    Peer,
    IdleTimeout,
    PayloadLimit,
    UpstreamError,
    ClientError,
    /// The session book closed or the stream hit its hard cap.
    Session,
}

impl Close {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::IdleTimeout => "idle-timeout",
            Self::PayloadLimit => "payload-limit",
            Self::UpstreamError => "upstream-error",
            Self::ClientError => "client-error",
            Self::Session => "session",
        }
    }
}

enum Pump {
    Eof,
    Limit,
    Failed,
}

#[derive(Clone, Copy)]
enum Direction {
    AgentToDestination,
    DestinationToAgent,
}

struct Activity(AtomicU64, Instant);

impl Activity {
    fn touch(&self) {
        let elapsed = u64::try_from(self.1.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.0.store(elapsed, Ordering::Relaxed);
    }

    fn since_last(&self) -> Duration {
        let last = Duration::from_millis(self.0.load(Ordering::Relaxed));
        self.1.elapsed().saturating_sub(last)
    }
}

/// Relay until a side ends, the idle timer fires, or the allowance runs out. `early` is the
/// client data that arrived with the envelope and goes to the destination first.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    early: Vec<u8>,
    hold: Hold,
    idle_timeout: Option<Duration>,
    shaping: Option<Arc<Shaping>>,
    cancel: Option<Arc<tokio::sync::Notify>>,
    traffic: Arc<Traffic>,
) -> Close {
    let budget = Arc::clone(&hold.budget);
    let key = Arc::new(hold.key.clone());
    let activity = Arc::new(Activity(AtomicU64::new(0), Instant::now()));
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let mut pumps = JoinSet::new();
    pumps.spawn(pump(
        Direction::AgentToDestination,
        client_read,
        upstream_write,
        early,
        Arc::clone(&budget),
        Arc::clone(&key),
        Arc::clone(&activity),
        shaping.clone(),
        Arc::clone(&traffic),
    ));
    pumps.spawn(pump(
        Direction::DestinationToAgent,
        upstream_read,
        client_write,
        Vec::new(),
        budget,
        key,
        Arc::clone(&activity),
        shaping,
        traffic,
    ));
    let idle = async {
        match idle_timeout {
            Some(limit) => loop {
                let since = activity.since_last();
                if since >= limit {
                    break;
                }
                tokio::time::sleep(limit - since).await;
            },
            None => std::future::pending().await,
        }
    };
    let cancelled = async {
        match &cancel {
            Some(notify) => notify.notified().await,
            None => std::future::pending().await,
        }
    };
    let close = tokio::select! {
        joined = pumps.join_next() => match joined {
            None | Some(Ok((_, Pump::Eof))) => Close::Peer,
            Some(Ok((_, Pump::Limit))) => Close::PayloadLimit,
            Some(Ok((Direction::AgentToDestination, Pump::Failed))) => Close::ClientError,
            Some(Ok((Direction::DestinationToAgent, Pump::Failed))) => Close::UpstreamError,
            Some(Err(_)) => Close::ClientError,
        },
        () = idle => Close::IdleTimeout,
        () = cancelled => Close::Session,
    };
    pumps.abort_all();
    drop(hold);
    close
}

#[allow(clippy::too_many_arguments)]
async fn pump(
    direction: Direction,
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    early: Vec<u8>,
    budget: Arc<Budget>,
    key: Arc<String>,
    activity: Arc<Activity>,
    shaping: Option<Arc<Shaping>>,
    traffic: Arc<Traffic>,
) -> (Direction, Pump) {
    let counted = match direction {
        Direction::AgentToDestination => telemetry::Direction::AgentToDestination,
        Direction::DestinationToAgent => telemetry::Direction::DestinationToAgent,
    };
    let mut chunk = vec![0_u8; CHUNK];
    let mut pending = early;
    loop {
        if !pending.is_empty() {
            let (allowed, exhausted) = budget.take(&key, pending.len());
            if allowed > 0 {
                if let Some(shaping) = &shaping {
                    let delay = shaping.delay(direction, allowed);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
                if writer.write_all(&pending[..allowed]).await.is_err() {
                    return (direction, Pump::Failed);
                }
                traffic.add(counted, allowed);
                activity.touch();
                if let Some(shaping) = &shaping {
                    shaping.touch();
                }
            }
            if exhausted {
                let _ = writer.flush().await;
                return (direction, Pump::Limit);
            }
            pending.clear();
        }
        match reader.read(&mut chunk).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return (direction, Pump::Eof);
            }
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(_) => return (direction, Pump::Failed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowance_is_shared_and_remembered_until_the_ttl() {
        let budget = Arc::new(Budget::new(10, 1));
        let key = Budget::key("e", "n");
        let hold = budget.acquire(key.clone()).unwrap();
        assert_eq!(budget.take(&key, 6), (6, false));
        assert_eq!(budget.take(&key, 6), (4, true));
        assert_eq!(budget.take(&key, 1), (0, true));
        drop(hold);
        assert!(
            budget.acquire(key.clone()).is_none(),
            "spent slots stay spent"
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert!(
            budget.acquire(key).is_some(),
            "the slot is forgotten after two epochs"
        );
    }

    #[test]
    fn an_unlimited_budget_never_exhausts() {
        let budget = Arc::new(Budget::new(0, 1));
        let key = Budget::key("e", "n");
        let _hold = budget.acquire(key.clone()).unwrap();
        assert_eq!(budget.take(&key, usize::MAX), (usize::MAX, false));
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_the_limit_closes_the_tunnel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0_u8; 64];
            // the relay closes the upstream with "pong" bytes still unread, which a loopback
            // peer may report as a reset rather than an orderly end
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
                if socket.write_all(b"pong").await.is_err() {
                    break;
                }
            }
            got
        });
        let (client, mut agent) = tokio::io::duplex(1024);
        let client = {
            let agent_side = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = agent_side.local_addr().unwrap();
            let connect = TcpStream::connect(addr);
            let (accepted, connected) = tokio::join!(agent_side.accept(), connect);
            let (server_end, _) = accepted.unwrap();
            let client_end = connected.unwrap();
            tokio::spawn(async move {
                let (mut cr, mut cw) = client_end.into_split();
                let (mut dr, mut dw) = tokio::io::split(client);
                tokio::join!(
                    async {
                        let _ = tokio::io::copy(&mut dr, &mut cw).await;
                        let _ = cw.shutdown().await;
                    },
                    async {
                        let _ = tokio::io::copy(&mut cr, &mut dw).await;
                        let _ = dw.shutdown().await;
                    }
                );
            });
            server_end
        };
        let upstream = TcpStream::connect(sink_addr).await.unwrap();
        let budget = Arc::new(Budget::new(12, 60));
        let hold = budget.acquire(Budget::key("e", "n")).unwrap();
        let registry = Arc::new(crate::metrics::Registry::new("node", "0", "0"));
        let traffic = Arc::new(Traffic::new(Arc::clone(&registry), None));
        let relay = tokio::spawn(relay(
            client,
            upstream,
            b"early".to_vec(),
            hold,
            None,
            None,
            None,
            traffic,
        ));
        let mut reply = [0_u8; 4];
        agent.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        agent.write_all(b"more-than-the-limit").await.unwrap();
        assert_eq!(relay.await.unwrap(), Close::PayloadLimit);
        let got = sink.await.unwrap();
        assert_eq!(got, b"earlymor", "5 early + 4 pong + 3 more = 12 bytes");
        let text = registry.render();
        assert!(
            text.contains("shade_tree_gateway_agent_to_destination_payload_bytes_total 8\n"),
            "{text}"
        );
        assert!(
            text.contains("shade_tree_gateway_destination_to_agent_payload_bytes_total 4\n"),
            "{text}"
        );
    }
}
