//! Federation (`packages/node/bootnode/federation.mjs`): with `SHADE_TREE_BOOTNODE_PEERS`
//! set, the Elder pulls each peer's `/directory` over Tor as a hint list of onions, takes the
//! signed announce each entry carries (or fetches it from the peer's `/gateway/<onion>`), and
//! re-verifies it through the same path a direct announce takes. The peer's own signature is
//! never trusted as authority over an entry; a forged, tampered, unstaked or stale gossiped
//! node is refused exactly as it would be at the door. Fail-soft at every level: a dark peer
//! is skipped, one missing gateway does not abort the peer, one failing peer does not abort
//! the cycle.

use std::sync::Arc;
use std::time::Duration;

use serde_json::value::RawValue;
use serde_json::Value;
use shadenet_service::clock;
use shadenet_service::torhttp::{self, Request, Socks};

use crate::registry::{Gossip, Registry};

const ELDER_PORT: u16 = 80;

/// What one peer's pull came to.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) listed: usize,
    pub(crate) merged: usize,
    pub(crate) skipped: usize,
    pub(crate) rejected: usize,
    pub(crate) errors: usize,
    pub(crate) error: Option<String>,
}

pub(crate) struct Federation {
    registry: Arc<Registry>,
    peers: Vec<String>,
    socks: Socks,
    interval: Duration,
    max_pull: usize,
}

/// An error message with every onion replaced, so a log never names a peer.
fn redact_onions(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(".onion") {
        let start = rest[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_alphanumeric())
            .last()
            .map_or(at, |(i, _)| i);
        if at - start == 56 {
            out.push_str(&rest[..start]);
            out.push_str("<onion>");
        } else {
            out.push_str(&rest[..at + 6]);
        }
        rest = &rest[at + 6..];
    }
    out.push_str(rest);
    out.chars().take(200).collect()
}

impl Federation {
    pub(crate) fn new(
        registry: Arc<Registry>,
        peers: Vec<String>,
        socks: Socks,
        interval: Duration,
        max_pull: usize,
    ) -> Self {
        Self {
            registry,
            peers,
            socks,
            interval,
            max_pull,
        }
    }

    pub(crate) fn peers(&self) -> &[String] {
        &self.peers
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    async fn fetch(&self, peer: &str, path: &str) -> Result<Value, String> {
        torhttp::request_over_tor(
            &self.socks,
            peer,
            ELDER_PORT,
            &Request::get(path),
            torhttp::DEFAULT_ATTEMPTS,
        )
        .await
        .map_err(|e| e.to_string())
    }

    /// Pull and merge one peer.
    pub(crate) async fn pull_peer(&self, peer: &str) -> Stats {
        let mut stats = Stats::default();
        let directory = match self.fetch(peer, "/directory").await {
            Ok(directory) => directory,
            Err(e) => {
                stats.errors += 1;
                stats.error = Some(e);
                return stats;
            }
        };
        // only the onion strings are consumed; the peer's labels and signature carry no weight
        let mut listed: Vec<(String, Option<Box<RawValue>>)> = Vec::new();
        for entry in directory["gateways"].as_array().into_iter().flatten() {
            let Some(onion) = entry["onion"].as_str() else {
                continue;
            };
            let announce = entry
                .get("announce")
                .filter(|a| a["onion"].as_str() == Some(onion))
                .and_then(|a| RawValue::from_string(a.to_string()).ok());
            listed.push((onion.to_string(), announce));
            if listed.len() >= self.max_pull {
                break;
            }
        }
        stats.listed = listed.len();
        let now = clock::now_secs();
        for (onion, announce) in listed {
            let record = match announce {
                Some(record) => record,
                None => match self.fetch(peer, &format!("/gateway/{onion}")).await {
                    Ok(value) => match RawValue::from_string(value.to_string()) {
                        Ok(record) => record,
                        Err(_) => {
                            stats.errors += 1;
                            continue;
                        }
                    },
                    Err(_) => {
                        stats.errors += 1;
                        continue;
                    }
                },
            };
            match self.registry.admit_gossip(&record, now).await {
                Gossip::Merged => stats.merged += 1,
                Gossip::FreshExisting => stats.skipped += 1,
                Gossip::Rejected(reason) => {
                    tracing::debug!(reason, "gossip rejected");
                    stats.rejected += 1;
                }
            }
        }
        stats
    }

    /// One pass over every peer.
    pub(crate) async fn pull_all(&self) -> Vec<Stats> {
        let mut results = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            results.push(self.pull_peer(peer).await);
        }
        let (merged, skipped, rejected, errors) = results.iter().fold((0, 0, 0, 0), |a, s| {
            (
                a.0 + s.merged,
                a.1 + s.skipped,
                a.2 + s.rejected,
                a.3 + s.errors,
            )
        });
        if merged > 0 || rejected > 0 {
            tracing::info!(
                merged,
                skipped,
                rejected,
                errors,
                peers = self.peers.len(),
                "federation pull"
            );
        }
        for stats in &results {
            if stats.errors > 0 && stats.listed == 0 {
                tracing::warn!(
                    error = redact_onions(stats.error.as_deref().unwrap_or("")),
                    "federation peer unreachable"
                );
            }
        }
        results
    }

    /// One convergence pull at once, then every interval.
    pub(crate) async fn run(self: Arc<Self>) {
        loop {
            self.pull_all().await;
            tokio::time::sleep(self.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canopy::Canopy;
    use crate::registry::tests::{make, mock, raw, Node};
    use crate::registry::Outcome;
    use crate::signer::Signer;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A peer Elder: the signed directory and the stored announces of a registry, served
    /// over plain HTTP from a local port; `paths` records what was asked.
    struct Peer {
        registry: Arc<Registry>,
        canopy: Arc<Canopy>,
        signer_hex: String,
        paths: Arc<Mutex<Vec<String>>>,
    }

    fn signer(name: &str) -> Arc<Signer> {
        let dir =
            std::env::temp_dir().join(format!("shadenet-elder-fed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(Signer::load_or_mint(&dir.join("signer.key")).unwrap())
    }

    async fn serve_peer(peer: Arc<Peer>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let peer = Arc::clone(&peer);
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = text.split(' ').nth(1).unwrap_or("/").to_string();
                    peer.paths.lock().unwrap().push(path.clone());
                    let (status, body) = if path == "/directory" {
                        ("200 OK", peer.canopy.directory(clock::now_secs()).body)
                    } else if let Some(onion) = path.strip_prefix("/gateway/") {
                        match peer.registry.record(onion) {
                            Some(record) => ("200 OK", record.get().as_bytes().to_vec()),
                            None => (
                                "404 Not Found",
                                b"{\"ok\":false,\"err\":\"not-found\"}".to_vec(),
                            ),
                        }
                    } else {
                        (
                            "404 Not Found",
                            b"{\"ok\":false,\"err\":\"no-route\"}".to_vec(),
                        )
                    };
                    let reply = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                });
            }
        });
        port
    }

    /// A fake Tor SOCKS port routing each onion to a local port; unknown onions are refused.
    async fn fake_tor(routes: Arc<Mutex<HashMap<String, u16>>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&routes);
                tokio::spawn(async move {
                    let mut greeting = [0_u8; 3];
                    if socket.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let _ = socket.write_all(&[5, 0]).await;
                    let mut head = [0_u8; 5];
                    if socket.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut name = vec![0_u8; usize::from(head[4]) + 2];
                    let _ = socket.read_exact(&mut name).await;
                    let destination = String::from_utf8_lossy(&name[..name.len() - 2]).to_string();
                    let target = routes.lock().unwrap().get(&destination).copied();
                    let Some(target) = target else {
                        let _ = socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    };
                    let _ = socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    let Ok(mut upstream) =
                        tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
                });
            }
        });
        port
    }

    async fn peer(name: &str, now: u64) -> Arc<Peer> {
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now));
        let signer = signer(name);
        let canopy = Arc::new(Canopy::new(Arc::clone(&signer), Arc::clone(&registry), 8));
        Arc::new(Peer {
            registry,
            canopy,
            signer_hex: signer.public_hex().to_string(),
            paths: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn accept(registry: &Registry, node: &Node, now: u64, nonce: &str) {
        assert!(matches!(
            registry
                .announce(&raw(&node.announce(100, now, nonce, None, None)), now)
                .await,
            Outcome::Accepted { .. }
        ));
    }

    #[tokio::test]
    async fn two_elders_converge_and_a_dark_peer_is_skipped() {
        let now = clock::now_secs();
        let (a, b) = (peer("a", now).await, peer("b", now).await);
        let (g1, g2) = (Node::new(1), Node::new(2));
        accept(&a.registry, &g1, now, "f1").await;
        accept(&b.registry, &g2, now, "f2").await;
        let (onion_a, onion_b, dark) = (
            Node::new(10).onion,
            Node::new(11).onion,
            Node::new(12).onion,
        );
        let routes = Arc::new(Mutex::new(HashMap::from([
            (onion_a.clone(), serve_peer(Arc::clone(&a)).await),
            (onion_b.clone(), serve_peer(Arc::clone(&b)).await),
        ])));
        let socks = Socks {
            host: "127.0.0.1".into(),
            port: fake_tor(routes).await,
        };
        let fed_a = Federation::new(
            Arc::clone(&a.registry),
            vec![onion_b.clone(), dark.clone()],
            socks.clone(),
            Duration::from_secs(60),
            100,
        );
        let fed_b = Federation::new(
            Arc::clone(&b.registry),
            vec![onion_a.clone()],
            socks.clone(),
            Duration::from_secs(60),
            100,
        );
        let stats = fed_a.pull_all().await;
        assert_eq!(
            (stats[0].merged, stats[0].rejected),
            (1, 0),
            "{:?}",
            stats[0]
        );
        assert!(
            stats[1].errors >= 1 && stats[1].listed == 0,
            "the dark peer is skipped: {:?}",
            stats[1]
        );
        let stats = fed_b.pull_all().await;
        assert_eq!(stats[0].merged, 1);
        assert_eq!(
            a.registry.live_onions(),
            b.registry.live_onions(),
            "the two Elders converge on the same live set"
        );
        assert_eq!(a.registry.live_onions().len(), 2);
        // the listed announce saved the per-gateway fetch, and a re-pull is idempotent
        assert!(!b
            .paths
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.starts_with("/gateway/")));
        let again = fed_a.pull_peer(&onion_b).await;
        assert_eq!((again.merged, again.skipped), (0, 2));
        // the merged directory verifies under the local signer, never the peer's
        let doc = String::from_utf8(a.canopy.directory(now).body).unwrap();
        assert!(shadenet::dircache::parse_and_verify_document(&doc, &a.signer_hex).is_ok());
    }

    #[tokio::test]
    async fn the_pull_is_bounded_and_falls_back_to_the_gateway_route() {
        let now = clock::now_secs();
        let (local, remote) = (peer("local", now).await, peer("remote", now).await);
        for tag in 1..=4 {
            let padded = format!(
                "{{\"pad\":\"{}\",{}",
                "x".repeat(5000),
                &Node::new(tag).announce(100, now, "big", None, None)[1..]
            );
            assert!(matches!(
                remote.registry.announce(&raw(&padded), now).await,
                Outcome::Accepted { .. }
            ));
        }
        let onion_remote = Node::new(20).onion;
        let routes = Arc::new(Mutex::new(HashMap::from([(
            onion_remote.clone(),
            serve_peer(Arc::clone(&remote)).await,
        )])));
        let socks = Socks {
            host: "127.0.0.1".into(),
            port: fake_tor(routes).await,
        };
        let fed = Federation::new(
            Arc::clone(&local.registry),
            vec![onion_remote.clone()],
            socks,
            Duration::from_secs(60),
            2,
        );
        let stats = fed.pull_peer(&onion_remote).await;
        assert_eq!((stats.listed, stats.merged), (2, 2), "{stats:?}");
        let fetched = remote
            .paths
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with("/gateway/"))
            .count();
        assert_eq!(
            fetched, 2,
            "oversized announces are not listed, so each was fetched; the bound held"
        );
        assert_eq!(local.registry.size(), 2);
    }

    #[test]
    fn onions_never_reach_a_log() {
        let onion = Node::new(1).onion;
        let redacted = redact_onions(&format!(
            "bootnode GET failed after 4 attempts: tor socks unreachable: {onion} refused"
        ));
        assert_eq!(
            redacted,
            "bootnode GET failed after 4 attempts: tor socks unreachable: <onion> refused"
        );
        assert_eq!(redact_onions("short.onion stays"), "short.onion stays");
    }
}
