//! Active health probing (`makeProbeHealth`, `makeProber`): a live entry means "announced
//! recently", not "reachable". With `SHADE_TREE_BOOTNODE_PROBE=1` the Elder dials each live
//! onion itself, a cheap SOCKS connect to port 80, and demotes one that failed the last N
//! probes to `health: "down"`. Still listed, the TTL governs removal; a false negative is a
//! soft failure, never an outage. Any success recovers at once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shadenet_service::torhttp::{self, Socks};

use crate::canopy::Canopy;
use crate::registry::Registry;

const ONION_PORT: u16 = 80;

/// Per-onion consecutive failures, present only while failing.
pub(crate) struct Health {
    fail_threshold: u32,
    fails: Mutex<HashMap<String, u32>>,
}

impl Health {
    pub(crate) fn new(fail_threshold: u32) -> Self {
        Self {
            fail_threshold: fail_threshold.max(1),
            fails: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, u32>> {
        self.fails.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One probe outcome: a success clears the counter, a failure adds to it.
    pub(crate) fn record(&self, onion: &str, ok: bool) {
        let mut fails = self.lock();
        if ok {
            fails.remove(onion);
        } else {
            *fails.entry(onion.to_string()).or_insert(0) += 1;
        }
    }

    /// Drop counters for onions no longer live, so probe state never outlives its node.
    pub(crate) fn retain(&self, live: &[String]) {
        self.lock().retain(|onion, _| live.contains(onion));
    }

    pub(crate) fn down(&self) -> HashSet<String> {
        let fails = self.lock();
        fails
            .iter()
            .filter(|(_, n)| **n >= self.fail_threshold)
            .map(|(onion, _)| onion.clone())
            .collect()
    }

    /// Onions with a failure on record, demoted or not.
    pub(crate) fn tracked(&self) -> usize {
        self.lock().len()
    }
}

pub(crate) struct Prober {
    socks: Socks,
    timeout: Duration,
    interval: Duration,
    pub(crate) health: Health,
    registry: Arc<Registry>,
    canopy: Arc<Canopy>,
}

impl Prober {
    pub(crate) fn new(
        socks: Socks,
        timeout: Duration,
        interval: Duration,
        fail_threshold: u32,
        registry: Arc<Registry>,
        canopy: Arc<Canopy>,
    ) -> Self {
        Self {
            socks,
            timeout,
            interval,
            health: Health::new(fail_threshold),
            registry,
            canopy,
        }
    }

    pub(crate) fn fail_threshold(&self) -> u32 {
        self.health.fail_threshold
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    /// Dial every live onion once; a dial that fails or times out counts against it, and one
    /// bad onion never aborts the cycle. Returns how many were probed.
    pub(crate) async fn run_cycle(&self) -> usize {
        let onions = self.registry.live_onions();
        let mut dials = tokio::task::JoinSet::new();
        for onion in &onions {
            let socks = self.socks.clone();
            let onion = onion.clone();
            let timeout = self.timeout;
            dials.spawn(async move {
                let ok = torhttp::connect_over_tor(&socks, &onion, ONION_PORT, timeout)
                    .await
                    .is_ok();
                (onion, ok)
            });
        }
        while let Some(result) = dials.join_next().await {
            if let Ok((onion, ok)) = result {
                self.health.record(&onion, ok);
            }
        }
        self.health.retain(&onions);
        self.canopy.set_down(self.health.down());
        onions.len()
    }

    pub(crate) async fn run(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.interval).await;
            let probed = self.run_cycle().await;
            tracing::debug!(
                probed,
                down = self.health.down().len(),
                failing = self.health.tracked(),
                "health probe cycle"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{make, mock, raw, Node};
    use crate::registry::Outcome;
    use crate::signer::Signer;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn consecutive_failures_demote_and_one_success_recovers() {
        let health = Health::new(3);
        health.record("a", false);
        health.record("a", false);
        assert!(health.down().is_empty(), "not demoted early");
        health.record("a", false);
        assert!(health.down().contains("a"));
        health.record("a", true);
        assert!(health.down().is_empty() && health.tracked() == 0);
        health.record("b", false);
        health.retain(&["c".to_string()]);
        assert_eq!(health.tracked(), 0, "swept with the live set");
    }

    /// A fake Tor SOCKS port: a destination in `reachable` connects, any other is refused.
    async fn fake_tor(reachable: Arc<Mutex<HashSet<String>>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let reachable = Arc::clone(&reachable);
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
                    let ok = reachable.lock().unwrap().contains(&destination);
                    let reply = if ok { 0 } else { 5 };
                    let _ = socket.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    if ok {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn the_prober_demotes_the_unreachable_and_bounds_its_state() {
        let now = shadenet_service::clock::now_secs();
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now));
        let dir = std::env::temp_dir().join(format!("shadenet-elder-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let signer = Arc::new(Signer::load_or_mint(&dir.join("signer.key")).unwrap());
        let canopy = Arc::new(Canopy::new(signer, Arc::clone(&registry), 8));
        let (g1, g2) = (Node::new(1), Node::new(2));
        for node in [&g1, &g2] {
            assert!(matches!(
                registry
                    .announce(&raw(&node.announce(100, now, "p", None, None)), now)
                    .await,
                Outcome::Accepted { .. }
            ));
        }
        let reachable = Arc::new(Mutex::new(HashSet::from([g2.onion.clone()])));
        let port = fake_tor(Arc::clone(&reachable)).await;
        let prober = Prober::new(
            Socks {
                host: "127.0.0.1".into(),
                port,
            },
            Duration::from_secs(2),
            Duration::from_secs(120),
            3,
            Arc::clone(&registry),
            Arc::clone(&canopy),
        );
        let health_of = |onion: &str| -> String {
            let doc: Value = serde_json::from_slice(&canopy.directory(now).body).unwrap();
            doc["gateways"]
                .as_array()
                .unwrap()
                .iter()
                .find(|g| g["onion"] == onion)
                .map(|g| g["health"].as_str().unwrap().to_string())
                .unwrap_or_default()
        };
        assert_eq!(health_of(&g1.onion), "up");
        for _ in 0..2 {
            assert_eq!(prober.run_cycle().await, 2);
            assert_eq!(health_of(&g1.onion), "up", "not demoted early");
        }
        prober.run_cycle().await;
        assert_eq!(health_of(&g1.onion), "down");
        assert_eq!(health_of(&g2.onion), "up");
        reachable.lock().unwrap().insert(g1.onion.clone());
        prober.run_cycle().await;
        assert_eq!(health_of(&g1.onion), "up", "one success recovers");
        assert_eq!(prober.health.tracked(), 0);

        // an unreachable tor port fails every dial, and the counters are swept with the set
        let dead = Prober::new(
            Socks {
                host: "127.0.0.1".into(),
                port: 1,
            },
            Duration::from_secs(1),
            Duration::from_secs(120),
            1,
            Arc::clone(&registry),
            Arc::clone(&canopy),
        );
        dead.run_cycle().await;
        assert_eq!(health_of(&g1.onion), "down");
        assert_eq!(health_of(&g2.onion), "down");
        let later = now + 901;
        assert!(matches!(
            registry
                .announce(&raw(&g2.announce(100, later, "q", None, None)), later)
                .await,
            Outcome::Accepted { .. }
        ));
        registry.sweep(later);
        dead.run_cycle().await;
        assert_eq!(
            dead.health.tracked(),
            1,
            "g1 expired and its counter went with it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
