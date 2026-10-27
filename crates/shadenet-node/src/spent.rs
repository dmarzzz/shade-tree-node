//! Nullifier spent set (`gateway.mjs` `makeSpentSet`, `makeSpentStatePersister`): one proof
//! share per nullifier, an honest-retry window for an exact replay, over-spend detection on a
//! second distinct share, and a restart snapshot that keeps budgets closed across a restart.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_IMPORTED: usize = 1_000_000;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Share {
    pub(crate) x: String,
    pub(crate) y: String,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    n: String,
    xs: Vec<String>,
    first: Share,
    slashed: bool,
    at: u64,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    entries: Vec<Entry>,
    envs: Vec<(String, u64)>,
}

struct Seen {
    xs: HashSet<String>,
    first: Share,
    slashed: bool,
    at: u64,
}

struct Inner {
    seen: HashMap<String, Seen>,
    seen_envelopes: HashMap<String, u64>,
    last_written: String,
}

pub(crate) enum Admission {
    /// The nullifier's first share on this node.
    First,
    /// An exact replay inside the honest-retry window.
    Replay,
    /// Refused with this wire reason.
    Refused(&'static str),
    /// A second distinct share: the member over-spent. The caller slashes.
    OverSpend { first: Share, second: Share },
}

pub(crate) struct SpentSet {
    inner: Mutex<Inner>,
    ttl: Duration,
    replay_window: Duration,
    path: Option<PathBuf>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl SpentSet {
    pub(crate) fn new(epoch_seconds: u64, replay_window: Duration, path: Option<PathBuf>) -> Self {
        let set = Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                seen_envelopes: HashMap::new(),
                last_written: String::new(),
            }),
            ttl: Duration::from_secs(2 * epoch_seconds),
            replay_window,
            path,
        };
        set.load();
        set
    }

    /// Has this node seen the nullifier already (its first share is held here)?
    pub(crate) fn is_known(&self, nullifier: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .contains_key(nullifier)
    }

    pub(crate) fn admit(&self, nullifier: &str, share: Share, nonce: Option<&str>) -> Admission {
        let envelope_key = format!("{nullifier}|{}|{}", share.x, nonce.unwrap_or(""));
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(seen) = inner.seen.get_mut(nullifier) else {
            inner.seen.insert(
                nullifier.to_string(),
                Seen {
                    xs: HashSet::from([share.x.clone()]),
                    first: share,
                    slashed: false,
                    at: now,
                },
            );
            inner.seen_envelopes.insert(envelope_key, now);
            return Admission::First;
        };
        if seen.slashed {
            return Admission::Refused("rate-slashed");
        }
        if seen.xs.contains(&share.x) {
            let window = u64::try_from(self.replay_window.as_millis()).unwrap_or(u64::MAX);
            return match inner.seen_envelopes.get(&envelope_key) {
                Some(first_at) if now.saturating_sub(*first_at) <= window => Admission::Replay,
                first_at => {
                    tracing::debug!(
                        age_ms = first_at.map(|at| now.saturating_sub(*at)),
                        window_ms = window,
                        "replayed envelope rejected"
                    );
                    Admission::Refused("replayed-envelope")
                }
            };
        }
        seen.slashed = true;
        Admission::OverSpend {
            first: seen.first.clone(),
            second: share,
        }
    }

    fn sweep(inner: &mut Inner, cutoff: u64) {
        inner.seen.retain(|_, seen| seen.at >= cutoff);
        inner.seen_envelopes.retain(|_, at| *at >= cutoff);
    }

    fn cutoff(&self) -> u64 {
        now_ms().saturating_sub(u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX))
    }

    fn load(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!("spent set snapshot unreadable; starting empty: {e}");
                return;
            }
        };
        let snapshot: Snapshot = match serde_json::from_slice(&bytes) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                tracing::warn!("spent set snapshot unreadable; starting empty: {e}");
                return;
            }
        };
        if snapshot.version != 1 {
            tracing::warn!(
                "spent set snapshot version {} not understood; starting empty",
                snapshot.version
            );
            return;
        }
        let cutoff = self.cutoff();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut restored = 0;
        for entry in snapshot.entries.into_iter().take(MAX_IMPORTED) {
            if entry.at < cutoff || inner.seen.contains_key(&entry.n) {
                continue;
            }
            inner.seen.insert(
                entry.n,
                Seen {
                    xs: entry.xs.into_iter().collect(),
                    first: entry.first,
                    slashed: entry.slashed,
                    at: entry.at,
                },
            );
            restored += 1;
        }
        for (key, at) in snapshot.envs.into_iter().take(MAX_IMPORTED) {
            if at >= cutoff {
                inner.seen_envelopes.entry(key).or_insert(at);
            }
        }
        tracing::info!("spent set restored: {restored} nullifiers");
    }

    /// Sweep expired entries and write the snapshot when it changed.
    pub(crate) fn flush(&self) {
        let cutoff = self.cutoff();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut inner, cutoff);
        let Some(path) = &self.path else {
            return;
        };
        let snapshot = Snapshot {
            version: 1,
            entries: inner
                .seen
                .iter()
                .map(|(n, seen)| Entry {
                    n: n.clone(),
                    xs: seen.xs.iter().cloned().collect(),
                    first: seen.first.clone(),
                    slashed: seen.slashed,
                    at: seen.at,
                })
                .collect(),
            envs: inner
                .seen_envelopes
                .iter()
                .map(|(k, at)| (k.clone(), *at))
                .collect(),
        };
        let body = match serde_json::to_string(&snapshot) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("spent set snapshot not serialised: {e}");
                return;
            }
        };
        if body == inner.last_written {
            return;
        }
        if let Err(e) = write_private(path, body.as_bytes()) {
            tracing::warn!("spent set snapshot write failed: {e}");
            return;
        }
        inner.last_written = body;
    }

    pub(crate) async fn flush_periodically(&self) {
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;
            self.flush();
        }
    }
}

fn write_private(path: &PathBuf, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options.open(&tmp)?.write_all(body)?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(x: &str) -> Share {
        Share {
            x: x.into(),
            y: "9".into(),
        }
    }

    #[test]
    fn first_then_replay_then_over_spend() {
        let set = SpentSet::new(120, Duration::from_secs(5), None);
        assert!(matches!(
            set.admit("n1", share("1"), Some("a")),
            Admission::First
        ));
        assert!(matches!(
            set.admit("n1", share("1"), Some("a")),
            Admission::Replay
        ));
        assert!(matches!(
            set.admit("n1", share("1"), Some("other")),
            Admission::Refused("replayed-envelope")
        ));
        match set.admit("n1", share("2"), Some("b")) {
            Admission::OverSpend { first, second } => {
                assert_eq!(first.x, "1");
                assert_eq!(second.x, "2");
            }
            _ => panic!("a second distinct share is an over-spend"),
        }
        assert!(matches!(
            set.admit("n1", share("3"), None),
            Admission::Refused("rate-slashed")
        ));
        assert!(matches!(
            set.admit("n2", share("1"), None),
            Admission::First
        ));
    }

    #[test]
    fn a_replay_outside_the_window_is_refused() {
        let set = SpentSet::new(120, Duration::ZERO, None);
        assert!(matches!(set.admit("n", share("1"), None), Admission::First));
        std::thread::sleep(Duration::from_millis(2));
        assert!(matches!(
            set.admit("n", share("1"), None),
            Admission::Refused("replayed-envelope")
        ));
    }

    #[test]
    fn the_snapshot_round_trips_live_entries_only() {
        let dir = std::env::temp_dir().join(format!("shadenet-node-spent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spent-set.json");
        let set = SpentSet::new(120, Duration::from_secs(5), Some(path.clone()));
        assert!(matches!(
            set.admit("n1", share("1"), Some("a")),
            Admission::First
        ));
        set.flush();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"version\":1,\"entries\":[{\"n\":\"n1\",\"xs\":[\"1\"],\"first\":{\"x\":\"1\",\"y\":\"9\"},\"slashed\":false,\"at\":"));
        assert!(text.contains("\"envs\":[[\"n1|1|a\","));

        let restored = SpentSet::new(120, Duration::from_secs(5), Some(path.clone()));
        assert!(matches!(
            restored.admit("n1", share("1"), Some("a")),
            Admission::Replay
        ));

        std::thread::sleep(Duration::from_millis(2));
        let expired = SpentSet::new(0, Duration::from_secs(5), Some(path));
        assert!(matches!(
            expired.admit("n1", share("1"), Some("a")),
            Admission::First
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
