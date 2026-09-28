//! Crash-safe, cross-process RLN slot allocation, interoperable with
//! `client/slot-state.mjs`.
//!
//! The state is default-on and lives under the member's public enrollment leaf:
//! `{ "version": 1, "epoch": 42, "nextSlot": 3 }`. It never contains the
//! bearer secret, identity secret, nullifier, proof, or target. A directory lock
//! serializes JavaScript and Rust processes. The cursor is durably advanced before
//! proving, so a crash burns capacity instead of risking nullifier reuse.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const K_SLOTS: u64 = 8;
pub const MAX_LIMIT: u64 = 65535;
pub const STATE_VERSION: u64 = 1;
// Durable fsyncs can serialize slowly on loaded or network-backed home volumes.
// Ten seconds still fails closed on a stale lock while allowing a bounded burst of
// JavaScript/Rust allocators to drain without sacrificing slot uniqueness.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub epoch: u64,
    pub slot: Option<u64>,
    pub next_slot: u64,
}

impl Allocation {
    #[cfg_attr(not(feature = "live"), allow(dead_code))]
    pub fn exhausted(self) -> bool {
        self.slot.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Unavailable(String),
    Locked(String),
    Corrupt(String),
    EpochRollback { saved: u64, current: u64 },
    InvalidLimit(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(s) => write!(f, "slot state unavailable: {s}"),
            Self::Locked(s) => write!(f, "slot state locked: {s}"),
            Self::Corrupt(s) => write!(f, "slot state corrupt: {s}"),
            Self::EpochRollback { saved, current } => write!(
                f,
                "slot state refuses epoch rollback from {saved} to {current}"
            ),
            Self::InvalidLimit(k) => write!(f, "slot limit {k} is outside 1..={MAX_LIMIT}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u64,
    epoch: u64,
    #[serde(rename = "nextSlot")]
    next_slot: u64,
}

fn unavailable(path: &Path, action: &str, error: impl fmt::Display) -> Error {
    Error::Unavailable(format!("{}: {action}: {error}", path.display()))
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Resolve the same default path as JavaScript. The filename is the public member
/// leaf, so the two clients coordinate without deriving or persisting a bearer token.
#[cfg_attr(not(feature = "live"), allow(dead_code))]
pub fn default_path(leaf: &str) -> Result<PathBuf, Error> {
    if leaf.is_empty() || !leaf.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Unavailable(
            "member leaf is not canonical decimal".into(),
        ));
    }
    let root = match std::env::var("SHADE_TREE_SLOT_STATE_DIR") {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("off") {
                return Err(Error::Unavailable(
                    "SHADE_TREE_SLOT_STATE_DIR cannot disable safety; use the explicit unsafe slashing-test flag only in an isolated test".into(),
                ));
            }
            PathBuf::from(value)
        }
        Err(_) => {
            if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
                PathBuf::from(xdg).join("shade-tree").join("rln-slots")
            } else if cfg!(windows) {
                let local = std::env::var("LOCALAPPDATA")
                    .map_err(|_| Error::Unavailable("neither SHADE_TREE_SLOT_STATE_DIR, XDG_STATE_HOME, nor LOCALAPPDATA is set".into()))?;
                PathBuf::from(local).join("shade-tree").join("rln-slots")
            } else {
                let home = std::env::var("HOME").map_err(|_| {
                    Error::Unavailable(
                        "neither SHADE_TREE_SLOT_STATE_DIR, XDG_STATE_HOME, nor HOME is set".into(),
                    )
                })?;
                PathBuf::from(home)
                    .join(".local")
                    .join("state")
                    .join("shade-tree")
                    .join("rln-slots")
            }
        }
    };
    Ok(root.join(format!("{leaf}.json")))
}

fn load(path: &Path) -> Result<Option<Envelope>, Error> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unavailable(path, "cannot read", e)),
    };
    let state: Envelope = serde_json::from_str(&raw)
        .map_err(|e| Error::Corrupt(format!("{}: invalid JSON or shape: {e}", path.display())))?;
    if state.version != STATE_VERSION {
        return Err(Error::Corrupt(format!(
            "{}: unsupported version {}",
            path.display(),
            state.version
        )));
    }
    Ok(Some(state))
}

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn save(path: &Path, state: Envelope) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = parent_of(path);
    let temp = parent.join(format!(
        ".{}-{}-{}.slot-state.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed),
        state.next_slot
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| unavailable(path, "cannot create temporary state", e))?;
        let body = serde_json::to_string_pretty(&state)
            .map_err(|e| unavailable(path, "cannot serialize", e))?
            + "\n";
        file.write_all(body.as_bytes())
            .map_err(|e| unavailable(path, "cannot write", e))?;
        file.sync_all()
            .map_err(|e| unavailable(path, "cannot fsync", e))?;
        drop(file);
        fs::rename(&temp, path).map_err(|e| unavailable(path, "cannot atomically replace", e))?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| unavailable(path, "cannot fsync parent directory", e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

// Windows rename does not atomically replace an existing file. The cross-process
// directory lock still serializes writers; a crash during this direct write leaves a
// partial/corrupt file, which the next run refuses (safe loss of availability, no reset).
#[cfg(not(unix))]
fn save(path: &Path, state: Envelope) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| unavailable(path, "cannot open for write", e))?;
    let body = serde_json::to_string_pretty(&state)
        .map_err(|e| unavailable(path, "cannot serialize", e))?
        + "\n";
    file.write_all(body.as_bytes())
        .map_err(|e| unavailable(path, "cannot write", e))?;
    file.sync_all()
        .map_err(|e| unavailable(path, "cannot fsync", e))
}

struct LockGuard {
    path: PathBuf,
    held: bool,
}

impl LockGuard {
    fn acquire(state_path: &Path, timeout: Duration) -> Result<Self, Error> {
        let mut lock_name = state_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let started = Instant::now();
        loop {
            match fs::create_dir(&lock_path) {
                Ok(()) => {
                    return Ok(Self {
                        path: lock_path,
                        held: true,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if started.elapsed() >= timeout {
                        return Err(Error::Locked(format!(
                            "{} remained locked for {}ms",
                            state_path.display(),
                            timeout.as_millis()
                        )));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(unavailable(state_path, "cannot create lock", e)),
            }
        }
    }

    fn release(mut self, state_path: &Path) -> Result<(), Error> {
        fs::remove_dir(&self.path)
            .map_err(|e| unavailable(state_path, "cannot release lock", e))?;
        self.held = false;
        Ok(())
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if self.held {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// Atomically allocate and durably burn one slot. `slot=None` means the epoch's K
/// slots are exhausted. Missing state is a valid first run; every other storage or
/// parsing failure is fatal. State resets only when `epoch` strictly advances.
pub fn allocate(path: &Path, epoch: u64, k: u64) -> Result<Allocation, Error> {
    allocate_with_timeout(path, epoch, k, DEFAULT_LOCK_TIMEOUT)
}

pub fn allocate_with_timeout(
    path: &Path,
    epoch: u64,
    k: u64,
    timeout: Duration,
) -> Result<Allocation, Error> {
    if !(1..=MAX_LIMIT).contains(&k) {
        return Err(Error::InvalidLimit(k));
    }
    let parent = parent_of(path);
    fs::create_dir_all(parent)
        .map_err(|e| unavailable(path, "cannot create parent directory", e))?;
    let lock = LockGuard::acquire(path, timeout)?;
    let result = (|| {
        let saved = load(path)?;
        if let Some(saved) = saved {
            if saved.epoch > epoch {
                return Err(Error::EpochRollback {
                    saved: saved.epoch,
                    current: epoch,
                });
            }
        }
        let next = match saved {
            Some(saved) if saved.epoch == epoch => saved.next_slot,
            _ => 0,
        };
        if next > k {
            return Err(Error::Corrupt(format!(
                "{}: nextSlot {next} exceeds limit {k}",
                path.display()
            )));
        }
        if next == k {
            return Ok(Allocation {
                epoch,
                slot: None,
                next_slot: k,
            });
        }
        let advanced = next + 1;
        save(
            path,
            Envelope {
                version: STATE_VERSION,
                epoch,
                next_slot: advanced,
            },
        )?;
        Ok(Allocation {
            epoch,
            slot: Some(next),
            next_slot: advanced,
        })
    })();
    let unlock = lock.release(path);
    match (result, unlock) {
        (_, Err(e)) => Err(e),
        (result, Ok(())) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};

    fn temp_path() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "shade-tree-slotcursor-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root.join("slot-state.json")
    }

    fn slot(path: &Path, epoch: u64, k: u64) -> Option<u64> {
        allocate(path, epoch, k).unwrap().slot
    }

    #[test]
    fn restart_advances_and_stops_at_k_without_wrapping() {
        let path = temp_path();
        assert_eq!(slot(&path, 5, 3), Some(0));
        assert_eq!(slot(&path, 5, 3), Some(1));
        assert_eq!(slot(&path, 5, 3), Some(2));
        assert_eq!(slot(&path, 5, 3), None);
        assert_eq!(slot(&path, 5, 3), None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn only_epoch_advance_resets() {
        let path = temp_path();
        assert_eq!(slot(&path, 10, 1), Some(0));
        assert_eq!(slot(&path, 10, 1), None);
        assert_eq!(slot(&path, 11, 1), Some(0));
        assert_eq!(
            allocate(&path, 10, 1),
            Err(Error::EpochRollback {
                saved: 11,
                current: 10
            })
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn racing_allocators_receive_unique_slots() {
        let path = Arc::new(temp_path());
        let n = 16;
        let barrier = Arc::new(Barrier::new(n));
        let mut workers = Vec::new();
        for _ in 0..n {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                allocate(&path, 20, n as u64).unwrap().slot.unwrap()
            }));
        }
        let got: BTreeSet<u64> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(got, (0..n as u64).collect::<BTreeSet<_>>());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn corrupt_locked_and_unavailable_fail_closed() {
        let corrupt = temp_path();
        fs::write(
            &corrupt,
            r#"{"version":1,"epoch":3,"nextSlot":0,"secret":"x"}"#,
        )
        .unwrap();
        assert!(matches!(allocate(&corrupt, 3, 8), Err(Error::Corrupt(_))));

        let locked = temp_path();
        fs::create_dir_all(format!("{}.lock", locked.display())).unwrap();
        assert!(matches!(
            allocate_with_timeout(&locked, 3, 8, Duration::from_millis(5)),
            Err(Error::Locked(_))
        ));

        let blocker = temp_path();
        fs::write(&blocker, "not a directory").unwrap();
        assert!(matches!(
            allocate(&blocker.join("state"), 3, 8),
            Err(Error::Unavailable(_))
        ));

        for path in [&corrupt, &locked, &blocker] {
            let _ = fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[test]
    fn state_shape_matches_js_and_contains_only_nonsecret_integers() {
        let path = temp_path();
        assert_eq!(slot(&path, 42, K_SLOTS), Some(0));
        let raw = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["epoch", "nextSlot", "version"]);
        assert_eq!(
            value,
            serde_json::json!({ "version": 1, "epoch": 42, "nextSlot": 1 })
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn js_state_is_accepted_and_advanced() {
        let path = temp_path();
        fs::write(&path, "{\"version\":1,\"epoch\":99,\"nextSlot\":4}\n").unwrap();
        assert_eq!(slot(&path, 99, 8), Some(4));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap()).unwrap()
                ["nextSlot"],
            5
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
