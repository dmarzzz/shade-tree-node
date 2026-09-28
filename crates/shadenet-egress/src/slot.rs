//! Crash-safe slot cursor shared byte-for-byte with the JavaScript client.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const MAX_LIMIT: u64 = 65_535;
pub const DEFAULT_LIMIT: u64 = 8;
const STATE_VERSION: u64 = 1;
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Unavailable(String),
    Locked(String),
    Corrupt(String),
    EpochRollback { saved: u64, current: u64 },
    InvalidLimit(u64),
    Exhausted { epoch: u64, limit: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "slot state unavailable: {e}"),
            Self::Locked(e) => write!(f, "slot state locked: {e}"),
            Self::Corrupt(e) => write!(f, "slot state corrupt: {e}"),
            Self::EpochRollback { saved, current } => {
                write!(
                    f,
                    "slot state refuses epoch rollback from {saved} to {current}"
                )
            }
            Self::InvalidLimit(k) => write!(f, "slot limit {k} is outside 1..={MAX_LIMIT}"),
            Self::Exhausted { epoch, limit } => write!(
                f,
                "epoch budget exhausted: used {limit}/{limit} slots in epoch {epoch}"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u64,
    epoch: u64,
    #[serde(rename = "nextSlot")]
    next_slot: u64,
}

fn unavailable(path: &Path, action: &str, error: impl fmt::Display) -> Error {
    Error::Unavailable(format!("{}: {action}: {error}", path.display()))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Same public-leaf-namespaced default path used by `client/slot-state.mjs`.
pub fn default_path(leaf: &str) -> Result<PathBuf, Error> {
    if leaf.is_empty() || !leaf.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Unavailable(
            "member leaf is not canonical decimal".into(),
        ));
    }
    let root = match std::env::var("SHADE_TREE_SLOT_STATE_DIR") {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("off") {
                return Err(Error::Unavailable(
                    "SHADE_TREE_SLOT_STATE_DIR cannot disable safety".into(),
                ));
            }
            PathBuf::from(value)
        }
        Err(_) => {
            if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
                PathBuf::from(xdg).join("shade-tree").join("rln-slots")
            } else if cfg!(windows) {
                let local = std::env::var("LOCALAPPDATA").map_err(|_| {
                    Error::Unavailable("no slot state base directory is configured".into())
                })?;
                PathBuf::from(local).join("shade-tree").join("rln-slots")
            } else {
                let home = std::env::var("HOME").map_err(|_| {
                    Error::Unavailable("no slot state base directory is configured".into())
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

fn load(path: &Path) -> Result<Option<State>, Error> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unavailable(path, "cannot read", error)),
    };
    let state: State = serde_json::from_str(&raw)
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
fn save(path: &Path, state: State) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = parent(path);
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
        fs::rename(&temp, path).map_err(|e| unavailable(path, "cannot replace", e))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| unavailable(path, "cannot fsync parent directory", e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(windows)]
fn save(path: &Path, state: State) -> Result<(), Error> {
    let body = serde_json::to_string_pretty(&state)
        .map_err(|e| unavailable(path, "cannot serialize", e))?
        + "\n";
    let parent = parent(path);
    for attempt in 0..16 {
        let temp = parent.join(format!(
            ".{}-{}-{}-{attempt}.slot-state.tmp",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed),
            state.next_slot
        ));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(unavailable(path, "cannot create temporary state", error)),
        };
        let result = (|| {
            file.write_all(body.as_bytes())
                .map_err(|e| unavailable(path, "cannot write", e))?;
            file.sync_all()
                .map_err(|e| unavailable(path, "cannot fsync", e))?;
            drop(file);
            windows_replace(&temp, path)
                .map_err(|e| unavailable(path, "cannot atomically replace", e))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        return result;
    }
    Err(Error::Unavailable(format!(
        "{}: cannot reserve a temporary state file",
        path.display()
    )))
}

#[cfg(windows)]
fn windows_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn save(path: &Path, state: State) -> Result<(), Error> {
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

struct Lock(PathBuf);

impl Lock {
    fn acquire(path: &Path) -> Result<Self, Error> {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        let lock = PathBuf::from(name);
        let started = Instant::now();
        loop {
            match fs::create_dir(&lock) {
                Ok(()) => return Ok(Self(lock)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(Error::Locked(format!(
                            "{} remained locked for {}ms",
                            path.display(),
                            LOCK_TIMEOUT.as_millis()
                        )));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(unavailable(path, "cannot create lock", error)),
            }
        }
    }

    fn release(mut self, path: &Path) -> Result<(), Error> {
        fs::remove_dir(&self.0).map_err(|e| unavailable(path, "cannot release lock", e))?;
        self.0.clear();
        Ok(())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir(&self.0);
        }
    }
}

/// Durably burn and return the next slot. The write and parent fsync happen
/// before this function returns, so a crash after allocation never rewinds it.
pub fn allocate(path: &Path, epoch: u64, limit: u64) -> Result<u64, Error> {
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::InvalidLimit(limit));
    }
    fs::create_dir_all(parent(path))
        .map_err(|e| unavailable(path, "cannot create parent directory", e))?;
    let lock = Lock::acquire(path)?;
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
        if next > limit {
            return Err(Error::Corrupt(format!(
                "{}: nextSlot {next} exceeds limit {limit}",
                path.display()
            )));
        }
        if next == limit {
            return Err(Error::Exhausted { epoch, limit });
        }
        save(
            path,
            State {
                version: STATE_VERSION,
                epoch,
                next_slot: next + 1,
            },
        )?;
        Ok(next)
    })();
    let unlock = lock.release(path);
    match (result, unlock) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_never_rewinds_a_consumed_slot() {
        let root = std::env::temp_dir().join(format!(
            "shade-tree-egress-slot-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("cursor.json");
        assert_eq!(allocate(&path, 7, 2).unwrap(), 0);
        // A new allocator invocation simulates a restarted process.
        assert_eq!(allocate(&path, 7, 2).unwrap(), 1);
        assert!(matches!(
            allocate(&path, 7, 2),
            Err(Error::Exhausted { .. })
        ));
        let _ = fs::remove_dir_all(root);
    }
}
