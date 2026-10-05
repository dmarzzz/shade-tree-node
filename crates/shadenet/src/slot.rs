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
///
/// The directory is `…/shade-tree/rln-slots/` and deliberately keeps that name through the ShadeNet
/// rename: a renamed binary that started from a fresh directory inside an epoch would re-issue slot
/// 0, reuse a nullifier with a different signal and get the member slashed. `SHADENET_SLOT_STATE_DIR`
/// and `SHADE_TREE_SLOT_STATE_DIR` are the same setting; setting both to different values fails
/// closed.
pub fn default_path(leaf: &str) -> Result<PathBuf, Error> {
    let configured = crate::env::var("SLOT_STATE_DIR").map_err(Error::Unavailable)?;
    default_path_with(
        leaf,
        configured.as_deref(),
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("LOCALAPPDATA").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// [`default_path`] with its inputs made explicit, for tests.
pub fn default_path_with(
    leaf: &str,
    configured: Option<&str>,
    xdg_state_home: Option<&str>,
    local_app_data: Option<&str>,
    home: Option<&str>,
) -> Result<PathBuf, Error> {
    if leaf.is_empty() || !leaf.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Unavailable(
            "member leaf is not canonical decimal".into(),
        ));
    }
    let root = match configured {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("off") {
                return Err(Error::Unavailable(
                    "SHADENET_SLOT_STATE_DIR cannot disable safety".into(),
                ));
            }
            PathBuf::from(value)
        }
        None => {
            if let Some(xdg) = xdg_state_home.filter(|value| !value.is_empty()) {
                PathBuf::from(xdg).join("shade-tree").join("rln-slots")
            } else if cfg!(windows) {
                let local = local_app_data.ok_or_else(|| {
                    Error::Unavailable("no slot state base directory is configured".into())
                })?;
                PathBuf::from(local).join("shade-tree").join("rln-slots")
            } else {
                let home = home.ok_or_else(|| {
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

/// Slots already used in `epoch`, without taking the lock. Informational only (status output);
/// allocation always goes through [`allocate`].
pub fn peek(path: &Path, epoch: u64) -> Result<u64, Error> {
    Ok(match load(path)? {
        Some(state) if state.epoch == epoch => state.next_slot,
        _ => 0,
    })
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

/// A lock whose holder is known to be gone is removed after this long.
const STALE_OWNED_LOCK: Duration = Duration::from_secs(60);
/// A lock with no owner record (written by the JS client or an older Rust client) is only removed
/// after this long. The critical section is a read, a write and two fsyncs, so a live holder never
/// comes close.
const STALE_ANONYMOUS_LOCK: Duration = Duration::from_secs(600);
const OWNER_FILE: &str = "owner";

struct Lock(PathBuf);

fn lock_age(lock: &Path) -> Option<Duration> {
    fs::metadata(lock)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let Ok(pid) = i32::try_from(pid) else {
        return true;
    };
    // Signal 0 checks existence. EPERM (a live process owned by someone else) also means alive.
    let result = unsafe { kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(3)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // No cheap portable check: treat the holder as alive and rely on the anonymous timeout.
    true
}

/// Decide whether an existing lock may be removed. Pure except for the liveness probe.
fn lock_is_stale(owner: Option<u32>, age: Duration, alive: impl Fn(u32) -> bool) -> bool {
    match owner {
        Some(pid) if pid == std::process::id() => false,
        Some(pid) => age >= STALE_OWNED_LOCK && !alive(pid),
        None => age >= STALE_ANONYMOUS_LOCK,
    }
}

fn read_owner(lock: &Path) -> Option<u32> {
    fs::read_to_string(lock.join(OWNER_FILE))
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
}

/// Clear a lock judged stale so two contenders can never both clear it and both enter the critical
/// section.
///
/// `remove_dir` + `create_dir` was not a compare-and-swap: two contenders that both judged the lock
/// stale could each remove it — the second removing the fresh lock the first had just created — and
/// both then create their own and hold it at once, so `allocate` handed both the same
/// (epoch, messageId), a slash. A plain `rename`-and-restore does not fix it either: a contender
/// descheduled between reading the dead owner and acting renames whatever sits at the path now
/// (possibly a live holder's lock), and restoring it leaves a window in which the path is empty and
/// a third contender enters alongside the live holder.
///
/// Recovery is instead serialized by an exclusive claim: `create_dir(<lock>.gc)` is atomic, so only
/// one recoverer proceeds; the losers fall back to the wait loop and then compete for the freed path
/// via the exclusive `create_dir(lock)`. Holding the claim, the recoverer re-reads the lock and
/// removes it only while it is STILL owned by a dead/anonymous holder. A dead-owned lock that is
/// still present proves no live holder exists (a holder must first see the path empty, which needs
/// this very claim), and no other recoverer can remove it meanwhile, so the recoverer never
/// destroys a live lock. A leftover `.gc` (a recoverer that died in the few syscalls it is held)
/// only blocks a later recovery and fails closed with `Locked`; it never slashes.
fn take_over_stale_lock(lock: &Path) -> Result<(), Error> {
    let mut gc = lock.as_os_str().to_os_string();
    gc.push(".gc");
    let gc = PathBuf::from(gc);
    match fs::create_dir(&gc) {
        Ok(()) => {
            // Re-read under the exclusive claim; only clear a lock still judged stale now.
            if let Some(age) = lock_age(lock) {
                if lock_is_stale(read_owner(lock), age, process_alive) {
                    tracing::warn!(
                        lock = %lock.display(),
                        age_secs = age.as_secs(),
                        "recovered a stale slot-state lock left by a dead process"
                    );
                    let _ = fs::remove_file(lock.join(OWNER_FILE));
                    let _ = fs::remove_dir(lock);
                }
            }
            let _ = fs::remove_dir(&gc);
            Ok(())
        }
        // Another recoverer holds the claim; wait and then compete via create_dir.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(unavailable(lock, "cannot claim stale-lock recovery", error)),
    }
}

impl Lock {
    fn acquire(path: &Path) -> Result<Self, Error> {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        let lock = PathBuf::from(name);
        let started = Instant::now();
        let mut recovered = false;
        loop {
            match fs::create_dir(&lock) {
                Ok(()) => {
                    // Best effort: an owner record lets a later process recover this lock if we die
                    // inside the critical section. Without it the lock is still exclusive.
                    let _ = fs::write(lock.join(OWNER_FILE), std::process::id().to_string());
                    return Ok(Self(lock));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !recovered {
                        if let Some(age) = lock_age(&lock) {
                            if lock_is_stale(read_owner(&lock), age, process_alive) {
                                // At most one takeover attempt per acquirer, whatever its outcome.
                                recovered = true;
                                take_over_stale_lock(&lock)?;
                                continue;
                            }
                        }
                    }
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
        let _ = fs::remove_file(self.0.join(OWNER_FILE));
        fs::remove_dir(&self.0).map_err(|e| unavailable(path, "cannot release lock", e))?;
        self.0.clear();
        Ok(())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_file(self.0.join(OWNER_FILE));
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

    #[test]
    fn slot_directory_survives_the_rename() {
        let leaf = "123";
        let xdg = default_path_with(leaf, None, Some("/state"), None, Some("/home/u")).unwrap();
        assert_eq!(xdg, PathBuf::from("/state/shade-tree/rln-slots/123.json"));
        if !cfg!(windows) {
            let home = default_path_with(leaf, None, None, None, Some("/home/u")).unwrap();
            assert_eq!(
                home,
                PathBuf::from("/home/u/.local/state/shade-tree/rln-slots/123.json")
            );
        }
        let explicit = default_path_with(leaf, Some("/x"), Some("/state"), None, None).unwrap();
        assert_eq!(explicit, PathBuf::from("/x/123.json"));
        for off in ["", "0", "off", "OFF"] {
            assert!(default_path_with(leaf, Some(off), None, None, Some("/h")).is_err());
        }
        assert!(default_path_with("0xabc", None, None, None, Some("/h")).is_err());
        // Both env prefixes name the same setting; a conflict must fail closed, never pick one.
        assert!(
            crate::env::resolve("SLOT_STATE_DIR", Some("/a".into()), Some("/b".into())).is_err()
        );
    }

    #[test]
    fn stale_lock_policy_never_steals_from_a_live_holder() {
        let alive = |_| true;
        let dead = |_| false;
        let long = Duration::from_secs(3600);
        let short = Duration::from_secs(1);
        assert!(!lock_is_stale(Some(1), long, alive));
        assert!(!lock_is_stale(Some(1), short, dead));
        assert!(lock_is_stale(Some(1), long, dead));
        assert!(!lock_is_stale(Some(std::process::id()), long, dead));
        assert!(!lock_is_stale(None, Duration::from_secs(300), dead));
        assert!(lock_is_stale(None, long, alive));
    }

    #[cfg(unix)]
    #[test]
    fn a_dead_holders_lock_is_recovered_and_peek_reports_usage() {
        let root = std::env::temp_dir().join(format!(
            "shadenet-slot-stale-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("cursor.json");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(peek(&path, 9).unwrap(), 0);
        assert_eq!(allocate(&path, 9, 4).unwrap(), 0);
        assert_eq!(peek(&path, 9).unwrap(), 1);
        assert_eq!(peek(&path, 10).unwrap(), 0);
        let lock = root.join("cursor.json.lock");
        fs::create_dir(&lock).unwrap();
        // A pid that cannot exist, aged past the owned-lock threshold.
        fs::write(lock.join(OWNER_FILE), (i32::MAX as u32).to_string()).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(120);
        File::open(&lock).unwrap().set_modified(old).unwrap();
        assert_eq!(allocate(&path, 9, 4).unwrap(), 1);
        assert!(!lock.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_recovery_of_a_stale_lock_never_hands_two_callers_the_same_slot() {
        // #A: many threads all find the SAME stale lock (dead owner, aged past the threshold) and
        // all attempt recovery at once. The old remove_dir + create_dir let two of them both
        // clear the lock and both enter `allocate`, returning the same (epoch, messageId) — a
        // slash. The atomic rename takeover admits one recoverer; everyone then serializes through
        // the lock, so every returned slot is distinct.
        use std::sync::{Arc, Barrier};

        for attempt in 0..8 {
            let root = std::env::temp_dir().join(format!(
                "shadenet-slot-race-{}-{}-{attempt}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let path = root.join("cursor.json");
            fs::create_dir_all(&root).unwrap();
            // Seed a stale lock: a pid that cannot exist, aged past the owned-lock threshold.
            let lock = root.join("cursor.json.lock");
            fs::create_dir(&lock).unwrap();
            fs::write(lock.join(OWNER_FILE), (i32::MAX as u32).to_string()).unwrap();
            let old = std::time::SystemTime::now() - Duration::from_secs(120);
            File::open(&lock).unwrap().set_modified(old).unwrap();

            let threads = 8;
            let barrier = Arc::new(Barrier::new(threads));
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let path = path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        allocate(&path, 42, 65_535)
                    })
                })
                .collect();

            let mut slots = Vec::new();
            for handle in handles {
                if let Ok(slot) = handle.join().unwrap() {
                    slots.push(slot);
                }
            }
            slots.sort_unstable();
            let mut unique = slots.clone();
            unique.dedup();
            assert_eq!(
                slots, unique,
                "two callers were handed the same slot during stale-lock recovery: {slots:?}"
            );
            // Every thread allocated (the big limit never exhausts): slots are exactly 0..threads.
            assert_eq!(
                slots,
                (0..threads as u64).collect::<Vec<_>>(),
                "attempt {attempt}"
            );
            assert!(!lock.exists(), "the recovered lock is released");
            let _ = fs::remove_dir_all(root);
        }
    }
}
