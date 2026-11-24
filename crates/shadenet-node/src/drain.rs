//! The operator drain flag (`packages/node/lib/drain.mjs`): one file whose presence makes
//! the heartbeat announce `draining: true` in its signed caps and `/readyz` answer 503, so a
//! planned stop is visible to clients before it happens.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

pub(crate) const DEFAULT_POLL_MS: u64 = 2_000;
const MIN_POLL_MS: u64 = 200;

#[derive(Clone)]
pub(crate) struct Flag {
    path: PathBuf,
}

impl Flag {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// True while the flag file exists; an unreadable path reads as not draining.
    pub(crate) fn is_set(&self) -> bool {
        self.path.exists()
    }

    /// Watch the file, publishing every transition. The receiver starts with the current state.
    pub(crate) fn watch(self: &Arc<Self>, poll: Duration) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(self.is_set());
        let flag = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                let next = flag.is_set();
                if *tx.borrow() != next && tx.send(next).is_err() {
                    return;
                }
            }
        });
        rx
    }
}

/// `SHADE_TREE_DRAIN_POLL_MS`, at least 200 ms.
pub(crate) fn poll_interval(raw: Option<u64>) -> Duration {
    Duration::from_millis(match raw {
        Some(ms) if ms >= MIN_POLL_MS => ms,
        _ => DEFAULT_POLL_MS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transitions_are_published() {
        let dir = std::env::temp_dir().join(format!("shadenet-drain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let flag = Arc::new(Flag::new(dir.join("draining")));
        let mut rx = flag.watch(Duration::from_millis(20));
        assert!(!*rx.borrow());
        std::fs::write(flag.path(), "now\n").unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*rx.borrow());
        std::fs::remove_file(flag.path()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(!*rx.borrow());
        assert_eq!(poll_interval(None), Duration::from_millis(2000));
        assert_eq!(poll_interval(Some(10)), Duration::from_millis(2000));
        assert_eq!(poll_interval(Some(500)), Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
