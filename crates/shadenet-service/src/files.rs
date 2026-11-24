//! Files a service owns: written whole through a temporary sibling and a rename, private to
//! the service user, so a crash mid-write never leaves a truncated state file behind.

use std::path::Path;

/// Write `bytes` to `path` atomically with mode 0600, creating the parent directory.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    options.open(&temp).and_then(|mut f| f.write_all(bytes))?;
    std::fs::rename(&temp, path)
}
