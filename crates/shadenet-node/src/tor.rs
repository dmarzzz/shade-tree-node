//! C Tor as a child process (`packages/node/lib/node-supervisor.mjs`): the same `torrc` the
//! JavaScript supervisor wrote, started before the node serves and stopped after it drains.
//! A Tor that exits on its own ends the node, so the container's restart policy brings both
//! back together.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::onion;

pub(crate) const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
const STOP_GRACE: Duration = Duration::from_secs(5);
const MAX_STREAMS: u32 = 512;

/// What `tor --version` and `tor --list-modules` say about the Tor on PATH.
pub(crate) struct Info {
    pub(crate) version: String,
    pub(crate) pow: bool,
}

/// `None` when `tor` is not on PATH.
pub(crate) fn info() -> Option<Info> {
    let version = std::process::Command::new("tor")
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    let version = String::from_utf8_lossy(&version.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let modules = std::process::Command::new("tor")
        .arg("--list-modules")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
        .unwrap_or_default();
    let pow = modules
        .lines()
        .any(|line| line.trim_start().starts_with("pow:") && line.contains("yes"));
    Some(Info { version, pow })
}

pub(crate) struct TorrcSettings<'a> {
    pub(crate) state_dir: &'a Path,
    pub(crate) hs_dir: &'a Path,
    pub(crate) gateway_port: u16,
    pub(crate) socks_port: u16,
    pub(crate) pow: bool,
    pub(crate) fleet_tally_port: Option<u16>,
    /// `notice` (the default) or `info` for the file log at `<state>/tor.log`.
    pub(crate) log_level: &'a str,
}

/// The `torrc` text, byte for byte what the JavaScript supervisor wrote.
pub(crate) fn render_torrc(settings: &TorrcSettings<'_>) -> String {
    let level = if settings.log_level == "info" {
        "info"
    } else {
        "notice"
    };
    let mut lines = vec![
        "# shadenet-node: written at every start; edit node.toml or SHADENET_*, not this file."
            .to_string(),
        format!("DataDirectory {}", settings.state_dir.join("tor").display()),
        format!("SocksPort 127.0.0.1:{}", settings.socks_port),
        "ClientOnly 0".to_string(),
        "Log notice stdout".to_string(),
        format!(
            "Log {level} file {}",
            settings.state_dir.join("tor.log").display()
        ),
        "AvoidDiskWrites 1".to_string(),
        format!("HiddenServiceDir {}", settings.hs_dir.display()),
        format!("HiddenServicePort 80 127.0.0.1:{}", settings.gateway_port),
    ];
    if let Some(port) = settings.fleet_tally_port {
        lines.push(format!("HiddenServicePort {port} 127.0.0.1:{port}"));
    }
    lines.push(format!(
        "HiddenServicePoWDefensesEnabled {}",
        u8::from(settings.pow)
    ));
    lines.push(format!("HiddenServiceMaxStreams {MAX_STREAMS}"));
    lines.push("HiddenServiceMaxStreamsCloseCircuit 1".to_string());
    format!("{}\n", lines.join("\n"))
}

/// `tor --verify-config -f <torrc>`: `Ok` when it verifies, else the `[warn]`/`[err]` lines.
pub(crate) fn verify_config(torrc: &Path) -> Result<(), String> {
    let out = std::process::Command::new("tor")
        .args(["--verify-config", "-f"])
        .arg(torrc)
        .output()
        .map_err(|e| format!("could not run tor: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Err(text
        .lines()
        .filter(|line| line.contains("[warn]") || line.contains("[err]"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn interesting(line: &str) -> bool {
    if line.contains("[warn]") || line.contains("[err]") {
        return true;
    }
    ["0%", "5%", "10%", "25%", "50%", "75%", "90%", "100%"]
        .iter()
        .any(|pct| line.contains(&format!("Bootstrapped {pct}")))
}

fn strip_timestamp(line: &str) -> &str {
    line.find('[').map_or(line, |i| &line[i..])
}

pub(crate) struct Tor {
    child: Child,
}

/// Start Tor from a freshly written `torrc` and wait for `Bootstrapped 100%`.
pub(crate) async fn start(settings: &TorrcSettings<'_>, timeout: Duration) -> Result<Tor, String> {
    let torrc = settings.state_dir.join("torrc");
    onion::make_private_dir(&settings.state_dir.join("tor"))?;
    let _ = std::fs::remove_file(settings.state_dir.join("tor.log"));
    std::fs::write(&torrc, render_torrc(settings))
        .map_err(|e| format!("write {}: {e}", torrc.display()))?;
    let mut child = Command::new("tor")
        .arg("-f")
        .arg(&torrc)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not start tor: {e}"))?;
    let (bootstrapped_tx, bootstrapped_rx) = oneshot::channel();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    tokio::spawn(async move {
        let mut bootstrapped = Some(bootstrapped_tx);
        let mut stdout = stdout.map(|s| BufReader::new(s).lines());
        let mut stderr = stderr.map(|s| BufReader::new(s).lines());
        loop {
            let line = tokio::select! {
                line = async { match stdout.as_mut() { Some(lines) => lines.next_line().await, None => std::future::pending().await } } => line,
                line = async { match stderr.as_mut() { Some(lines) => lines.next_line().await, None => std::future::pending().await } } => line,
            };
            let Ok(Some(line)) = line else {
                break;
            };
            if line.trim().is_empty() {
                continue;
            }
            if interesting(&line) {
                tracing::info!("[tor] {}", strip_timestamp(&line));
            }
            if line.contains("Bootstrapped 100%") {
                if let Some(tx) = bootstrapped.take() {
                    let _ = tx.send(());
                }
            }
        }
    });
    let mut tor = Tor { child };
    tokio::select! {
        outcome = bootstrapped_rx => {
            if outcome.is_err() {
                let code = tor.child.wait().await.ok().and_then(|s| s.code());
                return Err(format!("tor exited with {} before bootstrapping", code.map_or("a signal".to_string(), |c| c.to_string())));
            }
        }
        () = tokio::time::sleep(timeout) => {
            tor.stop().await;
            return Err("tor did not bootstrap within the timeout (outbound to the Tor network blocked?)".into());
        }
    }
    Ok(tor)
}

impl Tor {
    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Resolves when Tor exits on its own, with its exit code when it has one.
    pub(crate) async fn exited(&mut self) -> Option<i32> {
        self.child.wait().await.ok().and_then(|s| s.code())
    }

    /// SIGTERM, a short grace, then SIGKILL.
    pub(crate) async fn stop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            // SAFETY: kill(2) with a pid this process spawned and still owns; it has no
            // memory-safety preconditions.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        if tokio::time::timeout(STOP_GRACE, self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_torrc_matches_the_javascript_supervisor() {
        let text = render_torrc(&TorrcSettings {
            state_dir: Path::new("/state"),
            hs_dir: Path::new("/state/hs-gateway"),
            gateway_port: 8443,
            socks_port: 9050,
            pow: false,
            fleet_tally_port: None,
            log_level: "notice",
        });
        assert_eq!(
            text,
            "# shadenet-node: written at every start; edit node.toml or SHADENET_*, not this file.\n\
DataDirectory /state/tor\n\
SocksPort 127.0.0.1:9050\n\
ClientOnly 0\n\
Log notice stdout\n\
Log notice file /state/tor.log\n\
AvoidDiskWrites 1\n\
HiddenServiceDir /state/hs-gateway\n\
HiddenServicePort 80 127.0.0.1:8443\n\
HiddenServicePoWDefensesEnabled 0\n\
HiddenServiceMaxStreams 512\n\
HiddenServiceMaxStreamsCloseCircuit 1\n"
        );
        let with_tally = render_torrc(&TorrcSettings {
            state_dir: Path::new("/state"),
            hs_dir: Path::new("/state/hs-gateway"),
            gateway_port: 8443,
            socks_port: 9050,
            pow: true,
            fleet_tally_port: Some(8444),
            log_level: "info",
        });
        assert!(with_tally.contains(
            "HiddenServicePort 8444 127.0.0.1:8444\nHiddenServicePoWDefensesEnabled 1\n"
        ));
        assert!(with_tally.contains("Log info file /state/tor.log\n"));
    }

    #[test]
    fn only_warnings_and_milestones_are_logged() {
        assert!(interesting("Oct 27 10:00:00.000 [notice] Bootstrapped 50% (loading_descriptors): Loading relay descriptors"));
        assert!(interesting("Oct 27 10:00:00.000 [warn] Something odd"));
        assert!(!interesting(
            "Oct 27 10:00:00.000 [notice] Bootstrapped 40% (loading_descriptors)"
        ));
        assert!(!interesting(
            "Oct 27 10:00:00.000 [notice] Opening Socks listener"
        ));
        assert_eq!(strip_timestamp("Oct 27 10:00:00.000 [warn] x"), "[warn] x");
    }
}
