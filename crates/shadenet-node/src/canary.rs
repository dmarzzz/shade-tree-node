//! The reputation canary (`SHADE_TREE_CANARY=1`): a plain HTTPS GET from this host's own
//! address to pages behind anti-bot vendors, on a timer. A block or a challenge in two rounds
//! running means the node's IP is being scored, so the canary sets the drain flag before that
//! reaches the operator's own browsing; clean rounds clear a flag the canary set. A flag the
//! operator set by hand holds other content and is never touched.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::alerts::Alerts;
use crate::metrics::Registry;

pub(crate) const DEFAULT_URLS: &str = "https://www.cloudflare.com/,https://duckduckgo.com/";
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 600;
const FIRST_PROBE: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Rounds in a row that must be challenged before the node drains.
const DRAIN_AFTER: u32 = 2;
/// Clean rounds in a row before a canary-set flag is cleared.
const CLEAR_AFTER: u32 = 3;
/// What the canary writes into the drain flag, so it only ever clears its own.
const FLAG_CONTENT: &str = "canary\n";

#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) urls: Vec<String>,
    pub(crate) interval: Duration,
}

/// One probe's verdict. Transport failures and server errors say nothing about reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Clean,
    Challenged,
    Unknown,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Challenged => "challenged",
            Self::Unknown => "unknown",
        }
    }
}

/// A 403 or 429 is a block or a captcha; a 503 carrying Cloudflare's `cf-mitigated` header is a
/// challenge page. Everything else below 500 reached the page.
pub(crate) fn classify(status: u16, mitigated: bool) -> Outcome {
    match status {
        403 | 429 => Outcome::Challenged,
        503 if mitigated => Outcome::Challenged,
        200..=499 => Outcome::Clean,
        _ => Outcome::Unknown,
    }
}

/// The streak counters and the flag they act on; pure so the policy is testable without HTTP.
pub(crate) struct Watch {
    flag: PathBuf,
    challenged_rounds: u32,
    clean_rounds: u32,
}

/// What one round changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    None,
    Drained,
    Cleared,
}

impl Watch {
    pub(crate) fn new(flag: PathBuf) -> Self {
        Self {
            flag,
            challenged_rounds: 0,
            clean_rounds: 0,
        }
    }

    /// True while the flag exists with the canary's content.
    pub(crate) fn holds_flag(&self) -> bool {
        std::fs::read_to_string(&self.flag).is_ok_and(|text| text == FLAG_CONTENT)
    }

    /// Fold one round's probes in and act on the streaks.
    pub(crate) fn round(&mut self, outcomes: &[Outcome]) -> Action {
        let round = if outcomes.contains(&Outcome::Challenged) {
            Outcome::Challenged
        } else if outcomes.contains(&Outcome::Clean) {
            Outcome::Clean
        } else {
            Outcome::Unknown
        };
        match round {
            Outcome::Challenged => {
                self.challenged_rounds += 1;
                self.clean_rounds = 0;
                if self.challenged_rounds >= DRAIN_AFTER && !self.flag.exists() {
                    return match std::fs::write(&self.flag, FLAG_CONTENT) {
                        Ok(()) => Action::Drained,
                        Err(error) => {
                            tracing::warn!(path = %self.flag.display(), %error, "canary could not set the drain flag");
                            Action::None
                        }
                    };
                }
            }
            Outcome::Clean => {
                self.clean_rounds += 1;
                self.challenged_rounds = 0;
                if self.clean_rounds >= CLEAR_AFTER && self.holds_flag() {
                    return match std::fs::remove_file(&self.flag) {
                        Ok(()) => Action::Cleared,
                        Err(error) => {
                            tracing::warn!(path = %self.flag.display(), %error, "canary could not clear its drain flag");
                            Action::None
                        }
                    };
                }
            }
            Outcome::Unknown => {}
        }
        Action::None
    }
}

pub(crate) struct Canary {
    settings: Settings,
    client: reqwest::Client,
    registry: Arc<Registry>,
    alerts: Option<Arc<Alerts>>,
    watch: Watch,
}

impl Canary {
    pub(crate) fn new(
        settings: Settings,
        flag: &Path,
        registry: Arc<Registry>,
        alerts: Option<Arc<Alerts>>,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .user_agent(format!(
                "shadenet-node canary/{}",
                crate::config::build_version()
            ))
            .build()
            .map_err(|e| format!("build the canary client: {e}"))?;
        Ok(Self {
            settings,
            client,
            registry,
            alerts,
            watch: Watch::new(flag.to_path_buf()),
        })
    }

    pub(crate) fn describe(&self) -> String {
        format!(
            "reputation canary: ON (GET {} every {}s from this host's own address; {DRAIN_AFTER} challenged rounds set the drain flag, {CLEAR_AFTER} clean rounds clear it)",
            self.settings.urls.join(" "),
            self.settings.interval.as_secs()
        )
    }

    async fn probe(&self, url: &str) -> Outcome {
        let outcome = match self.client.get(url).send().await {
            Ok(response) => classify(
                response.status().as_u16(),
                response.headers().contains_key("cf-mitigated"),
            ),
            Err(error) => {
                tracing::debug!(url, %error, "canary probe failed");
                Outcome::Unknown
            }
        };
        self.registry.counter(
            "shade_tree_canary_probes_total",
            &[("outcome", outcome.label())],
        );
        if outcome == Outcome::Challenged {
            tracing::warn!(url, "canary probe was blocked or challenged");
        }
        outcome
    }

    /// Probe forever at the configured interval.
    pub(crate) async fn run(mut self) {
        tokio::time::sleep(FIRST_PROBE).await;
        loop {
            let mut outcomes = Vec::with_capacity(self.settings.urls.len());
            for url in &self.settings.urls {
                outcomes.push(self.probe(url).await);
            }
            let challenged = outcomes.contains(&Outcome::Challenged);
            self.registry.gauge(
                "shade_tree_canary_challenged",
                &[],
                if challenged { 1.0 } else { 0.0 },
            );
            match self.watch.round(&outcomes) {
                Action::Drained => {
                    tracing::warn!(
                        path = %self.watch.flag.display(),
                        "canary: this host's address is being challenged; drain flag set, the node announces draining until probes come back clean"
                    );
                    if let Some(alerts) = &self.alerts {
                        alerts
                            .lifecycle(
                                "CanaryDrained",
                                "the reputation canary set the drain flag: probes from this node's address are being challenged",
                            )
                            .await;
                    }
                }
                Action::Cleared => {
                    tracing::info!("canary: probes clean again; drain flag cleared");
                    if let Some(alerts) = &self.alerts {
                        alerts
                            .lifecycle(
                                "CanaryCleared",
                                "the reputation canary cleared its drain flag: probes are clean again",
                            )
                            .await;
                    }
                }
                Action::None => {}
            }
            self.registry.gauge(
                "shade_tree_canary_drained",
                &[],
                if self.watch.holds_flag() { 1.0 } else { 0.0 },
            );
            tokio::time::sleep(self.settings.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_classify_as_the_vendors_signal_them() {
        assert_eq!(classify(200, false), Outcome::Clean);
        assert_eq!(classify(301, false), Outcome::Clean);
        assert_eq!(classify(404, false), Outcome::Clean);
        assert_eq!(classify(403, false), Outcome::Challenged);
        assert_eq!(classify(429, false), Outcome::Challenged);
        assert_eq!(classify(503, true), Outcome::Challenged);
        assert_eq!(classify(503, false), Outcome::Unknown);
        assert_eq!(classify(500, false), Outcome::Unknown);
    }

    #[test]
    fn two_challenged_rounds_drain_and_three_clean_ones_clear_only_the_canarys_flag() {
        let dir = std::env::temp_dir().join(format!("shadenet-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("draining");
        let mut watch = Watch::new(flag.clone());

        assert_eq!(
            watch.round(&[Outcome::Challenged, Outcome::Clean]),
            Action::None
        );
        assert_eq!(
            watch.round(&[Outcome::Unknown]),
            Action::None,
            "an unknown round changes nothing"
        );
        assert_eq!(
            watch.round(&[Outcome::Clean, Outcome::Challenged]),
            Action::Drained
        );
        assert!(watch.holds_flag());
        assert_eq!(
            watch.round(&[Outcome::Challenged]),
            Action::None,
            "already drained"
        );

        assert_eq!(watch.round(&[Outcome::Clean]), Action::None);
        assert_eq!(watch.round(&[Outcome::Clean]), Action::None);
        assert_eq!(watch.round(&[Outcome::Clean]), Action::Cleared);
        assert!(!flag.exists());

        // the operator's own flag has other content and survives clean rounds
        std::fs::write(&flag, "maintenance\n").unwrap();
        assert!(!watch.holds_flag());
        for _ in 0..CLEAR_AFTER + 1 {
            assert_eq!(watch.round(&[Outcome::Clean]), Action::None);
        }
        assert!(flag.exists());
        // and a challenged streak does not overwrite it either
        for _ in 0..DRAIN_AFTER + 1 {
            assert_eq!(watch.round(&[Outcome::Challenged]), Action::None);
        }
        assert_eq!(std::fs::read_to_string(&flag).unwrap(), "maintenance\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_probe_reads_the_status_and_the_mitigation_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let replies: [&[u8]; 3] = [
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                b"HTTP/1.1 503 Service Unavailable\r\ncf-mitigated: challenge\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            ];
            for reply in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0_u8; 1024];
                let _ = socket.read(&mut buf).await;
                socket.write_all(reply).await.unwrap();
                let _ = socket.shutdown().await;
            }
        });
        let registry = Arc::new(Registry::new("node", "0", "0"));
        let dir = std::env::temp_dir().join(format!("shadenet-canary-http-{}", std::process::id()));
        let canary = Canary::new(
            Settings {
                urls: vec![format!("http://{addr}/")],
                interval: Duration::from_secs(1),
            },
            &dir.join("draining"),
            Arc::clone(&registry),
            None,
        )
        .unwrap();
        let url = format!("http://{addr}/");
        assert_eq!(canary.probe(&url).await, Outcome::Clean);
        assert_eq!(canary.probe(&url).await, Outcome::Challenged);
        assert_eq!(canary.probe(&url).await, Outcome::Challenged);
        let text = registry.render();
        assert!(
            text.contains("shade_tree_canary_probes_total{outcome=\"challenged\"} 2\n"),
            "{text}"
        );
        assert!(canary.describe().starts_with("reputation canary: ON"));
    }
}
