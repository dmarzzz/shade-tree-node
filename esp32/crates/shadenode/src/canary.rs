//! The reputation canary: every ten minutes, fetch a couple of pages behind anti-bot vendors
//! from this node's own address. Two challenged rounds in a row mean the address is being
//! scored, so the node announces itself as draining before that reaches the household's own
//! browsing; three clean rounds clear it again. A drain the operator set is never touched.

use std::sync::Arc;
use std::time::Duration;

use microtor::rt::{sleep, spawn};

use crate::chain::{in_thread, Http};
use crate::node::Node;

pub const DEFAULT_URLS: [&str; 2] = ["https://www.cloudflare.com/", "https://duckduckgo.com/"];
const FIRST_PROBE: Duration = Duration::from_secs(30);
const DRAIN_AFTER: u32 = 2;
const CLEAR_AFTER: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    Challenged,
    /// Transport failures and server errors say nothing about reputation.
    Unknown,
}

/// A 403 or 429 is a block or a captcha; a 503 carrying Cloudflare's `cf-mitigated` header is
/// a challenge page. Everything else below 500 reached the page.
pub fn classify(status: u16, mitigated: bool) -> Outcome {
    match status {
        403 | 429 => Outcome::Challenged,
        503 if mitigated => Outcome::Challenged,
        200..=499 => Outcome::Clean,
        _ => Outcome::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Drained,
    Cleared,
}

/// The streak counters; pure, so the policy is testable without HTTP.
#[derive(Default)]
pub struct Watch {
    challenged_rounds: u32,
    clean_rounds: u32,
    drained: bool,
}

impl Watch {
    pub fn round(&mut self, outcomes: &[Outcome]) -> Action {
        if outcomes.contains(&Outcome::Challenged) {
            self.clean_rounds = 0;
            self.challenged_rounds += 1;
            if self.challenged_rounds >= DRAIN_AFTER && !self.drained {
                self.drained = true;
                return Action::Drained;
            }
        } else if outcomes.contains(&Outcome::Clean) {
            self.challenged_rounds = 0;
            self.clean_rounds += 1;
            if self.clean_rounds >= CLEAR_AFTER && self.drained {
                self.drained = false;
                return Action::Cleared;
            }
        }
        Action::None
    }
}

#[derive(Clone)]
pub struct CanaryConfig {
    pub http: Arc<dyn Http>,
    pub urls: Vec<String>,
    pub interval: Duration,
    pub thread_stack: usize,
    pub exclusive: bool,
}

impl Node {
    pub fn start_canary(&self, config: CanaryConfig) {
        let node = self.clone();
        spawn(async move {
            let mut watch = Watch::default();
            sleep(FIRST_PROBE).await;
            loop {
                let mut outcomes = Vec::with_capacity(config.urls.len());
                for url in &config.urls {
                    let (http, target) = (config.http.clone(), url.clone());
                    let _heavy = if config.exclusive {
                        Some(microtor::rt::heavy().await)
                    } else {
                        None
                    };
                    let probe =
                        in_thread(config.thread_stack, move || http.get_status(&target)).await;
                    outcomes.push(match probe.and_then(|r| r) {
                        Ok((status, mitigated)) => classify(status, mitigated),
                        Err(_) => Outcome::Unknown,
                    });
                }
                match watch.round(&outcomes) {
                    Action::Drained => {
                        log::warn!(
                            "canary: this address is being challenged; announcing as draining"
                        );
                        node.set_canary_drain(true);
                    }
                    Action::Cleared => {
                        log::info!("canary: probes are clean again; drain cleared");
                        node.set_canary_drain(false);
                    }
                    Action::None => {}
                }
                sleep(config.interval).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(classify(200, false), Outcome::Clean);
        assert_eq!(classify(403, false), Outcome::Challenged);
        assert_eq!(classify(429, false), Outcome::Challenged);
        assert_eq!(classify(503, true), Outcome::Challenged);
        assert_eq!(classify(503, false), Outcome::Unknown);
        assert_eq!(classify(404, false), Outcome::Clean);
    }

    #[test]
    fn two_challenged_rounds_drain_and_three_clean_rounds_clear() {
        use Outcome::*;
        let mut w = Watch::default();
        assert_eq!(w.round(&[Clean, Challenged]), Action::None);
        assert_eq!(w.round(&[Unknown, Unknown]), Action::None);
        assert_eq!(w.round(&[Challenged, Clean]), Action::Drained);
        assert_eq!(w.round(&[Challenged]), Action::None);
        assert_eq!(w.round(&[Clean]), Action::None);
        assert_eq!(w.round(&[Clean, Clean]), Action::None);
        assert_eq!(w.round(&[Clean]), Action::Cleared);
        // A challenged round in between starts the clean count over.
        let mut w = Watch::default();
        w.round(&[Challenged]);
        w.round(&[Challenged]);
        w.round(&[Clean]);
        w.round(&[Challenged]);
        w.round(&[Clean]);
        assert_eq!(w.round(&[Clean]), Action::None);
        assert_eq!(w.round(&[Clean]), Action::Cleared);
    }
}
