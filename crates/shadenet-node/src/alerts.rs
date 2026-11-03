//! Webhook alerts without Prometheus (`packages/node/lib/alerts.mjs`): the fleet's alert
//! conditions evaluated in process from the local registry, posted to one webhook on every
//! transition and repeated while still firing. Off unless a webhook URL is configured.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::clock;
use crate::drain;
use crate::metrics::{Registry, Sample};

pub(crate) const DEFAULT_INTERVAL_MS: u64 = 30_000;
pub(crate) const DEFAULT_REPEAT_MS: u64 = 4 * 60 * 60 * 1000;
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);
const WINDOW_15_MIN: u64 = 15 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Generic,
    Slack,
    Discord,
    Matrix,
}

impl Format {
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("slack") => Self::Slack,
            Some("discord") => Self::Discord,
            Some("matrix") => Self::Matrix,
            _ => Self::Generic,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Slack => "slack",
            Self::Discord => "discord",
            Self::Matrix => "matrix",
        }
    }
}

#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) url: String,
    pub(crate) format: Format,
    pub(crate) instance: String,
    pub(crate) interval: Duration,
    pub(crate) repeat: Duration,
    /// The heartbeat interval the staleness rules are scaled by.
    pub(crate) heartbeat_interval: Duration,
}

/// This machine's name for the `instance` label.
pub(crate) fn hostname() -> String {
    for path in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let name = text.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "unknown".into()
}

struct Event<'a> {
    alert: &'a str,
    severity: &'a str,
    status: &'a str,
    summary: &'a str,
    starts_at: String,
}

fn line(instance: &str, event: &Event<'_>) -> String {
    let where_ = if instance.is_empty() {
        String::new()
    } else {
        format!(" ({instance})")
    };
    format!(
        "[shadenet] {} {}{where_}: {}",
        event.status.to_ascii_uppercase(),
        event.alert,
        event.summary
    )
}

fn payload(settings: &Settings, event: &Event<'_>) -> Value {
    let now = clock::iso(clock::now_ms());
    let generic = json!({
        "source": "shadenet",
        "version": 1,
        "role": "node",
        "instance": settings.instance,
        "alert": event.alert,
        "severity": event.severity,
        "status": event.status,
        "summary": event.summary,
        "startsAt": event.starts_at,
        "ts": now,
    });
    match settings.format {
        Format::Generic => generic,
        Format::Slack => json!({ "text": line(&settings.instance, event) }),
        Format::Discord => {
            json!({ "content": line(&settings.instance, event).chars().take(1900).collect::<String>() })
        }
        Format::Matrix => {
            let mut matrix = generic;
            if let Some(object) = matrix.as_object_mut() {
                object.insert(
                    "text".into(),
                    Value::String(line(&settings.instance, event)),
                );
                object.insert("msgtype".into(), Value::String("m.text".into()));
            }
            matrix
        }
    }
}

/// Which condition a rule watches.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    HeartbeatStale,
    HeartbeatNeverAccepted,
    EgressDown,
    ElderPartial,
    HeartbeatDraining,
    RootSourceDegraded,
    RpcEndpointFailing,
    HighDropRate,
    GatewayDraining,
}

impl Rule {
    const ALL: [Rule; 9] = [
        Rule::RootSourceDegraded,
        Rule::RpcEndpointFailing,
        Rule::HighDropRate,
        Rule::GatewayDraining,
        Rule::HeartbeatStale,
        Rule::HeartbeatNeverAccepted,
        Rule::EgressDown,
        Rule::ElderPartial,
        Rule::HeartbeatDraining,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::HeartbeatStale => "HeartbeatStale",
            Self::HeartbeatNeverAccepted => "HeartbeatNeverAccepted",
            Self::EgressDown => "EgressDown",
            Self::ElderPartial => "ElderPartial",
            Self::HeartbeatDraining | Self::GatewayDraining => "Draining",
            Self::RootSourceDegraded => "RootSourceDegraded",
            Self::RpcEndpointFailing => "RpcEndpointFailing",
            Self::HighDropRate => "HighDropRate",
        }
    }

    fn severity(self) -> &'static str {
        match self {
            Self::HeartbeatStale | Self::HeartbeatNeverAccepted | Self::EgressDown => "critical",
            Self::ElderPartial
            | Self::RootSourceDegraded
            | Self::RpcEndpointFailing
            | Self::HighDropRate => "warning",
            Self::HeartbeatDraining | Self::GatewayDraining => "info",
        }
    }

    fn for_ticks(self) -> u32 {
        match self {
            Self::EgressDown | Self::ElderPartial | Self::RootSourceDegraded => 2,
            _ => 1,
        }
    }
}

fn first(samples: &[Sample]) -> Option<f64> {
    samples.first().map(|s| s.value)
}

fn sum(samples: &[Sample]) -> f64 {
    samples.iter().map(|s| s.value).sum()
}

/// A rule's per-key history for rate rules: the counter value at each tick inside the window.
#[derive(Default)]
struct Windows {
    history: BTreeMap<&'static str, Vec<(u64, f64)>>,
}

impl Windows {
    fn delta(&mut self, key: &'static str, value: f64, span_ms: u64, now: u64) -> f64 {
        let entries = self.history.entry(key).or_default();
        entries.push((now, value));
        entries.retain(|(t, _)| *t >= now.saturating_sub(span_ms));
        (value - entries.first().map_or(value, |(_, v)| *v)).max(0.0)
    }
}

struct Context<'a> {
    registry: &'a Registry,
    drain: &'a drain::Flag,
    heartbeat: bool,
    stale_secs: f64,
    now: u64,
    windows: &'a mut Windows,
}

fn evaluate(rule: Rule, ctx: &mut Context<'_>) -> Option<String> {
    let values = |name: &str| ctx.registry.values(name);
    match rule {
        Rule::HeartbeatStale => {
            if !ctx.heartbeat {
                return None;
            }
            let last = first(&values(
                "shade_tree_heartbeat_last_success_timestamp_seconds",
            ))
            .filter(|v| *v > 0.0)?;
            let age = (ctx.now as f64 / 1000.0 - last).floor();
            (age > ctx.stale_secs).then(|| format!(
                "no Elder Tree accepted a heartbeat for {age}s (> {}s); the node ages out of the canopy at the directory TTL",
                ctx.stale_secs
            ))
        }
        Rule::HeartbeatNeverAccepted => {
            if !ctx.heartbeat {
                return None;
            }
            let last = first(&values(
                "shade_tree_heartbeat_last_success_timestamp_seconds",
            ))
            .unwrap_or(0.0);
            let up = first(&values("shade_tree_process_uptime_seconds")).unwrap_or(0.0);
            (last == 0.0 && up > ctx.stale_secs).then(|| format!(
                "no heartbeat accepted since start ({}s); check Tor, the Elder onion and the operator key",
                up.floor()
            ))
        }
        Rule::EgressDown => {
            if !ctx.heartbeat {
                return None;
            }
            (first(&values("shade_tree_heartbeat_egress_check_up")) == Some(0.0)).then(|| {
                "local egress check failing; heartbeat skipped, node will age out".to_string()
            })
        }
        Rule::ElderPartial => {
            if !ctx.heartbeat {
                return None;
            }
            let total = first(&values("shade_tree_heartbeat_elders_total")).unwrap_or(0.0);
            let accepted = first(&values("shade_tree_heartbeat_elders_accepted")).unwrap_or(0.0);
            (total > 1.0 && accepted > 0.0 && accepted < total)
                .then(|| format!("{accepted} of {total} Elder Trees accept this node's heartbeat"))
        }
        Rule::HeartbeatDraining => {
            if !ctx.heartbeat {
                return None;
            }
            (first(&values("shade_tree_heartbeat_draining")) == Some(1.0)).then(|| {
                "node announced draining; clients deprioritise it until the flag is removed"
                    .to_string()
            })
        }
        Rule::RootSourceDegraded => {
            let bad: Vec<String> = values("shade_tree_gateway_root_source_degraded")
                .iter()
                .filter(|s| s.value > 0.0)
                .map(|s| s.label("source").unwrap_or("?").to_string())
                .collect();
            (!bad.is_empty()).then(|| {
                format!(
                    "admission root source degraded: {} (serving the last good root)",
                    bad.join(",")
                )
            })
        }
        Rule::RpcEndpointFailing => {
            let total = sum(&values("shade_tree_rpc_failovers_total"));
            let delta = ctx.windows.delta("rpc", total, WINDOW_15_MIN, ctx.now);
            (delta >= 3.0).then(|| format!(
                "{delta} RPC failovers in the last 15 min (an endpoint in the record's list is failing)"
            ))
        }
        Rule::HighDropRate => {
            let series = values("shade_tree_gateway_tunnels_total");
            let pass: f64 = series
                .iter()
                .filter(|s| s.label("result") == Some("pass"))
                .map(|s| s.value)
                .sum();
            let drop: f64 = series
                .iter()
                .filter(|s| s.label("result") == Some("drop"))
                .map(|s| s.value)
                .sum();
            let wp = ctx.windows.delta("pass", pass, WINDOW_15_MIN, ctx.now);
            let wd = ctx.windows.delta("drop", drop, WINDOW_15_MIN, ctx.now);
            let n = wp + wd;
            (n >= 20.0 && wd / n > 0.5).then(|| {
                format!("{wd} of {n} tunnels dropped in 15 min (members failing the gate)")
            })
        }
        Rule::GatewayDraining => ctx.drain.is_set().then(|| {
            "gateway draining (readyz 503); in-flight tunnels finish, new ones go elsewhere"
                .to_string()
        }),
    }
}

struct RuleState {
    true_ticks: u32,
    firing: bool,
    since: u64,
    last_sent: u64,
}

pub(crate) struct Alerts {
    settings: Settings,
    registry: Arc<Registry>,
    drain: Arc<drain::Flag>,
    heartbeat: bool,
    client: reqwest::Client,
}

impl Alerts {
    pub(crate) fn new(
        settings: Settings,
        registry: Arc<Registry>,
        drain: Arc<drain::Flag>,
        heartbeat: bool,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .build()
            .map_err(|e| format!("build the alert webhook client: {e}"))?;
        Ok(Self {
            settings,
            registry,
            drain,
            heartbeat,
            client,
        })
    }

    pub(crate) fn format(&self) -> Format {
        self.settings.format
    }

    pub(crate) fn interval(&self) -> Duration {
        self.settings.interval
    }

    async fn send(&self, event: &Event<'_>) {
        let body = payload(&self.settings, event);
        let sent = self
            .client
            .post(&self.settings.url)
            .json(&body)
            .send()
            .await;
        match sent {
            Ok(response) if response.status().is_success() => {
                self.registry
                    .counter("shade_tree_alert_webhook_total", &[("result", "sent")]);
            }
            Ok(response) => {
                self.registry
                    .counter("shade_tree_alert_webhook_total", &[("result", "failed")]);
                tracing::warn!(
                    alert = event.alert,
                    "alert webhook delivery failed: webhook HTTP {}",
                    response.status().as_u16()
                );
            }
            Err(e) => {
                self.registry
                    .counter("shade_tree_alert_webhook_total", &[("result", "failed")]);
                tracing::warn!(alert = event.alert, "alert webhook delivery failed: {e}");
            }
        }
    }

    /// A one-off notice (started, stopping): sent as `info`, never repeated.
    pub(crate) async fn lifecycle(&self, alert: &str, summary: &str) {
        self.send(&Event {
            alert,
            severity: "info",
            status: "firing",
            summary,
            starts_at: clock::iso(clock::now_ms()),
        })
        .await;
    }

    /// Evaluate every rule on the interval until the task is dropped.
    pub(crate) async fn run(self: Arc<Self>) {
        let mut states: BTreeMap<Rule, RuleState> = BTreeMap::new();
        let mut windows = Windows::default();
        let stale_secs = 3.0 * self.settings.heartbeat_interval.as_secs_f64();
        loop {
            tokio::time::sleep(self.settings.interval).await;
            let now = clock::now_ms();
            for rule in Rule::ALL {
                let summary = evaluate(
                    rule,
                    &mut Context {
                        registry: &self.registry,
                        drain: &self.drain,
                        heartbeat: self.heartbeat,
                        stale_secs,
                        now,
                        windows: &mut windows,
                    },
                );
                let state = states.entry(rule).or_insert(RuleState {
                    true_ticks: 0,
                    firing: false,
                    since: 0,
                    last_sent: 0,
                });
                match summary {
                    Some(summary) => {
                        state.true_ticks += 1;
                        if !state.firing && state.true_ticks >= rule.for_ticks() {
                            state.firing = true;
                            state.since = now;
                            state.last_sent = now;
                            self.send(&Event {
                                alert: rule.name(),
                                severity: rule.severity(),
                                status: "firing",
                                summary: &summary,
                                starts_at: clock::iso(now),
                            })
                            .await;
                        } else if state.firing
                            && now.saturating_sub(state.last_sent)
                                >= self.settings.repeat.as_millis() as u64
                        {
                            state.last_sent = now;
                            self.send(&Event {
                                alert: rule.name(),
                                severity: rule.severity(),
                                status: "firing",
                                summary: &summary,
                                starts_at: clock::iso(state.since),
                            })
                            .await;
                        }
                    }
                    None => {
                        state.true_ticks = 0;
                        if state.firing {
                            state.firing = false;
                            self.send(&Event {
                                alert: rule.name(),
                                severity: rule.severity(),
                                status: "resolved",
                                summary: "condition cleared",
                                starts_at: clock::iso(state.since),
                            })
                            .await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_read_the_registry_like_the_javascript_evaluator() {
        let registry = Registry::new("node", "0", "0");
        let drain = drain::Flag::new(std::env::temp_dir().join("shadenet-alerts-no-such-flag"));
        let mut windows = Windows::default();
        fn ctx<'a>(
            registry: &'a Registry,
            drain: &'a drain::Flag,
            now: u64,
            windows: &'a mut Windows,
        ) -> Context<'a> {
            Context {
                registry,
                drain,
                heartbeat: true,
                stale_secs: 900.0,
                now,
                windows,
            }
        }
        registry.gauge(
            "shade_tree_heartbeat_last_success_timestamp_seconds",
            &[],
            1000.0,
        );
        assert!(evaluate(
            Rule::HeartbeatStale,
            &mut ctx(&registry, &drain, 2_000_000, &mut windows)
        )
        .unwrap()
        .starts_with("no Elder Tree accepted a heartbeat for 1000s"));
        assert!(evaluate(
            Rule::HeartbeatStale,
            &mut ctx(&registry, &drain, 1_500_000, &mut windows)
        )
        .is_none());
        registry.gauge("shade_tree_heartbeat_egress_check_up", &[], 0.0);
        assert!(evaluate(
            Rule::EgressDown,
            &mut ctx(&registry, &drain, 0, &mut windows)
        )
        .is_some());
        registry.gauge("shade_tree_heartbeat_elders_total", &[], 2.0);
        registry.gauge("shade_tree_heartbeat_elders_accepted", &[], 1.0);
        assert_eq!(
            evaluate(
                Rule::ElderPartial,
                &mut ctx(&registry, &drain, 0, &mut windows)
            )
            .unwrap(),
            "1 of 2 Elder Trees accept this node's heartbeat"
        );
        registry.gauge(
            "shade_tree_gateway_root_source_degraded",
            &[("source", "staked")],
            1.0,
        );
        assert_eq!(
            evaluate(
                Rule::RootSourceDegraded,
                &mut ctx(&registry, &drain, 0, &mut windows)
            )
            .unwrap(),
            "admission root source degraded: staked (serving the last good root)"
        );
        assert!(evaluate(
            Rule::GatewayDraining,
            &mut ctx(&registry, &drain, 0, &mut windows)
        )
        .is_none());
        // rate rules compare against the window's first sample
        registry.counter_add(
            "shade_tree_gateway_tunnels_total",
            &[("result", "drop"), ("reason", "bad-target")],
            30,
        );
        assert!(
            evaluate(
                Rule::HighDropRate,
                &mut ctx(&registry, &drain, 0, &mut windows)
            )
            .is_none(),
            "the first tick has no delta"
        );
        registry.counter_add(
            "shade_tree_gateway_tunnels_total",
            &[("result", "drop"), ("reason", "bad-target")],
            30,
        );
        registry.counter_add("shade_tree_gateway_tunnels_total", &[("result", "pass")], 5);
        assert_eq!(
            evaluate(
                Rule::HighDropRate,
                &mut ctx(&registry, &drain, 1000, &mut windows)
            )
            .unwrap(),
            "30 of 35 tunnels dropped in 15 min (members failing the gate)"
        );
        registry.counter_add("shade_tree_rpc_failovers_total", &[("endpoint", "0")], 3);
        evaluate(
            Rule::RpcEndpointFailing,
            &mut ctx(&registry, &drain, 0, &mut windows),
        );
        registry.counter_add("shade_tree_rpc_failovers_total", &[("endpoint", "0")], 3);
        assert!(evaluate(
            Rule::RpcEndpointFailing,
            &mut ctx(&registry, &drain, 1000, &mut windows)
        )
        .unwrap()
        .starts_with("3 RPC failovers"));
    }

    #[test]
    fn payloads_follow_the_format() {
        let settings = Settings {
            url: "https://hook".into(),
            format: Format::Slack,
            instance: "box".into(),
            interval: Duration::from_secs(30),
            repeat: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(300),
        };
        let event = Event {
            alert: "EgressDown",
            severity: "critical",
            status: "firing",
            summary: "down",
            starts_at: "t".into(),
        };
        assert_eq!(
            payload(&settings, &event),
            json!({"text": "[shadenet] FIRING EgressDown (box): down"})
        );
        let generic = payload(
            &Settings {
                format: Format::Generic,
                ..settings.clone()
            },
            &event,
        );
        assert_eq!(generic["source"], "shadenet");
        assert_eq!(generic["alert"], "EgressDown");
        let matrix = payload(
            &Settings {
                format: Format::Matrix,
                ..settings
            },
            &event,
        );
        assert_eq!(matrix["msgtype"], "m.text");
        assert_eq!(Format::parse(Some("DISCORD")), Format::Discord);
        assert_eq!(Format::parse(Some("pager")), Format::Generic);
    }
}
