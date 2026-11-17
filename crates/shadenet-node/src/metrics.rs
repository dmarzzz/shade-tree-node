//! In-process Prometheus metrics (`packages/node/lib/metrics.mjs`): the same series names,
//! help text, label enums and text exposition as the JavaScript node, served on a loopback
//! listener with `/metrics`, `/livez` and `/readyz`. Label values are closed enums chosen by
//! the node, never peer bytes, and every metric has a series ceiling.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::clock;
use crate::drain;

const MAX_SERIES: usize = 128;
const MAX_LABEL_VALUE: usize = 160;
const LATENCY_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const REQUEST_HEAD_MAX: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Every series this process may emit, with the help text the JavaScript node ships.
const DEFINITIONS: &[(&str, Kind, &str)] = &[
    ("shade_tree_build_info", Kind::Gauge, "Build and role information (role, version, running commit); always 1."),
    ("shade_tree_process_start_time_seconds", Kind::Gauge, "Unix time when this process started."),
    ("shade_tree_process_uptime_seconds", Kind::Gauge, "Process uptime in seconds."),
    ("shade_tree_process_resident_memory_bytes", Kind::Gauge, "Resident memory used by this process."),
    ("shade_tree_gateway_tunnels_total", Kind::Counter, "Tunnels by result=pass|drop (+ reason on drop)."),
    ("shade_tree_gateway_slashes_total", Kind::Counter, "Members slashed for an RLN over-spend (2nd distinct signal on a nullifier)."),
    ("shade_tree_gateway_verify_seconds", Kind::Histogram, "verifyEnvelope() latency in seconds (cheap-first checks + Groth16)."),
    ("shade_tree_gateway_upstream_connect_seconds", Kind::Histogram, "Node-to-destination TCP connect latency in seconds. No destination labels are recorded."),
    ("shade_tree_gateway_tunnel_closes_total", Kind::Counter, "Established tunnels closed by the gateway, by reason (idle-timeout|payload-limit|upstream-error)."),
    ("shade_tree_gateway_trusted_roots", Kind::Gauge, "Trusted admission roots right now, by bounded source=invited|staked|paid."),
    ("shade_tree_gateway_root_source_degraded", Kind::Gauge, "1 = this bounded root source failed its last refresh; 0 = healthy."),
    ("shade_tree_gateway_paid_access_leaves", Kind::Gauge, "Live leaves in the PaidAccessSet; no contract label is exposed."),
    ("shade_tree_gateway_agent_to_destination_payload_bytes_total", Kind::Counter, "Application payload bytes relayed from agents after tunnel establishment. No traffic labels are recorded."),
    ("shade_tree_gateway_destination_to_agent_payload_bytes_total", Kind::Counter, "Application payload bytes relayed from destinations after tunnel establishment. No traffic labels are recorded."),
    ("shade_tree_gateway_sessions_total", Kind::Counter, "Session-ticket initializations by result=pass|drop (+ reason on drop)."),
    ("shade_tree_gateway_tickets_total", Kind::Counter, "Session-ticket spends by result=pass|drop (+ reason on drop)."),
    ("shade_tree_gateway_active_tunnels", Kind::Gauge, "Established egress tunnels open right now."),
    ("shade_tree_gateway_connections", Kind::Gauge, "Accepted client connections, including pre-verification sockets."),
    ("shade_tree_rpc_failovers_total", Kind::Counter, "RPC endpoint failovers by endpoint index (never the URL)."),
    ("shade_tree_rpc_throttle_retries_total", Kind::Counter, "RPC requests resent after the endpoint rate-limited them, by HTTP status."),
    ("shade_tree_heartbeat_attempts_total", Kind::Counter, "Heartbeat cycles by bounded outcome=accepted|rejected|egress-unhealthy|transport-error."),
    ("shade_tree_heartbeat_last_success_timestamp_seconds", Kind::Gauge, "Unix timestamp of the last accepted heartbeat."),
    ("shade_tree_heartbeat_egress_check_up", Kind::Gauge, "1 when the latest local egress check succeeded, 0 when it failed."),
    ("shade_tree_heartbeat_elders_total", Kind::Gauge, "Elder Trees this heartbeat announces to (ADR 0012)."),
    ("shade_tree_heartbeat_elders_accepted", Kind::Gauge, "Elder Trees that accepted the latest heartbeat cycle."),
    ("shade_tree_heartbeat_draining", Kind::Gauge, "1 while the operator drain flag is set and announced in the signed caps."),
    ("shade_tree_canary_probes_total", Kind::Counter, "Reputation canary probes by outcome=clean|challenged|unknown."),
    ("shade_tree_canary_challenged", Kind::Gauge, "1 when the latest canary round met a block or a challenge."),
    ("shade_tree_canary_drained", Kind::Gauge, "1 while the canary holds the drain flag."),
    ("shade_tree_gateway_blocklist_hosts", Kind::Gauge, "Hosts loaded from SHADE_TREE_EGRESS_DENY_FILE."),
    ("shade_tree_alert_webhook_total", Kind::Counter, "Alert webhook deliveries by result=sent|failed."),
];

/// Wire reasons that may appear on a `reason` label, as the JavaScript node bounds them.
const DROP_LABELS: &[&str] = &[
    "too-many-connections",
    "envelope-timeout",
    "envelope-too-large",
    "bad-envelope",
    "bad-version",
    "unsupported-version",
    "wrong-group-root",
    "root-not-recent",
    "invalid-proof",
    "bad-share",
    "bad-signal",
    "bad-external-nullifier",
    "bad-nullifier",
    "artifact-unknown",
    "artifact-retired",
    "bad-artifact",
    "bad-target",
    "bad-target-policy",
    "bad-target-address",
    "bad-target-dns",
    "replayed-envelope",
    "rate-slashed",
    "over-spend-slashed",
    "nullifier-conn-limit",
    "payload-limit",
    "upstream-timeout",
    "upstream-refused",
    "upstream-unreachable",
    "upstream-reset",
    "upstream-error",
    "internal-error",
    "session-unsupported",
    "session-malformed",
    "session-version",
    "session-class",
    "session-gateway",
    "session-nonce",
    "session-ticket-count",
    "session-commitment",
    "session-digest",
    "session-wrong-gateway",
    "session-conflict",
    "session-capacity",
    "session-unknown",
    "session-expired",
    "session-idle",
    "session-streams",
    "session-pending",
    "session-stream-max",
    "session-not-bound",
    "ticket-malformed",
    "ticket-version",
    "ticket-book",
    "ticket-index",
    "ticket-secret",
    "ticket-nonce",
    "ticket-mismatch",
    "ticket-spent",
    "ticket-conflict",
    "ticket-inflight",
];

/// A bounded metrics label for a refusal reason (`gateway.mjs` `gatewayDropLabel`).
pub(crate) fn drop_label(reason: &str) -> &'static str {
    let raw = reason.to_ascii_lowercase();
    let base = raw.split(':').next().unwrap_or("internal-error");
    if let Some(known) = DROP_LABELS.iter().find(|label| **label == base) {
        return known;
    }
    if base.contains("artifact") {
        "bad-artifact"
    } else if base.contains("version") {
        "bad-version"
    } else if base.contains("root") {
        "root-not-recent"
    } else if base.contains("proof") {
        "invalid-proof"
    } else {
        "internal-error"
    }
}

/// The label a dropped upstream connect gets from its error reason (`upstream:<code>`).
pub(crate) fn upstream_drop_label(reason: &str) -> &'static str {
    match reason.strip_prefix("upstream:").unwrap_or(reason) {
        "ECONNREFUSED" => "upstream-refused",
        "ENETUNREACH" | "EHOSTUNREACH" | "ENETDOWN" => "upstream-unreachable",
        "ECONNRESET" | "EPIPE" => "upstream-reset",
        "ETIMEDOUT" => "upstream-timeout",
        _ => "upstream-error",
    }
}

struct Histogram {
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

struct Series {
    labels: Vec<(String, String)>,
    value: f64,
    histogram: Option<Histogram>,
}

struct Metric {
    kind: Kind,
    help: &'static str,
    series: BTreeMap<String, Series>,
}

/// One series' current labels and value, for the alert rules.
pub(crate) struct Sample {
    pub(crate) labels: Vec<(String, String)>,
    pub(crate) value: f64,
}

impl Sample {
    pub(crate) fn label(&self, name: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) struct Registry {
    started: Instant,
    metrics: Mutex<BTreeMap<&'static str, Metric>>,
}

fn escape_label_value(value: &str) -> String {
    let bounded: String = if value.chars().count() <= MAX_LABEL_VALUE {
        value.to_string()
    } else {
        format!(
            "{}[truncated]",
            value.chars().take(MAX_LABEL_VALUE).collect::<String>()
        )
    };
    bounded
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn label_key(labels: &[(&str, &str)]) -> (String, Vec<(String, String)>) {
    let mut sorted: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    sorted.sort();
    let key = sorted
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
        .collect::<Vec<_>>()
        .join(",");
    (key, sorted)
}

/// Render a value the way JavaScript's `String(number)` does for the values seen here.
fn format_number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    if value.fract() == 0.0 && value.abs() < 1e21 {
        return format!("{}", value as i128);
    }
    format!("{value}")
}

fn resident_memory_bytes() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kib: f64 = rest
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse()
                        .unwrap_or(0.0);
                    return kib * 1024.0;
                }
            }
        }
    }
    0.0
}

impl Registry {
    /// Every series registered, with the role and build labels fixed for the process.
    pub(crate) fn new(role: &str, version: &str, commit: &str) -> Self {
        let mut metrics = BTreeMap::new();
        for (name, kind, help) in DEFINITIONS {
            metrics.insert(
                *name,
                Metric {
                    kind: *kind,
                    help,
                    series: BTreeMap::new(),
                },
            );
        }
        let registry = Self {
            started: Instant::now(),
            metrics: Mutex::new(metrics),
        };
        registry.gauge(
            "shade_tree_build_info",
            &[("role", role), ("version", version), ("commit", commit)],
            1.0,
        );
        registry.gauge(
            "shade_tree_process_start_time_seconds",
            &[],
            clock::now_ms() as f64 / 1000.0,
        );
        registry
    }

    fn update(&self, name: &str, labels: &[(&str, &str)], apply: impl FnOnce(Kind, &mut Series)) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        let Some(metric) = metrics.get_mut(name) else {
            return;
        };
        let (key, sorted) = label_key(labels);
        if !metric.series.contains_key(&key) {
            if metric.series.len() >= MAX_SERIES {
                return;
            }
            metric.series.insert(
                key.clone(),
                Series {
                    labels: sorted,
                    value: 0.0,
                    histogram: None,
                },
            );
        }
        if let Some(series) = metric.series.get_mut(&key) {
            apply(metric.kind, series);
        }
    }

    pub(crate) fn counter(&self, name: &str, labels: &[(&str, &str)]) {
        self.counter_add(name, labels, 1);
    }

    pub(crate) fn counter_add(&self, name: &str, labels: &[(&str, &str)], n: u64) {
        self.update(name, labels, |kind, series| {
            if kind == Kind::Counter {
                series.value += n as f64;
            }
        });
    }

    pub(crate) fn gauge(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        if !value.is_finite() {
            return;
        }
        self.update(name, labels, |kind, series| {
            if kind == Kind::Gauge {
                series.value = value;
            }
        });
    }

    pub(crate) fn observe(&self, name: &str, seconds: f64) {
        if !seconds.is_finite() || seconds < 0.0 {
            return;
        }
        self.update(name, &[], |kind, series| {
            if kind != Kind::Histogram {
                return;
            }
            let histogram = series.histogram.get_or_insert_with(|| Histogram {
                counts: vec![0; LATENCY_BUCKETS.len()],
                sum: 0.0,
                count: 0,
            });
            histogram.count += 1;
            histogram.sum += seconds;
            for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
                if seconds <= *bound {
                    histogram.counts[i] += 1;
                }
            }
        });
    }

    /// Every counter or gauge series of `name` (an unknown name is empty).
    pub(crate) fn values(&self, name: &str) -> Vec<Sample> {
        match name {
            "shade_tree_process_uptime_seconds" => {
                return vec![Sample {
                    labels: Vec::new(),
                    value: self.started.elapsed().as_secs_f64(),
                }]
            }
            "shade_tree_process_resident_memory_bytes" => {
                return vec![Sample {
                    labels: Vec::new(),
                    value: resident_memory_bytes(),
                }]
            }
            _ => {}
        }
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics
            .get(name)
            .filter(|m| m.kind != Kind::Histogram)
            .map(|m| {
                m.series
                    .values()
                    .map(|s| Sample {
                        labels: s.labels.clone(),
                        value: s.value,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The Prometheus text exposition of every metric, deterministic.
    pub(crate) fn render(&self) -> String {
        let synthesized: BTreeMap<&str, f64> = BTreeMap::from([
            (
                "shade_tree_process_uptime_seconds",
                self.started.elapsed().as_secs_f64(),
            ),
            (
                "shade_tree_process_resident_memory_bytes",
                resident_memory_bytes(),
            ),
        ]);
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        for (name, metric) in metrics.iter() {
            out.push_str(&format!(
                "# HELP {name} {}\n",
                metric.help.replace('\\', "\\\\").replace('\n', "\\n")
            ));
            out.push_str(&format!("# TYPE {name} {}\n", metric.kind.label()));
            if let Some(value) = synthesized.get(name) {
                out.push_str(&format!("{name} {}\n", format_number(*value)));
                continue;
            }
            for (key, series) in &metric.series {
                let suffix = if key.is_empty() {
                    String::new()
                } else {
                    format!("{{{key}}}")
                };
                match (&metric.kind, &series.histogram) {
                    (Kind::Histogram, Some(histogram)) => {
                        let with_le = |le: &str| {
                            if key.is_empty() {
                                format!("{{le=\"{le}\"}}")
                            } else {
                                format!("{{{key},le=\"{le}\"}}")
                            }
                        };
                        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
                            out.push_str(&format!(
                                "{name}_bucket{} {}\n",
                                with_le(&format_number(*bound)),
                                histogram.counts[i]
                            ));
                        }
                        out.push_str(&format!(
                            "{name}_bucket{} {}\n",
                            with_le("+Inf"),
                            histogram.count
                        ));
                        out.push_str(&format!(
                            "{name}_sum{suffix} {}\n",
                            format_number(histogram.sum)
                        ));
                        out.push_str(&format!("{name}_count{suffix} {}\n", histogram.count));
                    }
                    (Kind::Histogram, None) => {}
                    _ => out.push_str(&format!("{name}{suffix} {}\n", format_number(series.value))),
                }
            }
        }
        out
    }
}

/// What `/readyz` reports: the listener is up and the operator drain flag is not set.
pub(crate) struct Readiness {
    listening: AtomicBool,
    drain: drain::Flag,
}

impl Readiness {
    pub(crate) fn new(drain: drain::Flag) -> Self {
        Self {
            listening: AtomicBool::new(false),
            drain,
        }
    }

    pub(crate) fn set_listening(&self, up: bool) {
        self.listening.store(up, Ordering::Relaxed);
    }

    pub(crate) fn ready(&self) -> bool {
        self.listening.load(Ordering::Relaxed) && !self.drain.is_set()
    }
}

/// `127.0.0.1` or `localhost` with an optional port, or `[::1]`: the only `Host` values a
/// loopback scrape may carry (DNS rebinding keeps a hostile `Host` on a loopback socket).
fn loopback_host(host: &str) -> bool {
    let value = host.trim().to_ascii_lowercase();
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') || name.ends_with(']') => (name, Some(port)),
        _ => (value.as_str(), None),
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

/// Bind the loopback metrics listener. The port must not collide with the node's own port.
pub(crate) async fn bind(port: u16) -> Result<TcpListener, std::io::Error> {
    TcpListener::bind(("127.0.0.1", port)).await
}

/// Serve `/metrics`, `/livez` and `/readyz` until the task is dropped.
pub(crate) async fn serve(
    listener: TcpListener,
    registry: Arc<Registry>,
    readiness: Arc<Readiness>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let registry = Arc::clone(&registry);
        let readiness = Arc::clone(&readiness);
        tokio::spawn(async move {
            let _ =
                tokio::time::timeout(REQUEST_TIMEOUT, respond(stream, &registry, &readiness)).await;
        });
    }
}

async fn respond(mut stream: TcpStream, registry: &Registry, readiness: &Readiness) {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > REQUEST_HEAD_MAX {
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let host = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default();
    let common = "cache-control: private, no-store\r\nx-content-type-options: nosniff\r\nconnection: close\r\n";
    let (status, content_type, body) = if !loopback_host(&host) {
        (
            "421 Misdirected Request",
            "text/plain; charset=utf-8",
            "misdirected request\n".to_string(),
        )
    } else if method == "GET" && path == "/metrics" {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            registry.render(),
        )
    } else if method == "GET" && (path == "/livez" || path == "/readyz") {
        let ok = path == "/livez" || readiness.ready();
        (
            if ok {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            "text/plain; charset=utf-8",
            if ok { "ok\n" } else { "not ready\n" }.to_string(),
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\n{common}content-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_labels_are_bounded_like_the_javascript_node() {
        assert_eq!(drop_label("wrong-group-root"), "wrong-group-root");
        assert_eq!(
            drop_label("gate:wrong-group-root"),
            "internal-error",
            "the wire prefix is never a label; callers pass the bare reason"
        );
        assert_eq!(drop_label("artifact-unknown:rln-abc"), "artifact-unknown");
        assert_eq!(drop_label("unsupported-version:9"), "unsupported-version");
        assert_eq!(drop_label("something-with-proof"), "invalid-proof");
        assert_eq!(drop_label("whatever"), "internal-error");
        assert_eq!(
            upstream_drop_label("upstream:ECONNREFUSED"),
            "upstream-refused"
        );
        assert_eq!(
            upstream_drop_label("upstream:ETIMEDOUT"),
            "upstream-timeout"
        );
        assert_eq!(upstream_drop_label("upstream:EWHAT"), "upstream-error");
    }

    #[test]
    fn render_is_sorted_escaped_and_prometheus_shaped() {
        let registry = Registry::new("node", "0.7.5", "abc123");
        registry.counter(
            "shade_tree_gateway_tunnels_total",
            &[("result", "drop"), ("reason", "bad-target")],
        );
        registry.counter(
            "shade_tree_gateway_tunnels_total",
            &[("reason", "bad-target"), ("result", "drop")],
        );
        registry.counter("shade_tree_gateway_tunnels_total", &[("result", "pass")]);
        registry.observe("shade_tree_gateway_verify_seconds", 0.3);
        registry.gauge("shade_tree_heartbeat_elders_total", &[], 2.0);
        registry.counter("not_a_metric", &[]);
        let text = registry.render();
        assert!(text.contains("# HELP shade_tree_gateway_tunnels_total Tunnels by result=pass|drop (+ reason on drop).\n# TYPE shade_tree_gateway_tunnels_total counter\nshade_tree_gateway_tunnels_total{reason=\"bad-target\",result=\"drop\"} 2\nshade_tree_gateway_tunnels_total{result=\"pass\"} 1\n"), "{text}");
        assert!(text.contains("shade_tree_gateway_verify_seconds_bucket{le=\"0.25\"} 0\nshade_tree_gateway_verify_seconds_bucket{le=\"0.5\"} 1\n"));
        assert!(text.contains("shade_tree_gateway_verify_seconds_bucket{le=\"+Inf\"} 1\nshade_tree_gateway_verify_seconds_sum 0.3\nshade_tree_gateway_verify_seconds_count 1\n"));
        assert!(text.contains(
            "shade_tree_build_info{commit=\"abc123\",role=\"node\",version=\"0.7.5\"} 1\n"
        ));
        assert!(text.contains(
            "# TYPE shade_tree_process_uptime_seconds gauge\nshade_tree_process_uptime_seconds "
        ));
        assert!(!text.contains("not_a_metric"));
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert_eq!(
            registry.values("shade_tree_heartbeat_elders_total")[0].value,
            2.0
        );
        assert_eq!(
            registry
                .values("shade_tree_gateway_tunnels_total")
                .iter()
                .find(|s| s.label("result") == Some("drop"))
                .map(|s| s.value),
            Some(2.0)
        );
        assert_eq!(format_number(1_791_191_700.779), "1791191700.779");
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn only_loopback_hosts_are_served() {
        assert!(loopback_host("127.0.0.1:9101"));
        assert!(loopback_host("localhost"));
        assert!(loopback_host("[::1]:9101"));
        assert!(!loopback_host("evil.example:9101"));
        assert!(!loopback_host("127.0.0.1:abc"));
        assert!(!loopback_host(""));
    }
}
