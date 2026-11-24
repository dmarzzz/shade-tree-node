//! The node's metric series (`packages/node/lib/metrics.mjs`) on the shared registry, the
//! bounded refusal labels, and what `/readyz` reports.

use std::sync::atomic::{AtomicBool, Ordering};

use shadenet_service::metrics::{Definition, Kind};

use crate::drain;

/// Every series the node emits beyond the process ones, with the help text the JavaScript
/// node ships.
pub(crate) const DEFINITIONS: &[Definition] = &[
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
}
