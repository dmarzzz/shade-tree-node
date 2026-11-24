//! The Elder's metric series (`packages/node/bootnode/server.mjs`) on the shared registry, and
//! the bounded reason labels.

use shadenet_service::metrics::{Definition, Kind};

/// Every series the Elder emits beyond the process ones, with the JavaScript help text.
pub(crate) const DEFINITIONS: &[Definition] = &[
    (
        "shade_tree_bootnode_announces_total",
        Kind::Counter,
        "Announces received, labeled result=accepted|rejected (+ reason on reject).",
    ),
    (
        "shade_tree_bootnode_directory_fetches_total",
        Kind::Counter,
        "Signed directory (Canopy) requests served by the Elder Tree.",
    ),
    (
        "shade_tree_bootnode_directory_delta_fetches_total",
        Kind::Counter,
        "GET /directory/delta requests served, labeled result=delta|full.",
    ),
    (
        "shade_tree_bootnode_relay_reports_total",
        Kind::Counter,
        "Private signed relay telemetry reports received, labeled only by bounded result/reason.",
    ),
    (
        "shade_tree_bootnode_relay_aggregates_total",
        Kind::Counter,
        "Delayed cohort aggregate relay snapshots served.",
    ),
    (
        "shade_tree_bootnode_live_gateways",
        Kind::Gauge,
        "Gateways currently live (announced within TTL).",
    ),
    (
        "shade_tree_bootnode_connections",
        Kind::Gauge,
        "Open Elder Tree transport connections.",
    ),
];

const ANNOUNCE_REASONS: &[&str] = &[
    "rate-limited",
    "global-rate-limited",
    "registry-full",
    "no-announce",
    "bad-version",
    "no-onion",
    "bad-onion",
    "stale-ts",
    "replayed-nonce",
    "bad-onion-sig",
    "bad-caps-sig",
    "bad-operator-sig",
    "stake-check-failed",
    "not-staked",
];

const RELAY_REASONS: &[&str] = &[
    "bad-report",
    "bad-signature",
    "not-announced",
    "future-interval",
    "stale-interval",
    "interval-too-long",
    "sequence-replay",
    "interval-overlap",
    "missing-reset",
    "unexpected-reset",
    "counter-rollback",
    "implausible-delta",
];

fn bounded(reason: &str, known: &[&'static str]) -> &'static str {
    let raw = reason.to_ascii_lowercase();
    let base = raw.split(':').next().unwrap_or("other");
    known
        .iter()
        .copied()
        .find(|label| *label == base)
        .unwrap_or("other")
}

/// The `reason` label of a rejected announce.
pub(crate) fn announce_reason_label(reason: &str) -> &'static str {
    bounded(reason, ANNOUNCE_REASONS)
}

/// The `reason` label of a rejected relay report.
pub(crate) fn relay_reason_label(reason: &str) -> &'static str {
    bounded(reason, RELAY_REASONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_labels_are_bounded() {
        assert_eq!(announce_reason_label("stale-ts:12345"), "stale-ts");
        assert_eq!(announce_reason_label("Bad-Onion:checksum"), "bad-onion");
        assert_eq!(announce_reason_label("something-new"), "other");
        assert_eq!(relay_reason_label("sequence-replay"), "sequence-replay");
        assert_eq!(relay_reason_label(""), "other");
    }
}
