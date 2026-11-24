//! The relay telemetry aggregator (`makeRelayAggregator` in
//! `packages/node/lib/relay-telemetry.mjs`): nodes that opt in send an onion-signed report of
//! two unlabeled payload byte counters; the Elder keeps a bounded set of raw interval deltas in
//! memory and a private replay checkpoint on disk, and publishes only a signed, delayed,
//! rounded cohort aggregate. A raw report is never served by any route.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::Value;
use shadenet_proto::{ed25519_verify, onion_to_pubkey};
use shadenet_service::clock;
use shadenet_service::files::atomic_write;

use crate::registry::Registry;
use crate::signer::Signer;

pub(crate) const REPORT_SCHEMA: &str = "shade-tree-relay-report-v1";
const AGGREGATE_SCHEMA: &str = "shade-tree-relay-aggregate-v1";
const STATE_SCHEMA: &str = "shade-tree-relay-elder-state-v1";
const ROUNDING_BUCKET_BYTES: u64 = 1024 * 1024 * 1024;
/// 16 Gibit/s of combined payload: more than that in an interval is not a real node.
const MAX_BYTES_PER_SECOND: u128 = 2 * 1024 * 1024 * 1024;
const MAX_INTERVAL_MS: u64 = 24 * 60 * 60_000;
const FUTURE_SKEW_MS: u64 = 5 * 60_000;
const RETENTION_MS: u64 = 36 * 60 * 60_000;
const MAX_CONTRIBUTIONS_PER_ONION: usize = 2_000;
const MAX_CONTRIBUTIONS: usize = 100_000;
const MAX_NODES: usize = 100_000;
const HOUR_MS: u64 = 60 * 60_000;
const PUBLICATION_STEP_MS: u64 = 15 * 60_000;
const WINDOWS: [(&str, u64); 2] = [("sixHour", 6), ("twentyFourHour", 24)];

struct NodeState {
    sequence: u64,
    boot_id: String,
    end_ms: u64,
    agent_to_destination: u64,
    destination_to_agent: u64,
}

struct Contribution {
    onion: String,
    start_ms: u64,
    end_ms: u64,
    bytes: u128,
}

struct Inner {
    nodes: HashMap<String, NodeState>,
    contributions: Vec<Contribution>,
}

pub(crate) struct Aggregator {
    signer: Arc<Signer>,
    registry: Arc<Registry>,
    state: Option<PathBuf>,
    minimum_cohort: u64,
    delay_hours: u64,
    inner: Mutex<Inner>,
}

#[derive(Serialize)]
struct Rounding {
    method: &'static str,
    #[serde(rename = "bucketBytes")]
    bucket_bytes: String,
}

#[derive(Serialize)]
struct Window {
    status: &'static str,
    #[serde(rename = "windowHours")]
    window_hours: u64,
    #[serde(rename = "windowStart")]
    window_start: String,
    #[serde(rename = "windowEnd")]
    window_end: String,
    #[serde(rename = "reportingNodes")]
    reporting_nodes: usize,
    #[serde(rename = "roundedBytes", skip_serializing_if = "Option::is_none")]
    rounded_bytes: Option<String>,
    #[serde(rename = "suppressionReason", skip_serializing_if = "Option::is_none")]
    suppression_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct Windows {
    #[serde(rename = "sixHour")]
    six_hour: Window,
    #[serde(rename = "twentyFourHour")]
    twenty_four_hour: Window,
}

/// The aggregate in the field order `relayAggregateSigningPayload` serializes; the served
/// document is this payload plus `signature`.
#[derive(Serialize)]
struct Payload<'a> {
    schema: &'static str,
    #[serde(rename = "generatedAt")]
    generated_at: String,
    definition: &'static str,
    unit: &'static str,
    #[serde(rename = "delayHours")]
    delay_hours: u64,
    #[serde(rename = "minimumCohort")]
    minimum_cohort: u64,
    rounding: Rounding,
    windows: Windows,
    signer: &'a str,
}

#[derive(Serialize)]
struct StateNode<'a> {
    onion: &'a str,
    sequence: u64,
    #[serde(rename = "bootId")]
    boot_id: &'a str,
    end: String,
    counters: Counters,
}

#[derive(Serialize)]
struct Counters {
    #[serde(rename = "agentToDestinationBytes")]
    agent_to_destination: String,
    #[serde(rename = "destinationToAgentBytes")]
    destination_to_agent: String,
}

#[derive(Serialize)]
struct StateFile<'a> {
    schema: &'static str,
    nodes: Vec<StateNode<'a>>,
}

/// A validated report, every field in the shape the signature covers.
struct Report {
    onion: String,
    boot_id: String,
    sequence: u64,
    start_ms: u64,
    end_ms: u64,
    agent_to_destination: u64,
    destination_to_agent: u64,
    reset: bool,
    signature: String,
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k)))
}

fn is_boot_id(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// A canonical decimal `u64` in a string: no sign, no leading zero, at most twenty digits.
fn u64_string(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let canonical = text == "0" || (!text.starts_with('0') && !text.is_empty() && text.len() <= 20);
    (canonical && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

fn iso_ms(value: &Value) -> Option<u64> {
    value.as_str().and_then(clock::parse_iso)
}

impl Report {
    /// `validRelayReport`: exact keys, canonical counters, a well-formed interval and reset.
    fn parse(value: &Value) -> Option<Self> {
        if !exact_keys(
            value,
            &[
                "schema",
                "onion",
                "bootId",
                "sequence",
                "intervalStart",
                "intervalEnd",
                "counters",
                "reset",
                "signature",
            ],
        ) {
            return None;
        }
        if value["schema"].as_str() != Some(REPORT_SCHEMA) || !is_boot_id(&value["bootId"]) {
            return None;
        }
        let onion = value["onion"].as_str()?.to_string();
        let sequence = value["sequence"].as_u64().filter(|s| *s >= 1)?;
        let start_ms = iso_ms(&value["intervalStart"])?;
        let end_ms = iso_ms(&value["intervalEnd"])?;
        if start_ms >= end_ms {
            return None;
        }
        if !exact_keys(
            &value["counters"],
            &["agentToDestinationBytes", "destinationToAgentBytes"],
        ) {
            return None;
        }
        let agent_to_destination = u64_string(&value["counters"]["agentToDestinationBytes"])?;
        let destination_to_agent = u64_string(&value["counters"]["destinationToAgentBytes"])?;
        if !exact_keys(&value["reset"], &["occurred", "reason"]) {
            return None;
        }
        let reset = value["reset"]["occurred"].as_bool()?;
        let reason_ok = if reset {
            value["reset"]["reason"].as_str() == Some("process-start")
        } else {
            value["reset"]["reason"].is_null()
        };
        if !reason_ok {
            return None;
        }
        let signature = value["signature"].as_str()?.to_string();
        if signature.len() != 128 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self {
            onion,
            boot_id: value["bootId"].as_str()?.to_string(),
            sequence,
            start_ms,
            end_ms,
            agent_to_destination,
            destination_to_agent,
            reset,
            signature,
        })
    }

    /// `relayReportSigningPayload` as `JSON.stringify` writes it.
    fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"schema\":\"{REPORT_SCHEMA}\",\"onion\":{},\"bootId\":\"{}\",\"sequence\":{},\"intervalStart\":\"{}\",\"intervalEnd\":\"{}\",\"counters\":{{\"agentToDestinationBytes\":\"{}\",\"destinationToAgentBytes\":\"{}\"}},\"reset\":{{\"occurred\":{},\"reason\":{}}}}}",
            serde_json::to_string(&self.onion).unwrap_or_default(),
            self.boot_id,
            self.sequence,
            clock::iso(self.start_ms),
            clock::iso(self.end_ms),
            self.agent_to_destination,
            self.destination_to_agent,
            self.reset,
            if self.reset { "\"process-start\"" } else { "null" }
        )
        .into_bytes()
    }

    /// Onion control over the signing bytes.
    fn verify(&self) -> bool {
        let Ok(pubkey) = onion_to_pubkey(&self.onion) else {
            return false;
        };
        let Some(sig) = hex::decode(&self.signature)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
        else {
            return false;
        };
        ed25519_verify(&self.signing_bytes(), &sig, &pubkey)
    }
}

fn rounded_up(value: u128, bucket: u128) -> u128 {
    if value == 0 {
        0
    } else {
        value.div_ceil(bucket) * bucket
    }
}

impl Aggregator {
    /// Load the private checkpoint, if any; a corrupt checkpoint refuses to start.
    pub(crate) fn new(
        signer: Arc<Signer>,
        registry: Arc<Registry>,
        state: Option<PathBuf>,
        minimum_cohort: u64,
        delay_hours: u64,
    ) -> Result<Self, String> {
        let nodes = match &state {
            Some(path) if path.exists() => load_checkpoint(path)?,
            _ => HashMap::new(),
        };
        Ok(Self {
            signer,
            registry,
            state,
            minimum_cohort,
            delay_hours,
            inner: Mutex::new(Inner {
                nodes,
                contributions: Vec::new(),
            }),
        })
    }

    fn checkpoint(&self, inner: &Inner) {
        let Some(path) = &self.state else {
            return;
        };
        let file = StateFile {
            schema: STATE_SCHEMA,
            nodes: inner
                .nodes
                .iter()
                .map(|(onion, n)| StateNode {
                    onion,
                    sequence: n.sequence,
                    boot_id: &n.boot_id,
                    end: clock::iso(n.end_ms),
                    counters: Counters {
                        agent_to_destination: n.agent_to_destination.to_string(),
                        destination_to_agent: n.destination_to_agent.to_string(),
                    },
                })
                .collect(),
        };
        let result = serde_json::to_vec(&file)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                atomic_write(path, &[bytes, b"\n".to_vec()].concat()).map_err(|e| e.to_string())
            });
        if let Err(e) = result {
            tracing::error!("relay checkpoint not written: {e}");
        }
    }

    fn prune(&self, inner: &mut Inner, now_ms: u64) {
        let oldest = now_ms.saturating_sub(RETENTION_MS);
        inner.contributions.retain(|c| c.end_ms >= oldest);
        let before = inner.nodes.len();
        inner.nodes.retain(|_, n| n.end_ms >= oldest);
        if inner.nodes.len() != before {
            self.checkpoint(inner);
        }
    }

    /// `POST /telemetry/relay`: the reason it was refused, or nothing.
    pub(crate) fn accept(&self, value: &Value, now_ms: u64) -> Result<(), &'static str> {
        let Some(report) = Report::parse(value) else {
            return Err("bad-report");
        };
        if !report.verify() {
            return Err("bad-signature");
        }
        if !self.registry.has(&report.onion) {
            return Err("not-announced");
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.prune(&mut inner, now_ms);
        let duration = report.end_ms - report.start_ms;
        if report.end_ms > now_ms + FUTURE_SKEW_MS {
            return Err("future-interval");
        }
        if report.end_ms < now_ms.saturating_sub(RETENTION_MS) {
            return Err("stale-interval");
        }
        if duration > MAX_INTERVAL_MS {
            return Err("interval-too-long");
        }
        let previous = inner.nodes.get(&report.onion);
        if previous.is_some_and(|p| report.sequence <= p.sequence) {
            return Err("sequence-replay");
        }
        if previous.is_some_and(|p| report.start_ms < p.end_ms) {
            return Err("interval-overlap");
        }
        let (delta_a, delta_b) = match previous {
            None => {
                if !report.reset {
                    return Err("missing-reset");
                }
                (report.agent_to_destination, report.destination_to_agent)
            }
            Some(p) if p.boot_id == report.boot_id => {
                if report.reset {
                    return Err("unexpected-reset");
                }
                if report.agent_to_destination < p.agent_to_destination
                    || report.destination_to_agent < p.destination_to_agent
                {
                    return Err("counter-rollback");
                }
                (
                    report.agent_to_destination - p.agent_to_destination,
                    report.destination_to_agent - p.destination_to_agent,
                )
            }
            Some(_) => {
                if !report.reset {
                    return Err("missing-reset");
                }
                (report.agent_to_destination, report.destination_to_agent)
            }
        };
        let allowed = u128::from(duration.div_ceil(1000)) * MAX_BYTES_PER_SECOND;
        let bytes = u128::from(delta_a) + u128::from(delta_b);
        if bytes > allowed {
            return Err("implausible-delta");
        }
        inner.nodes.insert(
            report.onion.clone(),
            NodeState {
                sequence: report.sequence,
                boot_id: report.boot_id,
                end_ms: report.end_ms,
                agent_to_destination: report.agent_to_destination,
                destination_to_agent: report.destination_to_agent,
            },
        );
        inner.contributions.push(Contribution {
            onion: report.onion.clone(),
            start_ms: report.start_ms,
            end_ms: report.end_ms,
            bytes,
        });
        // fail-open memory bounds: the onion's oldest extras go first, then the oldest of all
        let per_onion = inner
            .contributions
            .iter()
            .filter(|c| c.onion == report.onion)
            .count();
        if per_onion > MAX_CONTRIBUTIONS_PER_ONION {
            let mut to_drop = per_onion - MAX_CONTRIBUTIONS_PER_ONION;
            inner.contributions.retain(|c| {
                if to_drop > 0 && c.onion == report.onion {
                    to_drop -= 1;
                    false
                } else {
                    true
                }
            });
        }
        if inner.contributions.len() > MAX_CONTRIBUTIONS {
            let excess = inner.contributions.len() - MAX_CONTRIBUTIONS;
            inner.contributions.drain(..excess);
        }
        self.checkpoint(&inner);
        Ok(())
    }

    fn window(&self, inner: &Inner, window_end: u64, hours: u64) -> Window {
        let window_start = window_end - hours * HOUR_MS;
        let eligible: Vec<&Contribution> = inner
            .contributions
            .iter()
            .filter(|c| c.start_ms >= window_start && c.end_ms <= window_end)
            .collect();
        let mut reporters: Vec<&str> = eligible.iter().map(|c| c.onion.as_str()).collect();
        reporters.sort_unstable();
        reporters.dedup();
        let total: u128 = eligible.iter().map(|c| c.bytes).sum();
        let suppression = if reporters.is_empty() {
            Some("unavailable")
        } else if (reporters.len() as u64) < self.minimum_cohort {
            Some("minimum-cohort")
        } else if total == 0 {
            Some("unavailable")
        } else {
            None
        };
        Window {
            status: if suppression.is_some() {
                "suppressed"
            } else {
                "available"
            },
            window_hours: hours,
            window_start: clock::iso(window_start),
            window_end: clock::iso(window_end),
            reporting_nodes: reporters.len(),
            rounded_bytes: suppression
                .is_none()
                .then(|| rounded_up(total, u128::from(ROUNDING_BUCKET_BYTES)).to_string()),
            suppression_reason: suppression,
        }
    }

    /// `GET /telemetry/aggregate`: the signed, delayed, rounded cohort aggregate. The
    /// publication time steps every fifteen minutes so repeated reads share one body.
    pub(crate) fn snapshot(&self, now_ms: u64) -> Vec<u8> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.prune(&mut inner, now_ms);
        let generated_at = now_ms / PUBLICATION_STEP_MS * PUBLICATION_STEP_MS;
        let window_end = now_ms.saturating_sub(self.delay_hours * HOUR_MS) / HOUR_MS * HOUR_MS;
        let payload = Payload {
            schema: AGGREGATE_SCHEMA,
            generated_at: clock::iso(generated_at),
            definition: "payload-bytes-relayed",
            unit: "bytes",
            delay_hours: self.delay_hours,
            minimum_cohort: self.minimum_cohort,
            rounding: Rounding {
                method: "ceiling",
                bucket_bytes: ROUNDING_BUCKET_BYTES.to_string(),
            },
            windows: Windows {
                six_hour: self.window(&inner, window_end, WINDOWS[0].1),
                twenty_four_hour: self.window(&inner, window_end, WINDOWS[1].1),
            },
            signer: self.signer.public_hex(),
        };
        let text = serde_json::to_string(&payload).unwrap_or_default();
        let signature = self.signer.sign(text.as_bytes());
        format!(
            "{},\"signature\":\"{signature}\"}}",
            &text[..text.len() - 1]
        )
        .into_bytes()
    }
}

/// The checkpoint, strictly: anything off refuses to start, as the JavaScript Elder does.
fn load_checkpoint(path: &Path) -> Result<HashMap<String, NodeState>, String> {
    let invalid = || format!("invalid Elder relay checkpoint at {}", path.display());
    let stored: Value = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or_else(invalid)?;
    if !exact_keys(&stored, &["schema", "nodes"]) || stored["schema"].as_str() != Some(STATE_SCHEMA)
    {
        return Err(invalid());
    }
    let entries = stored["nodes"].as_array().ok_or_else(invalid)?;
    if entries.len() > MAX_NODES {
        return Err(invalid());
    }
    let mut nodes = HashMap::new();
    for entry in entries {
        let valid = exact_keys(entry, &["onion", "sequence", "bootId", "end", "counters"])
            && is_boot_id(&entry["bootId"])
            && exact_keys(
                &entry["counters"],
                &["agentToDestinationBytes", "destinationToAgentBytes"],
            );
        if !valid {
            return Err(invalid());
        }
        let onion = entry["onion"].as_str().ok_or_else(invalid)?.to_string();
        let state = NodeState {
            sequence: entry["sequence"]
                .as_u64()
                .filter(|s| *s >= 1)
                .ok_or_else(invalid)?,
            boot_id: entry["bootId"].as_str().unwrap_or_default().to_string(),
            end_ms: iso_ms(&entry["end"]).ok_or_else(invalid)?,
            agent_to_destination: u64_string(&entry["counters"]["agentToDestinationBytes"])
                .ok_or_else(invalid)?,
            destination_to_agent: u64_string(&entry["counters"]["destinationToAgentBytes"])
                .ok_or_else(invalid)?,
        };
        if nodes.insert(onion, state).is_some() {
            return Err(invalid());
        }
    }
    Ok(nodes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::registry::tests::{make, mock, raw, Node};
    use crate::registry::Outcome;
    use serde_json::json;
    use shadenet_proto::ed25519_sign;

    /// `buildRelayReport` for a node: the signing payload the node sends, signed by its seed.
    pub(crate) fn report(
        node: &Node,
        boot_id: &str,
        sequence: u64,
        interval: (&str, &str),
        counters: (u64, u64),
        reset: bool,
    ) -> Value {
        let (start, end) = interval;
        let (a2d, d2a) = counters;
        let payload = format!(
            "{{\"schema\":\"{REPORT_SCHEMA}\",\"onion\":\"{}\",\"bootId\":\"{boot_id}\",\"sequence\":{sequence},\"intervalStart\":\"{start}\",\"intervalEnd\":\"{end}\",\"counters\":{{\"agentToDestinationBytes\":\"{a2d}\",\"destinationToAgentBytes\":\"{d2a}\"}},\"reset\":{{\"occurred\":{reset},\"reason\":{}}}}}",
            node.onion,
            if reset { "\"process-start\"" } else { "null" }
        );
        let signature = hex::encode(ed25519_sign(payload.as_bytes(), &node.seed));
        serde_json::from_str(&format!(
            "{},\"signature\":\"{signature}\"}}",
            &payload[..payload.len() - 1]
        ))
        .unwrap()
    }

    fn ms(iso: &str) -> u64 {
        clock::parse_iso(iso).unwrap()
    }

    async fn aggregator(
        state: Option<PathBuf>,
        nodes: &[&Node],
        now: u64,
    ) -> (Aggregator, Arc<Signer>) {
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now));
        for node in nodes {
            assert!(matches!(
                registry
                    .announce(&raw(&node.announce(100, now, "r", None, None)), now)
                    .await,
                Outcome::Accepted { .. }
            ));
        }
        let dir = std::env::temp_dir().join(format!(
            "shadenet-elder-relay-{}-{}",
            std::process::id(),
            clock::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let signer = Arc::new(Signer::load_or_mint(&dir.join("signer.key")).unwrap());
        (
            Aggregator::new(Arc::clone(&signer), registry, state, 5, 6).unwrap(),
            signer,
        )
    }

    /// Verify a served aggregate: the payload is the document without its signature.
    pub(crate) fn verify_aggregate(body: &[u8], signer_hex: &str) -> bool {
        let text = String::from_utf8_lossy(body);
        let Some(at) = text.rfind(",\"signature\":\"") else {
            return false;
        };
        let payload = format!("{}}}", &text[..at]);
        let doc: Value = serde_json::from_str(&text).unwrap();
        if doc["signer"].as_str() != Some(signer_hex) {
            return false;
        }
        let sig: [u8; 64] = hex::decode(doc["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let pubkey: [u8; 32] = hex::decode(signer_hex).unwrap().try_into().unwrap();
        ed25519_verify(payload.as_bytes(), &sig, &pubkey)
    }

    #[tokio::test]
    async fn reports_are_checked_the_way_the_javascript_aggregator_checks_them() {
        let now = ms("2026-08-25T12:30:00.000Z");
        let node = Node::new(1);
        let stranger = Node::new(2);
        let (agg, _) = aggregator(None, &[&node], now / 1000).await;
        let boot = "ab".repeat(16);
        let first = report(
            &node,
            &boot,
            1,
            ("2026-08-25T05:15:00.000Z", "2026-08-25T05:30:00.000Z"),
            (1000, 2000),
            true,
        );
        assert_eq!(agg.accept(&first, now), Ok(()));
        assert_eq!(agg.accept(&first, now), Err("sequence-replay"));
        assert_eq!(
            agg.accept(&json!({"schema": REPORT_SCHEMA}), now),
            Err("bad-report")
        );
        let mut tampered = first.clone();
        tampered["counters"]["agentToDestinationBytes"] = Value::String("1001".into());
        assert_eq!(agg.accept(&tampered, now), Err("bad-signature"));
        let unknown = report(
            &stranger,
            &"cd".repeat(16),
            1,
            ("2026-08-25T05:15:00.000Z", "2026-08-25T05:30:00.000Z"),
            (1, 1),
            true,
        );
        assert_eq!(agg.accept(&unknown, now), Err("not-announced"));
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T12:40:00.000Z"),
                    (1000, 2000),
                    false
                ),
                now
            ),
            Err("future-interval")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-23T05:30:00.000Z", "2026-08-24T00:00:00.000Z"),
                    (1000, 2000),
                    false
                ),
                now
            ),
            Err("stale-interval")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-24T05:00:00.000Z", "2026-08-25T06:00:00.000Z"),
                    (1000, 2000),
                    false
                ),
                now
            ),
            Err("interval-too-long")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:20:00.000Z", "2026-08-25T05:45:00.000Z"),
                    (1000, 2000),
                    false
                ),
                now
            ),
            Err("interval-overlap")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T05:45:00.000Z"),
                    (1000, 2000),
                    true
                ),
                now
            ),
            Err("unexpected-reset")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T05:45:00.000Z"),
                    (999, 2000),
                    false
                ),
                now
            ),
            Err("counter-rollback")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T05:30:01.000Z"),
                    (1000 + 3 * 1024 * 1024 * 1024, 2000),
                    false
                ),
                now
            ),
            Err("implausible-delta")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &"ef".repeat(16),
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T05:45:00.000Z"),
                    (5, 5),
                    false
                ),
                now
            ),
            Err("missing-reset")
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &boot,
                    2,
                    ("2026-08-25T05:30:00.000Z", "2026-08-25T05:45:00.000Z"),
                    (1500, 2500),
                    false
                ),
                now
            ),
            Ok(())
        );
        assert_eq!(
            agg.accept(
                &report(
                    &node,
                    &"ef".repeat(16),
                    3,
                    ("2026-08-25T05:45:00.000Z", "2026-08-25T06:00:00.000Z"),
                    (5, 5),
                    true
                ),
                now
            ),
            Ok(()),
            "a new boot starts over"
        );
    }

    #[tokio::test]
    async fn the_aggregate_is_signed_delayed_rounded_and_suppressed_under_the_cohort() {
        let now = ms("2026-08-25T12:30:00.000Z");
        let nodes: Vec<Node> = (1..=6).map(Node::new).collect();
        let refs: Vec<&Node> = nodes.iter().collect();
        let dir =
            std::env::temp_dir().join(format!("shadenet-elder-relay-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("relay-state.json");
        let (agg, signer) = aggregator(Some(state.clone()), &refs, now / 1000).await;
        let suppressed: Value = serde_json::from_slice(&agg.snapshot(now)).unwrap();
        assert!(verify_aggregate(&agg.snapshot(now), signer.public_hex()));
        assert_eq!(suppressed["generatedAt"], "2026-08-25T12:30:00.000Z");
        assert_eq!(suppressed["windows"]["sixHour"]["status"], "suppressed");
        assert_eq!(
            suppressed["windows"]["sixHour"]["suppressionReason"],
            "unavailable"
        );
        assert_eq!(
            suppressed["windows"]["twentyFourHour"]["windowEnd"],
            "2026-08-25T06:00:00.000Z"
        );
        assert!(suppressed["windows"]["twentyFourHour"]
            .get("roundedBytes")
            .is_none());
        // four reporters inside the window: still under the cohort floor
        for (i, node) in nodes.iter().take(4).enumerate() {
            assert_eq!(
                agg.accept(
                    &report(
                        node,
                        &format!("{:02x}", i).repeat(16),
                        1,
                        ("2026-08-25T01:00:00.000Z", "2026-08-25T05:00:00.000Z"),
                        (600_000_000, 600_000_000),
                        true
                    ),
                    now
                ),
                Ok(())
            );
        }
        let few: Value = serde_json::from_slice(&agg.snapshot(now)).unwrap();
        assert_eq!(
            few["windows"]["sixHour"]["suppressionReason"],
            "minimum-cohort"
        );
        assert_eq!(few["windows"]["sixHour"]["reportingNodes"], 4);
        for (i, node) in nodes.iter().enumerate().skip(4) {
            assert_eq!(
                agg.accept(
                    &report(
                        node,
                        &format!("{:02x}", i).repeat(16),
                        1,
                        ("2026-08-25T01:00:00.000Z", "2026-08-25T05:00:00.000Z"),
                        (600_000_000, 600_000_000),
                        true
                    ),
                    now
                ),
                Ok(())
            );
        }
        let body = agg.snapshot(now);
        assert!(verify_aggregate(&body, signer.public_hex()));
        let available: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(available["windows"]["sixHour"]["status"], "available");
        assert_eq!(available["windows"]["sixHour"]["reportingNodes"], 6);
        // 6 * 1.2e9 bytes = 7.2e9, rounded up to a 1 GiB bucket
        assert_eq!(
            available["windows"]["sixHour"]["roundedBytes"],
            (7 * 1024_u64 * 1024 * 1024).to_string()
        );
        assert!(available["windows"]["sixHour"]
            .get("suppressionReason")
            .is_none());
        assert_eq!(available["rounding"]["bucketBytes"], "1073741824");
        assert_eq!(available["delayHours"], 6);

        // the checkpoint carries the replay state across a restart, raw contributions do not
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now / 1000));
        let restarted = Aggregator::new(
            Arc::clone(&signer),
            Arc::clone(&registry),
            Some(state.clone()),
            5,
            6,
        )
        .unwrap();
        let fresh: Value = serde_json::from_slice(&restarted.snapshot(now)).unwrap();
        assert_eq!(
            fresh["windows"]["sixHour"]["suppressionReason"], "unavailable",
            "raw contributions do not survive a restart"
        );
        assert!(matches!(
            registry
                .announce(
                    &raw(&nodes[0].announce(100, now / 1000, "z", None, None)),
                    now / 1000
                )
                .await,
            Outcome::Accepted { .. }
        ));
        assert_eq!(
            restarted.accept(
                &report(
                    &nodes[0],
                    &"00".repeat(16),
                    1,
                    ("2026-08-25T05:00:00.000Z", "2026-08-25T06:00:00.000Z"),
                    (700_000_000, 700_000_000),
                    false
                ),
                now
            ),
            Err("sequence-replay")
        );
        std::fs::write(&state, "{\"schema\":\"wrong\"}").unwrap();
        assert!(
            Aggregator::new(signer, registry, Some(state), 5, 6).is_err(),
            "a corrupt checkpoint refuses to start"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
