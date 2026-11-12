//! Private relay-byte telemetry (`packages/node/lib/relay-telemetry.mjs`): two unlabeled
//! payload byte counters kept in a local file, and, when the operator opts in, an onion-signed
//! report of them sent to the Elder Tree after an accepted announce. The public side only
//! ever sees delayed, rounded cohort aggregates.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use shadenet_proto::ed25519_sign;

use crate::clock;
use crate::metrics::Registry;
use crate::receipt::Signer;
use crate::torhttp::{self, Request, Socks};

pub(crate) const COUNTER_SCHEMA: &str = "shade-tree-relay-counter-v1";
pub(crate) const REPORT_STATE_SCHEMA: &str = "shade-tree-relay-report-state-v1";
pub(crate) const REPORT_SCHEMA: &str = "shade-tree-relay-report-v1";
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const ELDER_PORT: u16 = 80;

/// Where the counter and the report state live.
#[derive(Clone)]
pub(crate) struct Paths {
    pub(crate) counter: PathBuf,
    pub(crate) report: PathBuf,
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    AgentToDestination,
    DestinationToAgent,
}

/// The node-local counters. A fresh random boot id on every start makes resets explicit;
/// the file keeps the counters as decimal strings so they never pass through a float.
pub(crate) struct Counter {
    boot_id: String,
    started_at: String,
    agent_to_destination: AtomicU64,
    destination_to_agent: AtomicU64,
    dirty: AtomicBool,
    path: PathBuf,
}

impl Counter {
    pub(crate) fn new(path: PathBuf) -> Self {
        let mut boot = [0_u8; 16];
        let _ = getrandom::fill(&mut boot);
        Self {
            boot_id: hex::encode(boot),
            started_at: clock::iso(clock::now_ms()),
            agent_to_destination: AtomicU64::new(0),
            destination_to_agent: AtomicU64::new(0),
            dirty: AtomicBool::new(true),
            path,
        }
    }

    fn add(&self, direction: Direction, bytes: u64) {
        if bytes == 0 {
            return;
        }
        match direction {
            Direction::AgentToDestination => self
                .agent_to_destination
                .fetch_add(bytes, Ordering::Relaxed),
            Direction::DestinationToAgent => self
                .destination_to_agent
                .fetch_add(bytes, Ordering::Relaxed),
        };
        self.dirty.store(true, Ordering::Relaxed);
    }

    fn snapshot(&self) -> String {
        format!(
            "{{\"schema\":\"{COUNTER_SCHEMA}\",\"bootId\":\"{}\",\"startedAt\":\"{}\",\"updatedAt\":\"{}\",\"counters\":{{\"agentToDestinationBytes\":\"{}\",\"destinationToAgentBytes\":\"{}\"}}}}\n",
            self.boot_id,
            self.started_at,
            clock::iso(clock::now_ms()),
            self.agent_to_destination.load(Ordering::Relaxed),
            self.destination_to_agent.load(Ordering::Relaxed)
        )
    }

    /// Write the file when something changed since the last flush.
    pub(crate) fn flush(&self) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        if let Err(e) = atomic_write(&self.path, self.snapshot().as_bytes()) {
            tracing::warn!("relay telemetry counter not written: {e}");
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub(crate) async fn flush_periodically(self: Arc<Self>) {
        loop {
            self.flush();
            tokio::time::sleep(FLUSH_INTERVAL).await;
        }
    }
}

/// Where relayed payload bytes are counted: the two Prometheus counters, and the telemetry
/// counter when the operator turned it on.
pub(crate) struct Traffic {
    registry: Arc<Registry>,
    counter: Option<Arc<Counter>>,
}

impl Traffic {
    pub(crate) fn new(registry: Arc<Registry>, counter: Option<Arc<Counter>>) -> Self {
        Self { registry, counter }
    }

    pub(crate) fn add(&self, direction: Direction, bytes: usize) {
        let bytes = bytes as u64;
        let name = match direction {
            Direction::AgentToDestination => {
                "shade_tree_gateway_agent_to_destination_payload_bytes_total"
            }
            Direction::DestinationToAgent => {
                "shade_tree_gateway_destination_to_agent_payload_bytes_total"
            }
        };
        self.registry.counter_add(name, &[], bytes);
        if let Some(counter) = &self.counter {
            counter.add(direction, bytes);
        }
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
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
    options
        .open(&temp)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| format!("write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

fn u64_string(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let canonical = text == "0" || (!text.starts_with('0') && text.len() <= 20 && !text.is_empty());
    if !canonical || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn is_boot_id(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|o| {
        let mut have: Vec<&str> = o.keys().map(String::as_str).collect();
        have.sort_unstable();
        let mut want = keys.to_vec();
        want.sort_unstable();
        have == want
    })
}

fn counters_ok(value: &Value) -> bool {
    exact_keys(
        value,
        &["agentToDestinationBytes", "destinationToAgentBytes"],
    ) && u64_string(&value["agentToDestinationBytes"]).is_some()
        && u64_string(&value["destinationToAgentBytes"]).is_some()
}

pub(crate) fn valid_counter_state(value: &Value) -> bool {
    let started = value
        .get("startedAt")
        .and_then(Value::as_str)
        .and_then(clock::parse_iso);
    let updated = value
        .get("updatedAt")
        .and_then(Value::as_str)
        .and_then(clock::parse_iso);
    exact_keys(
        value,
        &["schema", "bootId", "startedAt", "updatedAt", "counters"],
    ) && value["schema"] == COUNTER_SCHEMA
        && is_boot_id(&value["bootId"])
        && matches!((started, updated), (Some(s), Some(u)) if u >= s)
        && counters_ok(&value["counters"])
}

fn valid_report_state(value: &Value) -> bool {
    exact_keys(
        value,
        &["schema", "sequence", "bootId", "intervalEnd", "counters"],
    ) && value["schema"] == REPORT_STATE_SCHEMA
        && value["sequence"].as_u64().is_some()
        && is_boot_id(&value["bootId"])
        && value["intervalEnd"]
            .as_str()
            .and_then(clock::parse_iso)
            .is_some()
        && counters_ok(&value["counters"])
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// The signed report and the state to keep once the Elder accepted it (`buildRelayReport`).
pub(crate) fn build_report(
    counter: &Value,
    previous: Option<&Value>,
    onion: &str,
    seed: &[u8; 32],
    now_ms: u64,
) -> Result<(String, String), String> {
    if !valid_counter_state(counter) {
        return Err("valid relay counter state required".into());
    }
    if previous.is_some_and(|p| !valid_report_state(p)) {
        return Err("invalid prior relay report state".into());
    }
    let boot_id = counter["bootId"].as_str().unwrap_or_default();
    let same_boot = previous.is_some_and(|p| p["bootId"] == boot_id);
    let start = if same_boot {
        previous
            .and_then(|p| p["intervalEnd"].as_str())
            .unwrap_or_default()
    } else {
        counter["startedAt"].as_str().unwrap_or_default()
    };
    let start_ms = clock::parse_iso(start).ok_or("relay report interval is empty")?;
    if start_ms >= now_ms {
        return Err("relay report interval is empty".into());
    }
    let a2d = u64_string(&counter["counters"]["agentToDestinationBytes"]).unwrap_or(0);
    let d2a = u64_string(&counter["counters"]["destinationToAgentBytes"]).unwrap_or(0);
    if same_boot {
        let prior_a = previous
            .and_then(|p| u64_string(&p["counters"]["agentToDestinationBytes"]))
            .unwrap_or(0);
        let prior_b = previous
            .and_then(|p| u64_string(&p["counters"]["destinationToAgentBytes"]))
            .unwrap_or(0);
        if a2d < prior_a || d2a < prior_b {
            return Err("relay counter rollback".into());
        }
    }
    let sequence = previous.and_then(|p| p["sequence"].as_u64()).unwrap_or(0) + 1;
    let interval_end = clock::iso(now_ms);
    let reset = if same_boot {
        "{\"occurred\":false,\"reason\":null}"
    } else {
        "{\"occurred\":true,\"reason\":\"process-start\"}"
    };
    let payload = format!(
        "{{\"schema\":\"{REPORT_SCHEMA}\",\"onion\":{},\"bootId\":\"{boot_id}\",\"sequence\":{sequence},\"intervalStart\":\"{start}\",\"intervalEnd\":\"{interval_end}\",\"counters\":{{\"agentToDestinationBytes\":\"{a2d}\",\"destinationToAgentBytes\":\"{d2a}\"}},\"reset\":{reset}}}",
        serde_json::to_string(onion).unwrap_or_default()
    );
    let signature = hex::encode(ed25519_sign(payload.as_bytes(), seed));
    let report = format!(
        "{},\"signature\":\"{signature}\"}}",
        &payload[..payload.len() - 1]
    );
    let next_state = format!(
        "{{\"schema\":\"{REPORT_STATE_SCHEMA}\",\"sequence\":{sequence},\"bootId\":\"{boot_id}\",\"intervalEnd\":\"{interval_end}\",\"counters\":{{\"agentToDestinationBytes\":\"{a2d}\",\"destinationToAgentBytes\":\"{d2a}\"}}}}\n"
    );
    Ok((report, next_state))
}

/// Send one report to the Elder. The state advances only once the Elder accepted it, so a
/// transport failure is retried from the same baseline next interval.
pub(crate) async fn report(
    socks: &Socks,
    elder: &str,
    signer: &Signer,
    paths: &Paths,
) -> Result<(), String> {
    let counter = read_json(&paths.counter).ok_or("relay counter state unavailable")?;
    let previous = read_json(&paths.report).filter(valid_report_state);
    let (body, next_state) = build_report(
        &counter,
        previous.as_ref(),
        &signer.onion(),
        signer.seed(),
        clock::now_ms(),
    )?;
    let reply = torhttp::request_over_tor(
        socks,
        elder,
        ELDER_PORT,
        &Request::post("/telemetry/relay", body.as_bytes()),
        torhttp::DEFAULT_ATTEMPTS,
    )
    .await
    .map_err(|e| e.to_string())?;
    if reply.get("ok") != Some(&Value::Bool(true)) {
        return Err("Elder rejected relay telemetry".into());
    }
    atomic_write(&paths.report, next_state.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_proto::{ed25519_verify, onion_to_pubkey};

    #[test]
    fn the_counter_file_is_the_javascript_schema_and_reports_chain_by_boot() {
        let dir = std::env::temp_dir().join(format!("shadenet-telemetry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let counter = Counter::new(dir.join("relay-telemetry.local.json"));
        counter.add(Direction::AgentToDestination, 10);
        counter.add(Direction::DestinationToAgent, 20);
        counter.flush();
        let state: Value = serde_json::from_slice(&std::fs::read(&counter.path).unwrap()).unwrap();
        assert!(valid_counter_state(&state), "{state}");
        assert_eq!(state["counters"]["agentToDestinationBytes"], "10");

        let signer = Signer::from_seed([3_u8; 32]);
        let now = clock::parse_iso(state["startedAt"].as_str().unwrap()).unwrap() + 60_000;
        let (report, next) =
            build_report(&state, None, &signer.onion(), signer.seed(), now).unwrap();
        let parsed: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(parsed["sequence"], 1);
        assert_eq!(parsed["reset"]["occurred"], true);
        assert_eq!(parsed["reset"]["reason"], "process-start");
        assert_eq!(parsed["intervalStart"], state["startedAt"]);
        // the signature covers the report minus its own field, as the elder recomputes it
        let signing = &report[..report.find(",\"signature\"").unwrap()];
        let payload = format!("{signing}}}");
        let sig: [u8; 64] = hex::decode(parsed["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(ed25519_verify(
            payload.as_bytes(),
            &sig,
            &onion_to_pubkey(&signer.onion()).unwrap()
        ));
        let next: Value = serde_json::from_str(&next).unwrap();
        assert!(valid_report_state(&next));

        counter.add(Direction::AgentToDestination, 5);
        counter.flush();
        let later: Value = serde_json::from_slice(&std::fs::read(&counter.path).unwrap()).unwrap();
        let (second, _) = build_report(
            &later,
            Some(&next),
            &signer.onion(),
            signer.seed(),
            now + 60_000,
        )
        .unwrap();
        let second: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(second["sequence"], 2);
        assert_eq!(second["reset"]["occurred"], false);
        assert_eq!(second["intervalStart"], next["intervalEnd"]);
        assert!(
            build_report(&later, Some(&next), &signer.onion(), signer.seed(), now).is_err(),
            "an empty interval is refused"
        );
        let mut rolled = later.clone();
        rolled["counters"]["agentToDestinationBytes"] = Value::String("1".into());
        assert_eq!(
            build_report(
                &rolled,
                Some(&next),
                &signer.onion(),
                signer.seed(),
                now + 60_000
            )
            .unwrap_err(),
            "relay counter rollback"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
