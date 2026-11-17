//! The deployment record a node joins (`packages/node/lib/network-record.mjs`,
//! `packages/node/lib/node-config.mjs`): fetched once at start, checked for joinability,
//! turned into the `SHADE_TREE_*` settings the node reads, and re-read later to tell the
//! operator when its source moved on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::knobs::{self, Knobs, GATEWAY_PORT, TOR_SOCKS_PORT};
use crate::verify;

const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const RECHECK_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Elder {
    pub(crate) onion: String,
    /// Comma-separated pinned canopy signer(s).
    pub(crate) canopy_signer: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Artifact {
    pub(crate) id: String,
    pub(crate) vkey_path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Record {
    pub(crate) value: Value,
    pub(crate) network: String,
    pub(crate) status: String,
    pub(crate) elders: Vec<Elder>,
    pub(crate) contract: String,
    pub(crate) rpc_urls: Vec<String>,
    pub(crate) chain_id: Option<u64>,
    pub(crate) deploy_block: Option<u64>,
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) node_commit: Option<String>,
    pub(crate) elder_admission: Option<String>,
}

fn is_onion(value: &str) -> bool {
    shadenet_proto::onion_to_pubkey(value).is_ok()
}

fn is_url(value: &str) -> bool {
    ["http://", "https://", "ws://", "wss://"]
        .iter()
        .any(|scheme| value.starts_with(scheme))
        && value.len() > 10
}

fn signer_text(value: &Value) -> Option<String> {
    let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    match value {
        Value::String(s) if hex64(s) => Some(s.clone()),
        Value::Array(items) if !items.is_empty() => {
            let parts: Option<Vec<&str>> = items
                .iter()
                .map(|v| v.as_str().filter(|s| hex64(s)))
                .collect();
            parts.map(|p| p.join(","))
        }
        _ => None,
    }
}

/// Every Elder Tree of a record, primary first (`eldersOf`).
pub(crate) fn elders_of(value: &Value) -> Vec<Elder> {
    let parse = |entry: &Value| {
        Some(Elder {
            onion: entry.get("onion")?.as_str()?.trim().to_string(),
            canopy_signer: entry
                .get("canopySigner")
                .and_then(signer_text)
                .unwrap_or_default(),
        })
    };
    if let Some(list) = value
        .get("elders")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty())
    {
        return list.iter().filter_map(parse).collect();
    }
    value.get("elder").and_then(parse).into_iter().collect()
}

/// The staked root's RPC endpoints in failover order (`rpcUrlsOf`).
pub(crate) fn rpc_urls_of(staked: &Value) -> Vec<String> {
    if let Some(list) = staked.get("rpcUrls").and_then(Value::as_array) {
        let urls: Vec<String> = list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        if !urls.is_empty() && urls.len() == list.len() && urls.iter().all(|u| is_url(u)) {
            return urls;
        }
    }
    staked
        .get("rpcUrl")
        .and_then(Value::as_str)
        .filter(|u| is_url(u))
        .map(|u| vec![u.to_string()])
        .unwrap_or_default()
}

/// Why a parsed record cannot be joined (`checkJoinableRecord`): empty when it can.
pub(crate) fn joinable_errors(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let mut forced = value.clone();
    if let Some(object) = forced.as_object_mut() {
        object.insert("status".into(), Value::String("live".into()));
    }
    if let Err(e) = shadenet::profile::parse_deployment("record", &forced.to_string()) {
        errors.push(e);
    }
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("undefined");
    if !matches!(status, "live" | "staging") {
        errors.push(format!(
            "status: {status}; only live or staging records can be joined"
        ));
    }
    let protocol = value.get("protocol");
    let min = protocol.and_then(|p| p.get("min")).and_then(Value::as_u64);
    let max = protocol.and_then(|p| p.get("max")).and_then(Value::as_u64);
    if !matches!((min, max), (Some(min), Some(max)) if min <= 4 && max >= 4) {
        errors.push("protocol: this node speaks v4; the record does not include it".into());
    }
    if elders_of(value).is_empty() {
        errors.push("elders: the record names no Elder Tree to announce to".into());
    }
    let staked = value
        .pointer("/admission/roots/staked")
        .cloned()
        .unwrap_or(Value::Null);
    if !staked
        .get("contract")
        .and_then(Value::as_str)
        .is_some_and(knobs::is_eth_address)
    {
        errors.push(
            "admission.roots.staked.contract: missing; a joinable record names the staked set"
                .into(),
        );
    }
    if rpc_urls_of(&staked).is_empty() {
        errors.push("admission.roots.staked.rpcUrl(s): missing".into());
    }
    errors
}

/// Parse a record's text; the errors are the operator-facing lines of the JavaScript node.
pub(crate) fn parse(text: &str) -> Result<Record, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("record: not JSON ({e})"))?;
    let errors = joinable_errors(&value);
    if !errors.is_empty() {
        return Err(format!(
            "record is not joinable:\n  {}",
            errors.join("\n  ")
        ));
    }
    let staked = value
        .pointer("/admission/roots/staked")
        .cloned()
        .unwrap_or(Value::Null);
    let artifacts = value
        .pointer("/artifacts/accepted")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    Some(Artifact {
                        id: a.get("id")?.as_str()?.to_string(),
                        vkey_path: a.get("verificationKeyPath")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Record {
        network: value
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        status: value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        elders: elders_of(&value),
        contract: staked
            .get("contract")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        rpc_urls: rpc_urls_of(&staked),
        chain_id: staked.get("chainId").and_then(Value::as_u64),
        deploy_block: staked.get("deployBlock").and_then(Value::as_u64),
        artifacts,
        node_commit: value
            .pointer("/services/node/commit")
            .and_then(Value::as_str)
            .map(str::to_string),
        elder_admission: value
            .pointer("/elder/admission")
            .and_then(Value::as_str)
            .map(str::to_string),
        value,
    })
}

fn expand_home(src: &str) -> PathBuf {
    match src.strip_prefix('~') {
        Some(rest) => {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(format!("{home}{rest}"))
        }
        None => knobs::absolute(Path::new(src)),
    }
}

/// Read the record's text from an `https://` URL or a file.
pub(crate) fn read_source(src: &str) -> Result<String, String> {
    if src.starts_with("https://") {
        let client = reqwest::blocking::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|e| format!("record: {e}"))?;
        let response = client
            .get(src)
            .header("accept", "application/json")
            .send()
            .map_err(|e| format!("record: {src}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "record: {src} answered HTTP {}",
                response.status().as_u16()
            ));
        }
        return response.text().map_err(|e| format!("record: {src}: {e}"));
    }
    let path = expand_home(src);
    if !path.exists() {
        return Err(format!("record: {} does not exist", path.display()));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("record: {}: {e}", path.display()))
}

/// Fetch, check and (when `save`) keep a copy as `<state>/record.json`.
pub(crate) fn fetch(src: &str, state_dir: &Path, save: bool) -> Result<Record, String> {
    let record = parse(&read_source(src)?)?;
    if save {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| format!("create {}: {e}", state_dir.display()))?;
        let pretty = serde_json::to_string_pretty(&record.value).unwrap_or_default();
        std::fs::write(state_dir.join("record.json"), format!("{pretty}\n"))
            .map_err(|e| format!("write {}: {e}", state_dir.join("record.json").display()))?;
    }
    Ok(record)
}

/// What changed between the record a node started with and the one its source serves now,
/// in the fields a running node cannot pick up without a restart (`recordDrift`).
pub(crate) fn drift(started: &Value, current: &Value) -> Vec<String> {
    let mut changes = Vec::new();
    let set = |r: &Value| {
        r.pointer("/admission/roots/staked/contract")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    if set(started) != set(current) {
        let name = |s: String| if s.is_empty() { "none".to_string() } else { s };
        changes.push(format!(
            "set {} -> {}",
            name(set(started)),
            name(set(current))
        ));
    }
    let elders = |r: &Value| {
        let mut list: Vec<String> = elders_of(r)
            .iter()
            .map(|e| format!("{}/{}", e.onion, e.canopy_signer))
            .collect();
        list.sort();
        list.join(",")
    };
    if elders(started) != elders(current) {
        changes.push(format!(
            "Elder Trees {} -> {} (onions or signers changed)",
            elders_of(started).len(),
            elders_of(current).len()
        ));
    }
    let artifacts = |r: &Value| {
        let mut ids: Vec<String> = r
            .pointer("/artifacts/accepted")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|a| a.get("id").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids.join(",")
    };
    if artifacts(started) != artifacts(current) {
        let name = |s: String| if s.is_empty() { "none".to_string() } else { s };
        changes.push(format!(
            "proof artifacts {} -> {}",
            name(artifacts(started)),
            name(artifacts(current))
        ));
    }
    let epoch = |r: &Value| {
        r.pointer("/ratePolicy/epochSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    if epoch(started) != epoch(current) {
        changes.push(format!(
            "epoch {} s -> {} s",
            epoch(started),
            epoch(current)
        ));
    }
    let status = |r: &Value| -> String {
        r.get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    if status(started) != status(current) {
        let name = |s: String| if s.is_empty() { "?".to_string() } else { s };
        changes.push(format!(
            "status {} -> {}",
            name(status(started)),
            name(status(current))
        ));
    }
    changes
}

/// The `SHADE_TREE_*` defaults a live record supplies (`envDefaultsFromRecords`), for a node:
/// the client-only `SHADE_TREE_LEAF_SOURCE` and `SHADE_TREE_LIMIT` are left out.
fn record_defaults(record: &Record) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let value = &record.value;
    let elders: Vec<&Elder> = record
        .elders
        .iter()
        .filter(|e| is_onion(&e.onion))
        .collect();
    if let Some(primary) = elders.first() {
        out.insert("SHADE_TREE_BOOTNODE_ONION".into(), primary.onion.clone());
    }
    out.insert(
        "SHADE_TREE_BOOTNODE_ONIONS".into(),
        elders
            .iter()
            .map(|e| e.onion.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    let mut signers: Vec<&str> = Vec::new();
    for elder in &elders {
        for signer in elder.canopy_signer.split(',').filter(|s| !s.is_empty()) {
            if !signers.contains(&signer) {
                signers.push(signer);
            }
        }
    }
    out.insert("SHADE_TREE_DIR_SIGNER".into(), signers.join(","));
    if let Some(admission) = &record.elder_admission {
        out.insert("SHADE_TREE_BOOTNODE_ADMISSION".into(), admission.clone());
    }
    if let Some(registry) = value
        .pointer("/elder/gatewayRegistry")
        .and_then(Value::as_str)
    {
        out.insert("SHADE_TREE_GATEWAY_REGISTRY".into(), registry.to_string());
    }
    if let Some(rate) = value.get("ratePolicy").filter(|r| r.is_object()) {
        for (field, name) in [
            ("epochSeconds", "SHADE_TREE_EPOCH_SECONDS"),
            ("rootFreshnessSeconds", "SHADE_TREE_ROOT_FRESHNESS_SECONDS"),
            ("payloadBytesPerSlot", "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES"),
        ] {
            if let Some(n) = rate.get(field).and_then(Value::as_u64) {
                out.insert(name.into(), n.to_string());
            }
        }
    }
    if value.get("sessionTickets") == Some(&Value::Bool(true)) {
        out.insert("SHADE_TREE_SESSION_TICKETS".into(), "1".into());
    }
    let staked = value
        .pointer("/admission/roots/staked")
        .cloned()
        .unwrap_or(Value::Null);
    if knobs::is_eth_address(&record.contract) {
        out.insert("SHADE_TREE_GROUP_CONTRACT".into(), record.contract.clone());
        if !record.rpc_urls.is_empty() {
            out.insert("SHADE_TREE_RPC_URL".into(), record.rpc_urls.join(","));
        }
        if let Some(chain) = record.chain_id.filter(|c| *c > 0) {
            out.insert("SHADE_TREE_CHAIN_ID".into(), chain.to_string());
        }
        if staked.get("profile").and_then(Value::as_str) == Some("public-stake-v1") {
            out.insert("SHADE_TREE_STAKE_PROFILE".into(), "public-stake-v1".into());
        }
        if let Some(block) = record.deploy_block {
            out.insert("SHADE_TREE_FROM_BLOCK".into(), format!("0x{block:x}"));
            out.insert(
                "SHADE_TREE_FROM_BLOCKS".into(),
                format!("{}={block}", record.contract),
            );
        }
        if let Some(tiers) = staked.get("tiers").and_then(Value::as_array) {
            out.insert(
                "SHADE_TREE_TIERS".into(),
                tiers
                    .iter()
                    .filter_map(|t| t.get("limit").and_then(Value::as_u64))
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }
    out
}

/// Knobs plus record into the `SHADE_TREE_*` map the node reads (`deriveNodeEnv`). The
/// operator's own explicit variables always win. Secrets are not read here: the operator
/// key file is read into `SHADE_TREE_GW_OPERATOR_KEY` by the caller.
pub(crate) fn derive_env(
    knobs: &Knobs,
    record: &Record,
    explicit: &BTreeMap<String, String>,
    hs_dir: &Path,
) -> BTreeMap<String, String> {
    let mut out = record_defaults(record);
    let (format, level) = knobs.log_parts();
    let metrics = knobs.metrics_port();
    let state = &knobs.state;
    let put = |out: &mut BTreeMap<String, String>, key: &str, value: String| {
        out.insert(key.to_string(), value);
    };
    put(
        &mut out,
        "SHADE_TREE_REF",
        record.node_commit.clone().unwrap_or_default(),
    );
    put(&mut out, "SHADE_TREE_ADMIT", knobs.admit.clone());
    put(&mut out, "SHADE_TREE_EGRESS_ALLOW", knobs.allow.clone());
    put(&mut out, "SHADE_TREE_GW_WEIGHT", knobs.weight.clone());
    put(&mut out, "SHADE_TREE_LOG_FORMAT", format);
    put(&mut out, "SHADE_TREE_LOG_LEVEL", level);
    put(&mut out, "SHADE_TREE_BANNER", "never".into());
    put(
        &mut out,
        "SHADE_TREE_METRICS_PORT",
        metrics.map_or("0".to_string(), |p| p.to_string()),
    );
    put(
        &mut out,
        "SHADE_TREE_HEARTBEAT_METRICS_PORT",
        metrics.map_or("0".to_string(), |p| (u32::from(p) + 2).to_string()),
    );
    put(
        &mut out,
        "SHADE_TREE_GATEWAY_PORT",
        GATEWAY_PORT.to_string(),
    );
    put(&mut out, "SHADE_TREE_TOR_HOST", "127.0.0.1".into());
    put(&mut out, "SHADE_TREE_TOR_PORT", TOR_SOCKS_PORT.to_string());
    put(
        &mut out,
        "SHADE_TREE_GW_IDENTITY",
        hs_dir
            .join(crate::onion::IDENTITY_FILE)
            .display()
            .to_string(),
    );
    put(
        &mut out,
        "SHADE_TREE_SPENT_STATE_FILE",
        state.join("spent-set.local.json").display().to_string(),
    );
    put(
        &mut out,
        "SHADE_TREE_RELAY_TELEMETRY_STATE",
        state
            .join("relay-telemetry.local.json")
            .display()
            .to_string(),
    );
    put(
        &mut out,
        "SHADE_TREE_RELAY_REPORT_STATE",
        state.join("relay-report.local.json").display().to_string(),
    );
    put(
        &mut out,
        "SHADE_TREE_DRAIN_FILE",
        state.join("draining").display().to_string(),
    );
    if !record.artifacts.is_empty() {
        let builtin = verify::builtin_artifact_id();
        let spec: Vec<String> = record
            .artifacts
            .iter()
            .map(|a| {
                if a.id == builtin {
                    format!("{}={}", a.id, verify::BUILTIN_PATH)
                } else {
                    format!("{}={}", a.id, a.vkey_path)
                }
            })
            .collect();
        put(&mut out, "SHADE_TREE_ZK_ARTIFACTS", spec.join(","));
    }
    let (extra, _) = knobs::parse_sets(&knobs.sets);
    let extra: Vec<&(String, u64)> = extra
        .iter()
        .filter(|(c, _)| !c.eq_ignore_ascii_case(&record.contract))
        .collect();
    if !extra.is_empty() && knobs::is_eth_address(&record.contract) {
        let mut all: Vec<(String, u64)> =
            vec![(record.contract.clone(), record.deploy_block.unwrap_or(0))];
        all.extend(extra.iter().map(|(c, b)| (c.clone(), *b)));
        put(
            &mut out,
            "SHADE_TREE_GROUP_CONTRACT",
            all.iter()
                .map(|(c, _)| c.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        put(
            &mut out,
            "SHADE_TREE_FROM_BLOCKS",
            all.iter()
                .map(|(c, b)| format!("{c}={b}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        let min = all.iter().map(|(_, b)| *b).min().unwrap_or(0);
        put(&mut out, "SHADE_TREE_FROM_BLOCK", format!("0x{min:x}"));
    }
    if !knobs.deny.is_empty() {
        put(&mut out, "SHADE_TREE_EGRESS_DENY", knobs.deny.clone());
    }
    if !knobs.conns.is_empty() {
        put(&mut out, "SHADE_TREE_MAX_CONNS", knobs.conns.clone());
    }
    if !knobs.sessions.is_empty() {
        put(&mut out, "SHADE_TREE_SESSION_MAX", knobs.sessions.clone());
    }
    if let Some(bytes) = knobs::parse_bandwidth(&knobs.bandwidth) {
        put(
            &mut out,
            "SHADE_TREE_BANDWIDTH_BYTES_PER_SECOND",
            bytes.to_string(),
        );
    }
    if let Some(file) = &knobs.deny_file {
        put(&mut out, "SHADE_TREE_EGRESS_DENY_FILE", file.clone());
    }
    if knobs.canary == "on" {
        put(&mut out, "SHADE_TREE_CANARY", "1".into());
    }
    if !knobs.region.is_empty() {
        put(&mut out, "SHADE_TREE_GATEWAY_REGION", knobs.region.clone());
    }
    if let Some(file) = &knobs.members_file {
        put(&mut out, "SHADE_TREE_MEMBERS_FILE", file.clone());
    }
    if let (Some(operator), Some(sig)) = (&knobs.operator, &knobs.operator_sig) {
        put(&mut out, "SHADE_TREE_GW_OPERATOR", operator.clone());
        put(
            &mut out,
            "SHADE_TREE_GW_OPERATOR_SIG",
            sig.trim().to_string(),
        );
    }
    for (key, value) in explicit {
        if !value.trim().is_empty() {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

/// A copy for printing: keys and signatures show their first six characters only.
pub(crate) fn redact(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env.iter()
        .map(|(k, v)| {
            let secret = ["_KEY", "_SIG", "_TOKEN", "_SECRET"]
                .iter()
                .any(|suffix| k.ends_with(suffix));
            let shown = if secret && !v.is_empty() {
                format!("{}…", v.chars().take(6).collect::<String>())
            } else {
                v.clone()
            };
            (k.clone(), shown)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEPOLIA: &str = include_str!("../../../network/sepolia/deployment.json");
    const STAGING: &str = include_str!("../../../network/sepolia-staging/deployment.json");

    fn knobs_for(state: &str) -> Knobs {
        Knobs {
            record: Some("/r".into()),
            state: PathBuf::from(state),
            admit: "staked".into(),
            allow: "*:443".into(),
            weight: "100".into(),
            metrics: "9101".into(),
            log: "json:info".into(),
            ..Knobs::default()
        }
    }

    #[test]
    fn the_bundled_records_are_joinable_and_derive_the_node_settings() {
        let record = parse(SEPOLIA).unwrap();
        assert_eq!(record.network, "sepolia");
        assert_eq!(record.elders.len(), 2);
        assert_eq!(record.rpc_urls.len(), 2);
        assert!(parse(STAGING).is_ok(), "staging records are joinable too");
        let env = derive_env(
            &knobs_for("/state"),
            &record,
            &BTreeMap::new(),
            Path::new("/state/hs-gateway"),
        );
        assert_eq!(
            env["SHADE_TREE_BOOTNODE_ONIONS"],
            record
                .elders
                .iter()
                .map(|e| e.onion.clone())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(env["SHADE_TREE_DIR_SIGNER"].split(',').count(), 2);
        assert_eq!(env["SHADE_TREE_GROUP_CONTRACT"], record.contract);
        assert_eq!(env["SHADE_TREE_RPC_URL"], record.rpc_urls.join(","));
        assert_eq!(env["SHADE_TREE_EPOCH_SECONDS"], "60");
        assert_eq!(env["SHADE_TREE_SESSION_TICKETS"], "1");
        assert_eq!(
            env["SHADE_TREE_FROM_BLOCK"],
            format!("0x{:x}", record.deploy_block.unwrap())
        );
        assert_eq!(env["SHADE_TREE_TIERS"], "8");
        assert_eq!(env["SHADE_TREE_METRICS_PORT"], "9101");
        assert_eq!(env["SHADE_TREE_HEARTBEAT_METRICS_PORT"], "9103");
        assert_eq!(
            env["SHADE_TREE_GW_IDENTITY"],
            "/state/hs-gateway/identity.local.json"
        );
        assert_eq!(env["SHADE_TREE_DRAIN_FILE"], "/state/draining");
        assert_eq!(
            env["SHADE_TREE_ZK_ARTIFACTS"],
            format!("{}={}", verify::builtin_artifact_id(), verify::BUILTIN_PATH),
            "the record's artifact is the one built into this binary"
        );
        assert!(!env.contains_key("SHADE_TREE_LEAF_SOURCE"));
        assert!(!env.contains_key("SHADE_TREE_LIMIT"));
        assert!(
            !env.contains_key("SHADE_TREE_MAX_CONNS")
                && !env.contains_key("SHADE_TREE_SESSION_MAX")
                && !env.contains_key("SHADE_TREE_BANDWIDTH_BYTES_PER_SECOND")
                && !env.contains_key("SHADE_TREE_EGRESS_DENY_FILE")
                && !env.contains_key("SHADE_TREE_CANARY"),
            "unset limits leave the node's own defaults alone"
        );
        assert_eq!(env["SHADE_TREE_BANNER"], "never");
    }

    #[test]
    fn extra_sets_follow_the_records_set_and_explicit_variables_win() {
        let record = parse(STAGING).unwrap();
        let production = parse(SEPOLIA).unwrap();
        let mut knobs = knobs_for("/state");
        knobs.sets = format!(
            "{}@{}",
            production.contract,
            production.deploy_block.unwrap()
        );
        knobs.deny = "*:80".into();
        knobs.conns = "32".into();
        knobs.sessions = "8".into();
        knobs.bandwidth = "2m".into();
        knobs.deny_file = Some("/etc/shadenet/blocklist.txt".into());
        knobs.canary = "on".into();
        knobs.region = "eu".into();
        knobs.operator = Some("0x70997970C51812dc3A010C7d01b50e0d17dc79C8".into());
        knobs.operator_sig = Some(format!("0x{}", "11".repeat(65)));
        let explicit = BTreeMap::from([
            ("SHADE_TREE_GW_WEIGHT".to_string(), "7".to_string()),
            ("SHADE_TREE_EMPTY".to_string(), " ".to_string()),
        ]);
        let env = derive_env(&knobs, &record, &explicit, Path::new("/state/hs-gateway"));
        assert_eq!(
            env["SHADE_TREE_GROUP_CONTRACT"],
            format!("{},{}", record.contract, production.contract)
        );
        assert_eq!(
            env["SHADE_TREE_FROM_BLOCKS"],
            format!(
                "{}={},{}={}",
                record.contract,
                record.deploy_block.unwrap(),
                production.contract,
                production.deploy_block.unwrap()
            )
        );
        assert_eq!(
            env["SHADE_TREE_FROM_BLOCK"],
            format!(
                "0x{:x}",
                record
                    .deploy_block
                    .unwrap()
                    .min(production.deploy_block.unwrap())
            )
        );
        assert_eq!(env["SHADE_TREE_GW_WEIGHT"], "7");
        assert_eq!(env["SHADE_TREE_EGRESS_DENY"], "*:80");
        assert_eq!(env["SHADE_TREE_MAX_CONNS"], "32");
        assert_eq!(env["SHADE_TREE_SESSION_MAX"], "8");
        assert_eq!(env["SHADE_TREE_BANDWIDTH_BYTES_PER_SECOND"], "2097152");
        assert_eq!(
            env["SHADE_TREE_EGRESS_DENY_FILE"],
            "/etc/shadenet/blocklist.txt"
        );
        assert_eq!(env["SHADE_TREE_CANARY"], "1");
        assert_eq!(env["SHADE_TREE_GATEWAY_REGION"], "eu");
        assert_eq!(
            env["SHADE_TREE_GW_OPERATOR"],
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        );
        assert!(!env.contains_key("SHADE_TREE_EMPTY"));
        let shown = redact(&env);
        assert_eq!(shown["SHADE_TREE_GW_OPERATOR_SIG"], "0x1111…");
        assert_eq!(shown["SHADE_TREE_GW_WEIGHT"], "7");
    }

    #[test]
    fn unjoinable_records_name_their_problems() {
        assert!(parse("nope").unwrap_err().starts_with("record: not JSON ("));
        let mut retired: Value = serde_json::from_str(SEPOLIA).unwrap();
        retired["status"] = Value::String("retired".into());
        let error = parse(&retired.to_string()).unwrap_err();
        assert!(error.contains("record is not joinable:\n"), "{error}");
        assert!(
            error.contains("status: retired; only live or staging records can be joined"),
            "{error}"
        );
        let mut no_elders: Value = serde_json::from_str(SEPOLIA).unwrap();
        no_elders["elders"] = Value::Array(Vec::new());
        no_elders["elder"] = Value::Null;
        let error = parse(&no_elders.to_string()).unwrap_err();
        assert!(
            error.contains("elders: the record names no Elder Tree to announce to"),
            "{error}"
        );
    }

    #[test]
    fn drift_names_what_a_running_node_cannot_follow() {
        let base: Value = serde_json::from_str(SEPOLIA).unwrap();
        assert!(drift(&base, &base.clone()).is_empty());
        let mut moved = base.clone();
        moved["admission"]["roots"]["staked"]["contract"] =
            Value::String(format!("0x{}", "ab".repeat(20)));
        assert!(drift(&base, &moved)[0].starts_with("set 0x"));
        assert!(drift(&base, &moved)[0].contains("-> 0xabab"));
        let mut elders = base.clone();
        elders["elders"].as_array_mut().unwrap().push(serde_json::json!({"onion": format!("{}.onion", "c".repeat(56)), "canopySigner": "d".repeat(64)}));
        assert!(drift(&base, &elders)[0].starts_with("Elder Trees 2 -> 3"));
        let mut retired = base.clone();
        retired["status"] = Value::String("retired".into());
        assert_eq!(drift(&base, &retired), vec!["status live -> retired"]);
        let mut note = base.clone();
        note["note"] = Value::String("edited prose".into());
        assert!(drift(&base, &note).is_empty(), "prose edits are not drift");
    }
}
