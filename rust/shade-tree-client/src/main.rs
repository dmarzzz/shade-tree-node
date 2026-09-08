//! `shade-tree` — the Shade Tree distributable client (single static binary with embedded Tor).
//!
//! This is the **deterministic client MVP** (T-RUST-2): it parses UNTRUSTED
//! directory / receipt JSON, then runs the trust-critical checks from `shade-tree-proto`
//! (the Rust port of the JS reference, gated by `testdata/vectors.json`). The two
//! non-deterministic LIVE pieces — the RLN Groth16 proof (T-RUST-2b/2c/2d) and the
//! embedded-Tor onion dial (T-RUST-2e, `arti-client`) — compile only under the
//! `live` cargo feature (see the [`live`] module); the default build stays sub-second.
//!
//! serde/serde_json are used HERE (to parse untrusted JSON into local DTOs) and are
//! deliberately kept out of `shade-tree-proto`, whose canonical byte path is serde-free.
//! See docs/adr/0001-client-language.md and docs/SHIP-PLAN.md T-RUST-2.

use std::collections::HashSet;
use std::process::ExitCode;

use serde::Deserialize;
use shade_tree_proto::{pick_gateway, selection_order, verify_receipt, Receipt};

mod capability;
mod dircache;
#[cfg(feature = "live")]
mod enroll;
mod health;
#[cfg(feature = "live")]
mod leaves;
#[cfg(feature = "live")]
mod member;
#[cfg(feature = "live")]
mod register;
mod run;
// The crash-safe K-slot coordinator is used by the `live` egress path; its unit
// tests run on the default build under `test`.
#[cfg(test)]
#[allow(dead_code)]
mod slotcursor;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CLIENT_NETWORK: &str = "sepolia";
const DEFAULT_DEPLOYMENT: &str = include_str!("../../../network/sepolia/deployment.json");
const LEGACY_DEFAULT_LIMIT: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledStakedRoot {
    profile: Option<String>,
    contract: String,
    rpc_url: String,
    chain_id: Option<u64>,
    deploy_tx: Option<String>,
    deploy_block: Option<u64>,
    hasher: Option<String>,
    withdraw_verifier: Option<String>,
    default_limit: Option<u64>,
    tiers: Option<Vec<(u64, String)>>,
    unbonding_seconds: Option<u64>,
    min_unbonding_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledDeployment {
    elder_onion: String,
    canopy_signer: String,
    default_path: Option<String>,
    rate_policy: Option<shade_tree_proto::CanonicalRate>,
    staked: Option<BundledStakedRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicStakedProfile {
    default_path: String,
    rate_policy: shade_tree_proto::CanonicalRate,
    contract: String,
    rpc_url: String,
    chain_id: u64,
    deploy_block: u64,
    default_limit: u64,
}

fn optional_u64(object: &serde_json::Value, name: &str) -> Result<Option<u64>, String> {
    match object.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("bundled deployment {name} must be an unsigned integer")),
    }
}

fn parse_bundled_rate(
    value: &serde_json::Value,
) -> Result<shade_tree_proto::CanonicalRate, String> {
    let string = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("bundled ratePolicy.{name} is missing or invalid"))
    };
    let integer = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .filter(|number| *number <= i64::MAX as u64)
            .map(|number| number as i64)
            .ok_or_else(|| format!("bundled ratePolicy.{name} is missing or invalid"))
    };
    let raw = shade_tree_proto::RateCaps {
        scope: string("scope")?,
        window: string("window")?,
        epoch_seconds: integer("epochSeconds")?,
        previous_epochs_accepted: integer("previousEpochsAccepted")?,
        root_freshness_seconds: integer("rootFreshnessSeconds")?,
        payload_bytes_per_slot: integer("payloadBytesPerSlot")?,
    };
    shade_tree_proto::canonical_rate(&raw).ok_or_else(|| {
        "bundled ratePolicy is outside the supported grove-v4 fixed-window bounds".into()
    })
}

fn parse_bundled_deployment(raw: &str) -> Result<BundledDeployment, String> {
    let deployment: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| format!("bundled {DEFAULT_CLIENT_NETWORK} deployment is invalid JSON: {e}"))?;
    if deployment.get("status").and_then(serde_json::Value::as_str) != Some("live") {
        return Err(format!(
            "bundled {DEFAULT_CLIENT_NETWORK} deployment is not live"
        ));
    }
    let protocol = deployment
        .get("protocol")
        .ok_or_else(|| "bundled deployment has no protocol range".to_string())?;
    let min = protocol
        .get("min")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "bundled deployment has no protocol.min".to_string())?;
    let max = protocol
        .get("max")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "bundled deployment has no protocol.max".to_string())?;
    if !(min..=max).contains(&4) {
        return Err("bundled deployment does not support protocol v4".into());
    }
    let elder = deployment
        .get("elder")
        .ok_or_else(|| "bundled deployment has no Elder".to_string())?;
    let onion = elder
        .get("onion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "bundled deployment has no Elder onion".to_string())?;
    // Parse the onion now, before Tor is involved. Directory verification validates the signer.
    shade_tree_proto::onion_to_pubkey(onion)
        .map_err(|e| format!("bundled deployment has an invalid Elder onion: {e}"))?;
    let pins: Vec<&str> = match elder.get("canopySigner") {
        Some(serde_json::Value::String(pin)) => vec![pin.as_str()],
        Some(serde_json::Value::Array(pins)) => pins
            .iter()
            .map(|pin| {
                pin.as_str()
                    .ok_or_else(|| "bundled deployment has a non-string Canopy signer".to_string())
            })
            .collect::<Result<_, _>>()?,
        _ => return Err("bundled deployment has no Canopy signer".into()),
    };
    if pins.is_empty()
        || pins
            .iter()
            .any(|pin| pin.len() != 64 || hex::decode(pin).map_or(true, |bytes| bytes.len() != 32))
    {
        return Err("bundled deployment has an invalid Canopy signer".into());
    }
    let admission = deployment.get("admission");
    let default_path = admission
        .and_then(|value| value.get("defaultPath"))
        .or_else(|| deployment.get("defaultPath"))
        .map(|value| {
            value
                .as_str()
                .map(|path| path.to_ascii_lowercase())
                .ok_or_else(|| "bundled deployment defaultPath must be a string".to_string())
        })
        .transpose()?;
    let rate_policy = deployment
        .get("ratePolicy")
        .or_else(|| admission.and_then(|value| value.get("ratePolicy")))
        .map(parse_bundled_rate)
        .transpose()?;
    let staked = admission
        .and_then(|value| value.pointer("/roots/staked"))
        .filter(|value| !value.is_null())
        .map(|value| {
            let contract = value
                .get("contract")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "bundled staked root has no contract".to_string())?;
            let rpc_url = value
                .get("rpcUrl")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "bundled staked root has no RPC".to_string())?;
            let optional_string = |name: &str| {
                value
                    .get(name)
                    .map(|entry| {
                        entry
                            .as_str()
                            .map(str::to_string)
                            .ok_or_else(|| format!("bundled staked root {name} must be a string"))
                    })
                    .transpose()
            };
            let tiers = value
                .get("tiers")
                .map(|tiers| {
                    tiers
                        .as_array()
                        .ok_or_else(|| "bundled staked root tiers must be an array".to_string())?
                        .iter()
                        .map(|tier| {
                            let limit = tier
                                .get("limit")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or_else(|| {
                                    "bundled staked tier limit must be an unsigned integer"
                                        .to_string()
                                })?;
                            let bond = tier
                                .get("bondWei")
                                .and_then(serde_json::Value::as_str)
                                .ok_or_else(|| {
                                    "bundled staked tier bondWei must be a string".to_string()
                                })?;
                            Ok((limit, bond.to_string()))
                        })
                        .collect::<Result<Vec<_>, String>>()
                })
                .transpose()?;
            Ok::<_, String>(BundledStakedRoot {
                profile: optional_string("profile")?,
                contract: contract.to_string(),
                rpc_url: rpc_url.to_string(),
                chain_id: optional_u64(value, "chainId")?,
                deploy_tx: optional_string("deployTx")?,
                deploy_block: optional_u64(value, "deployBlock")?,
                hasher: optional_string("hasher")?,
                withdraw_verifier: optional_string("withdrawVerifier")?,
                default_limit: optional_u64(value, "defaultLimit")?,
                tiers,
                unbonding_seconds: optional_u64(value, "unbondingSeconds")?,
                min_unbonding_seconds: optional_u64(value, "minUnbondingSeconds")?,
            })
        })
        .transpose()?;
    Ok(BundledDeployment {
        elder_onion: onion.to_string(),
        canopy_signer: pins.join(","),
        default_path,
        rate_policy,
        staked,
    })
}

// Read the bundled deployment record instead of duplicating its trust pair in Rust source. The
// signed Canopy remains the mutable gateway list; this record pins the Elder, its signer, and the
// public Grove's internally consistent membership/rate defaults.
fn default_deployment() -> Result<BundledDeployment, String> {
    parse_bundled_deployment(DEFAULT_DEPLOYMENT)
}

fn staked_default_limit_from(deployment: &BundledDeployment) -> Result<u64, String> {
    let limit = deployment
        .staked
        .as_ref()
        .ok_or_else(|| "bundled deployment has no live staked admission root".to_string())?
        .default_limit
        .unwrap_or(LEGACY_DEFAULT_LIMIT);
    if !(1..=u16::MAX as u64).contains(&limit) {
        return Err("bundled staked admission root has an invalid defaultLimit".into());
    }
    Ok(limit)
}

fn default_staked_limit() -> Result<u64, String> {
    let deployment = default_deployment()?;
    staked_default_limit_from(&deployment)
}

fn default_discovery() -> Result<(String, String), String> {
    let deployment = default_deployment()?;
    Ok((deployment.elder_onion, deployment.canopy_signer))
}

fn public_profile_from(deployment: BundledDeployment) -> Result<PublicStakedProfile, String> {
    let default_path = deployment
        .default_path
        .ok_or_else(|| "bundled deployment has no admission.defaultPath".to_string())?;
    if default_path != "staked" {
        return Err(format!(
            "bundled deployment defaultPath={default_path:?}; this client profile requires staked"
        ));
    }
    let rate_policy = deployment
        .rate_policy
        .ok_or_else(|| "bundled deployment has no ratePolicy".to_string())?;
    let expected_rate = shade_tree_proto::CanonicalRate {
        scope: "grove-v4".into(),
        window: "fixed".into(),
        epoch_seconds: 60,
        previous_epochs_accepted: 1,
        root_freshness_seconds: 60,
        payload_bytes_per_slot: shade_tree_proto::DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES,
    };
    if rate_policy != expected_rate {
        return Err(
            "bundled ratePolicy does not match the supported public Grove v4 policy".into(),
        );
    }
    let staked = deployment
        .staked
        .ok_or_else(|| "bundled deployment has no staked admission root".to_string())?;
    if staked.profile.as_deref() != Some("public-stake-v1") {
        return Err("bundled staking root does not declare profile public-stake-v1".into());
    }
    let chain_id = staked
        .chain_id
        .filter(|chain_id| *chain_id == 11_155_111)
        .ok_or_else(|| {
            "bundled public staking profile must pin Sepolia chainId 11155111".to_string()
        })?;
    let exact_tiers = vec![
        (1, "100000000000000000".to_string()),
        (8, "800000000000000000".to_string()),
    ];
    if staked.tiers.as_ref() != Some(&exact_tiers) {
        return Err("bundled public staking tiers must equal 1:0.1 ETH and 8:0.8 ETH".into());
    }
    let address_is_valid = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|address| address.strip_prefix("0x"))
            .is_some_and(|hex_address| {
                hex_address.len() == 40
                    && hex::decode(hex_address).is_ok_and(|bytes| bytes.len() == 20)
            })
    };
    if !address_is_valid(&staked.hasher) || !address_is_valid(&staked.withdraw_verifier) {
        return Err(
            "bundled public staking profile must pin hasher and withdrawVerifier addresses".into(),
        );
    }
    if staked
        .deploy_tx
        .as_deref()
        .is_none_or(|tx| tx.len() != 66 || !tx.starts_with("0x") || hex::decode(&tx[2..]).is_err())
    {
        return Err("bundled public staking profile must pin a deployment transaction".into());
    }
    if staked.unbonding_seconds != Some(86_400) || staked.min_unbonding_seconds != Some(3_720) {
        return Err(
            "bundled public staking profile must pin 86400/3720-second unbonding safety values"
                .into(),
        );
    }
    let deploy_block = staked
        .deploy_block
        .ok_or_else(|| "bundled staked admission root has no deployBlock".to_string())?;
    let default_limit = staked
        .default_limit
        .filter(|limit| (1..=u16::MAX as u64).contains(limit))
        .ok_or_else(|| "bundled staked admission root has no valid defaultLimit".to_string())?;
    if default_limit != 1 {
        return Err(format!(
            "bundled staked defaultLimit is {default_limit}, expected public tier 1"
        ));
    }
    Ok(PublicStakedProfile {
        default_path,
        rate_policy,
        contract: staked.contract,
        rpc_url: staked.rpc_url,
        chain_id,
        deploy_block,
        default_limit,
    })
}

fn default_public_profile() -> Result<PublicStakedProfile, String> {
    public_profile_from(default_deployment()?)
}

#[cfg(test)]
mod default_discovery_tests {
    use serde_json::json;

    fn public_deployment_fixture() -> serde_json::Value {
        let mut deployment: serde_json::Value =
            serde_json::from_str(super::DEFAULT_DEPLOYMENT).unwrap();
        deployment["ratePolicy"] = json!({
            "scope": "grove-v4",
            "window": "fixed",
            "epochSeconds": 60,
            "previousEpochsAccepted": 1,
            "rootFreshnessSeconds": 60,
            "payloadBytesPerSlot": 41_943_040
        });
        deployment["admission"]["defaultPath"] = json!("staked");
        let staked = &mut deployment["admission"]["roots"]["staked"];
        staked["profile"] = json!("public-stake-v1");
        staked["chainId"] = json!(11_155_111);
        staked["deployTx"] = json!(format!("0x{}", "11".repeat(32)));
        staked["deployBlock"] = json!(12_345);
        staked["hasher"] = json!("0x1111111111111111111111111111111111111111");
        staked["withdrawVerifier"] = json!("0x2222222222222222222222222222222222222222");
        staked["defaultLimit"] = json!(1);
        staked["tiers"] = json!([
            { "limit": 1, "bondWei": "100000000000000000" },
            { "limit": 8, "bondWei": "800000000000000000" }
        ]);
        staked["unbondingSeconds"] = json!(86_400);
        staked["minUnbondingSeconds"] = json!(3_720);
        deployment
    }

    #[test]
    fn bundled_v4_elder_and_signer_are_valid() {
        let (onion, signer) = super::default_discovery().expect("bundled discovery profile");
        assert!(onion.ends_with(".onion"));
        assert_eq!(signer.len(), 64);
    }

    #[test]
    fn bundled_profile_schema_parses_public_staking_defaults() {
        let deployment = public_deployment_fixture();
        let parsed = super::parse_bundled_deployment(&deployment.to_string()).unwrap();
        assert_eq!(parsed.default_path.as_deref(), Some("staked"));
        assert_eq!(parsed.staked.as_ref().unwrap().default_limit, Some(1));
        assert_eq!(parsed.staked.as_ref().unwrap().deploy_block, Some(12_345));
        let rate = parsed.rate_policy.as_ref().unwrap();
        assert_eq!(rate.epoch_seconds, 60);
        assert_eq!(rate.previous_epochs_accepted, 1);
        assert_eq!(rate.root_freshness_seconds, 60);
        assert_eq!(rate.payload_bytes_per_slot, 41_943_040);

        let profile = super::public_profile_from(parsed).unwrap();
        assert_eq!(profile.default_path, "staked");
        assert_eq!(profile.default_limit, 1);
        assert_eq!(profile.chain_id, 11_155_111);
        assert_eq!(profile.deploy_block, 12_345);
        assert_eq!(profile.rate_policy.epoch_seconds, 60);
    }

    #[test]
    fn public_profile_rejects_absent_or_different_rate_policy() {
        let mut deployment = public_deployment_fixture();
        deployment.as_object_mut().unwrap().remove("ratePolicy");
        if let Some(admission) = deployment["admission"].as_object_mut() {
            admission.remove("ratePolicy");
        }

        let absent = super::parse_bundled_deployment(&deployment.to_string()).unwrap();
        assert!(super::public_profile_from(absent)
            .unwrap_err()
            .contains("no ratePolicy"));

        deployment["ratePolicy"] = json!({
            "scope": "grove-v4",
            "window": "fixed",
            "epochSeconds": 120,
            "previousEpochsAccepted": 1,
            "rootFreshnessSeconds": 60,
            "payloadBytesPerSlot": 41_943_040
        });
        let different = super::parse_bundled_deployment(&deployment.to_string()).unwrap();
        assert!(super::public_profile_from(different)
            .unwrap_err()
            .contains("does not match"));
    }

    #[cfg(feature = "live")]
    #[test]
    fn identity_creation_uses_public_default_with_flag_then_env_precedence() {
        assert_eq!(super::identity_creation_limit_setting(None, None, 1), Ok(1));
        assert_eq!(
            super::identity_creation_limit_setting(None, Some("32"), 1),
            Ok(32)
        );
        assert_eq!(
            super::identity_creation_limit_setting(Some("8"), Some("32"), 1),
            Ok(8)
        );
    }
}

// --------------------------------------------------------------------------
// Untrusted-JSON DTOs (serde) -> shade-tree-proto structs (trust-critical checks)
// --------------------------------------------------------------------------
//
// The directory DTO now lives in `dircache` (it owns directory loading + the LKG
// cache). The receipt DTO stays here. Both are UNTRUSTED input: we deserialize
// them, map them into the shade-tree-proto types, and let shade-tree-proto do every
// security-critical decision (onion<->pubkey binding, pinned-signer signature,
// receipt onion binding + sig).

#[derive(Deserialize)]
struct ReceiptDto {
    v: u64,
    onion: String,
    // epoch is a canonical decimal STRING on the wire (lib/receipt.mjs normalizes it);
    // a number here would be a malformed receipt and is surfaced as a parse error.
    epoch: String,
    ok: bool,
    #[serde(default)]
    sig: Option<String>,
}

impl ReceiptDto {
    fn into_proto(self) -> Receipt {
        Receipt {
            v: self.v,
            onion: self.onion,
            epoch: self.epoch,
            ok: self.ok,
            sig: self.sig,
        }
    }
}

// --------------------------------------------------------------------------
// LIVE egress
// --------------------------------------------------------------------------
//
// T-RUST-2d wired the RLN prover + native tree into `shade-tree egress` behind the `live`
// cargo feature; T-RUST-2e adds the embedded-Tor transport. WITH the feature
// (`--features live`), `egress` builds a REAL envelope in Rust and sends it to the gateway
// over EMBEDDED TOR (arti dials the selected `.onion`) by default, with a `--plain-tcp`
// escape hatch that preserves the loop-22 plain-socket path (see the `live` module below).
//
// WITHOUT the feature (the default fast build), `egress` returns this honest error — the
// heavy native deps (ark-circom -> wasmer, arti-client) are only compiled under the feature
// so the deterministic client stays sub-second to build.

/// The `egress` path when the `live` feature is OFF (default): the RLN prover + embedded
/// Tor transport are not compiled in. Kept as an honest, non-hanging error.
#[cfg(not(feature = "live"))]
fn live_egress() -> Result<(), String> {
    Err(
        "live egress needs the `live` cargo feature (RLN prover + native tree + arti Tor \
         transport). Rebuild with `cargo build -p shade-tree-client --features live`. \
         See docs/adr/0001-client-language.md"
            .to_string(),
    )
}

// --------------------------------------------------------------------------
// A tiny seedable PRNG (mulberry32) so `select` is reproducible with `--seed`
// --------------------------------------------------------------------------
//
// Zero-dep on purpose (no `rand` runtime dependency). Same algorithm the JS test suite
// uses. Default seed is derived from the wall clock so an unseeded `select` still varies.

fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6D2B_79F5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        (((t ^ (t >> 14)) as f64) / 4_294_967_296.0).fract()
    }
}

fn default_seed() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x1234_5678)
}

/// Current wall clock in milliseconds (for the LKG max-age guard + health-cache
/// decay/last-seen, both of which are ms like the JS `Date.now()`).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse an optional `--max-age-ms <n>` into the LKG freshness guard. A default
/// 5-minute skew grace (matching selection.mjs `SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS`)
/// is added on top of the bound so a lagging client clock doesn't spuriously reject
/// a just-issued directory.
fn parse_max_age(args: &[String]) -> dircache::MaxAge {
    dircache::MaxAge {
        max_age_ms: take_flag(args, "--max-age-ms").and_then(|s| s.parse::<u64>().ok()),
        skew_ms: take_flag(args, "--max-age-skew-ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5 * 60 * 1000),
    }
}

/// `fetch-directory`: obtain a FRESH directory (from `--file`, or `--bootnode-tcp`
/// over plain HTTP), verify it against the pinned signer, apply the rollback +
/// optional max-age guards against the last-known-good cache, write the cache, and
/// print a summary. This is the default-build, no-Tor path that proves the
/// discovery -> verify -> LKG-cache chain; the `live` egress `--bootnode-onion`
/// reuses the same dircache machinery over embedded Tor.
fn cmd_fetch_directory(args: &[String]) -> ExitCode {
    let Some(signer) = take_flag(args, "--signer") else {
        eprintln!("fetch-directory: missing --signer <hex>");
        return ExitCode::from(2);
    };
    let cache = take_flag(args, "--cache").map(std::path::PathBuf::from);
    let max_age = parse_max_age(args);

    // Fresh source: exactly one of --file (offline) or --bootnode-tcp (plain HTTP).
    let fresh: Result<String, String> = if let Some(f) = take_flag(args, "--file") {
        read_file(&f)
    } else if let Some(hp) = take_flag(args, "--bootnode-tcp") {
        let path = take_flag(args, "--path").unwrap_or_else(|| "/directory".to_string());
        let host = hp.split(':').next().unwrap_or("127.0.0.1").to_string();
        dircache::fetch_http_plain(&hp, &host, &path)
    } else {
        eprintln!(
            "fetch-directory: need a source: --file <f> (offline) or --bootnode-tcp <host:port> \
             (plain HTTP). Live embedded-Tor discovery is `egress --bootnode-onion` (--features live)."
        );
        return ExitCode::from(2);
    };

    match dircache::resolve_directory(fresh, cache.as_deref(), &signer, max_age, now_ms()) {
        Ok(out) => {
            println!("ok");
            println!(
                "source: {}",
                match out.source {
                    dircache::Source::Fresh => "fresh",
                    dircache::Source::Cache => "cache",
                }
            );
            if let Some(fe) = out.fresh_error {
                println!("fresh-error: {fe}");
            }
            println!("issued: {}", out.dir.issued);
            println!("gateways: {}", out.dir.gateways.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}

// --------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------

const HELP: &str = "\
shade-tree — local egress client (research preview)

USAGE:
    shade-tree <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    verify-directory <file> --signer <hex>
        Parse a signed directory JSON file and verify it against the pinned
        ed25519 signer (onion<->pubkey binding + signature). Prints ok / reason.

    fetch-directory --signer <hex> [--cache <f>] [--max-age-ms <n>]
                    (--file <f> | --bootnode-tcp <host:port> [--path </directory>])
        Obtain a FRESH directory (offline --file, or --bootnode-tcp plain HTTP),
        verify it, apply the rollback + optional max-age guards against the
        last-known-good --cache, write the cache, and print source/issued/gateways.
        On a failed or refused fresh fetch, falls back to the verified LKG cache
        (never serves an unverified directory). Embedded-Tor bootnode discovery is
        `egress --bootnode-onion` in a --features live build.

    select <dir-file> --signer <hex> [--seed <n>] [--health-cache <f>]
                      [--port <n>] [--proto <n>] [--region <bucket>]
                      [--leaf-source invited|staked|paid] [--max-anon]
        Verify the directory, then print the weighted-random chosen gateway onion
        and the full failover order. --seed makes the choice reproducible.
        --health-cache seeds each gateway's health from persisted egress failover
        feedback, so a gateway that failed last session starts deprioritized.
        --port/--proto/--region (T-FEAT-10) form an OPT-IN capability requirement:
        only gateways whose SIGNED caps meet it are selected (a no-caps gateway meets
        only the conservative 443/v4 floor; region is never implicit). If no gateway
        qualifies, select fails closed (not-ok) rather than dialing an incapable one.
        --leaf-source / --max-anon (T-FEAT-9, docs/adr/0008): admission-aware selection.
        A gateway advertises WHICH admission paths it honours as signed caps.admits
        (invited > staked > paid, the anonymity order). --leaf-source names the set
        YOUR leaf is in (SHADE_TREE_LEAF_SOURCE): only gateways that admit it are selected
        (a gateway advertising no policy is kept, rollout compat). --max-anon
        (SHADE_TREE_MAX_ANON=1) keeps ONLY invited-only gateways (admits=[invited]) and
        refuses a staked/paid leaf source. Neither given = byte-identical selection.
        The same two flags apply to `egress --directory` / `--bootnode-onion`.

    verify-receipt <receipt-file> --onion <onion>
        Parse an egress-success receipt JSON file and verify it (onion<->pubkey
        binding + ed25519 signature), bound to --onion. Prints ok / reason.

    enroll [--limit <n>] [--out identity.json] [--members members.json]
        Generate a new member identity entirely in Rust. The owner-only identity
        file stays local; stdout contains only its public enrollment leaf for a
        Grove operator. --members explicitly adds the leaf to a local version-2
        demo set. The default tier is the bundled staked defaultLimit (public: 1);
        --limit / SHADE_TREE_LIMIT wins for a custom Grove. Existing identity files
        are never overwritten. Requires live.

    proxy-token
        Print a fresh 256-bit URL-safe token for `proxy` and `run`. Requires live.

    identity [--secret <decimal|0xhex> | --secret-file <f>] [--limit <n>] [--out <f>]
        Derive the Rust client's Semaphore-v3 identitySecret and RLN rate-commitment
        leaf natively (no Node.js setup step). Secret fallback order is
        --secret, --secret-file, SHADE_TREE_SECRET, then ./.secret. --out is
        written owner-only; otherwise the identity JSON is printed to stdout. Tier
        precedence is --limit, SHADE_TREE_LIMIT, then bundled staked defaultLimit.
        Requires a --features live build.

    register-member [<commitment> | --identity <identity.json>] [--limit <n>] [--contract <0xaddress>]
                    [--rpc-url <url>] [--key-file <owner-only-file>]
        Stake a public RLN leaf natively, signing the EIP-1559 transaction locally.
        --identity verifies and uses the file's matching public leaf + exact tier,
        keeping its identitySecret local and eliminating a manual leaf handoff.
        Contract, RPC, and --limit default to the bundled live Sepolia staking
        profile (public defaultLimit=1). The funding key comes only from --key-file
        or SHADE_TREE_REGISTER_KEY (never a raw-key argument) and is never sent to
        the RPC. Requires a --features live build.

    member-status --identity <identity.json> [--json]
                  [--contract <0xaddress>] [--rpc-url <url>]
        Report whether the identity's verified public leaf is absent, active, or
        exiting, including its tier, bond, and withdrawal time. Requires live.

    exit-member --identity <identity.json> [--key-file <owner-only-file>]
                [--contract <0xaddress>] [--rpc-url <url>]
        Build a Groth16 proof of identity ownership locally, remove the leaf from
        admission, and begin unbonding. The identity secret never leaves the process.
        A separate gas wallet is allowed. Requires live.

    withdraw-member --identity <identity.json> --recipient <0xaddress>
                    [--key-file <owner-only-file>] [--contract <0xaddress>]
                    [--rpc-url <url>]
        After unbonding, build a fresh local proof bound to the exact recipient and
        reclaim the bond. The sender/gas wallet need not be the funding or recipient
        wallet. Requires live.

    leaves --contract <0xaddress> [--rpc-url <url>] [--from-block <n>]
           [--block-tag latest|finalized] [--out <f>]
        Reconstruct an on-chain StakedReputationSet or PaidAccessSet directly
        from JSON-RPC event logs and emit the ordered, zero-in-place members.json
        consumed by egress. No Node.js exporter is required. Requires live.

    egress [TRANSPORT] --identity <f> --target <host:port>
           [--members <f> | --contract <0xaddress> [--rpc-url <url>]]
           [--circuits <dir>] [--epoch <n>] [--slot <i>] [--slot-cursor <f>]
           [--rln-identifier <n>] [--k <n>] [--nonce <hex>]
        LIVE egress (requires a `--features live` build). Builds a REAL RLN envelope
        in Rust (native depth-20 Poseidon tree + Groth16 proof over the repo's
        circuits) binding <target>, opens a connection to the gateway, sends the
        envelope exactly as client/shade-tree-client.mjs does, and reports accept/reject.
        FAILOVER: the transport yields an ORDERED candidate list; the ONE envelope is
        built once and REUSED across candidates (deterministic-retry parity). On a
        dial failure the client rotates to the next candidate until one accepts; a
        gate REFUSAL is terminal, including payload-limit.
        Choose at most one TRANSPORT; omitting it uses the bundled current v4 Sepolia Elder:
          --directory <f> --signer <hex>  Verify the signed directory (LKG-cached via
                                          --cache), pick the weighted failover ORDER,
                                          and dial each .onion over EMBEDDED TOR (arti;
                                          no system tor daemon, no SOCKS).
                                          Optional: --cache <f> (LKG), --health-cache <f>
                                          (seed + record cross-session liveness),
                                          --max-age-ms <n>.
          --bootnode-onion <onion> --signer <hex>
                                          Fetch /directory from the bootnode onion over
                                          EMBEDDED TOR, verify + LKG-cache it, then select
                                          + failover exactly as --directory. Same optional
                                          --cache/--health-cache/--max-age-ms.
          (none)                          Fetch the signed Canopy from the bundled Elder and verify
                                          it with the signer pinned in the bundled deployment. With
                                          no explicit member source, use that deployment's staked
                                          contract/RPC/deployBlock, 60s epoch, and defaultLimit=1;
                                          every selected gateway must sign the matching caps.rate.
          --onion <a[:p]>[,<a[:p]>...]    Dial these specific .onion(s) over embedded Tor,
                                          in order (default port 80). Comma = failover list.
          --plain-tcp <h:p>[,<h:p>...]    Escape hatch: dial plain TCP, no Tor, in order
                                          (comma = failover list; used by the CI harness).
        DIRECTORY ROTATION defaults to smooth weighted round-robin for the first gateway on every
        new tunnel; the remaining failover order stays weighted-random. Use
        --no-rotation-spread or SHADE_TREE_ROTATION_SPREAD=0 to restore a weighted-random first pick.
        Envelope options:
          --identity  JSON { identitySecret, leaf[, limit] } (the member's derived secret + leaf;
                      create it with Rust `shade-tree enroll`, or derive it from an existing
                      SHADE_TREE_SECRET with Rust `shade-tree identity --out identity.json`;
                      `limit` = the leaf's reputation-tier userMessageLimit, T-FEAT-8)
          --members   JSON { members: [leaf,...] } (the ordered group, same as the gateway).
          --contract  Discover the ordered group natively from on-chain events. For
                      --leaf-source demo, omission uses the validated directory demo.contract;
                      staked/paid may use SHADE_TREE_GROUP_CONTRACT / PAID_ACCESS_CONTRACT.
          --target    host:port bound into the proof (the egress destination)
          --circuits  OPTIONAL dir with rln.wasm + rln_final.zkey + verification_key.json;
                      omit it to use the artifacts EMBEDDED in this binary (self-contained,
                      no external circuit files — T-RUST-4). Embedded artifacts are hash-
                      checked at startup against the embedded zk-artifacts lock (T-HARD-8):
                      any drift is a hard, named error. The set's content-derived artifact
                      id (rln-<sha256(vkey)[0:16]>) is stamped into the envelope's `artifact`
                      field; if the selected gateway advertises accepted artifact ids
                      (signed caps.artifacts) that exclude ours, egress fails closed with
                      `no-mutual-artifact:...` BEFORE proving.
          --epoch     epoch to prove for (default: floor(now/60s) on the bundled public profile;
                      explicit SHADE_TREE_EPOCH_SECONDS wins but must match signed caps.rate;
                      custom discovery keeps the historical 120s fallback)
          --k         userMessageLimit / tier (explicit flag/env, then identity `limit`, then
                      bundled public defaultLimit=1; custom discovery keeps fallback 8;
                      must be the leaf's enrolled limit)
          --slot-cursor  exact state-file override (or SHADE_TREE_SLOT_CURSOR). Persistence is
                      default-on under SHADE_TREE_SLOT_STATE_DIR / XDG_STATE_HOME / ~/.local/state,
                      namespaced by the public member leaf. JS and Rust processes atomically
                      share it, stop at K, and reset only when the epoch advances.
          --unsafe-allow-slot-reuse-for-slashing-tests --slot <i>
                      bypass persistent allocation ONLY for an isolated slashing test; never
                      use with a funded/live member secret
          --rln-identifier  group id (default 1)     --nonce  32-hex per-request nonce
        Without the feature: prints an honest not-built error.

    proxy [EGRESS OPTIONS] [--listen 127.0.0.1:8118] [--once]
        Agent-facing local HTTP CONNECT proxy. CONNECT tunnels share one long-lived
        embedded Arti bootstrap with isolated per-tunnel circuit groups and a bounded
        proving/connection pool. The Proxy requires an unpredictable 32+ character
        token (prefer SHADE_TREE_PROXY_TOKEN), returns 200 only after gateway
        acceptance, and relays application bytes in both directions. Requires live.

    run [--proxy URL] [--no-proxy HOSTS]
        [--check-timeout-ms N] -- <command> [args]
        Refuse to start the command unless the local Proxy is accepting, then inject
        authenticated process-scoped HTTP(S)/WSS proxy variables into that child only.
        Member/operator SHADE_TREE_* credentials are stripped from the child.

    help, --help, -h        Show this help.
    version, --version, -V  Show the version.

NOTES:
    The trust-critical checks come from the shade-tree-proto crate (a Rust port of the
    JS reference, gated byte-for-byte by testdata/vectors.json). This binary parses
    untrusted JSON and calls those checks. Live network I/O (the RLN prover and the
    embedded-Tor onion dial) is compiled only under `--features live`.
    See docs/adr/0001-client-language.md.";

/// T-FEAT-9: `--leaf-source invited|staked|paid` + `--max-anon` (or SHADE_TREE_LEAF_SOURCE /
/// SHADE_TREE_MAX_ANON=1). `--max-anon` with a staked/paid leaf source is refused up front (an
/// invited-only gateway would reject that proof with wrong-group-root) — see the JS client.
fn admission_from_args(args: &[String]) -> capability::Admission {
    let env_src = std::env::var("SHADE_TREE_LEAF_SOURCE")
        .ok()
        .filter(|s| !s.trim().is_empty() && s.trim() != "auto");
    let leaf_source = take_flag(args, "--leaf-source")
        .or(env_src)
        .map(|s| s.trim().to_ascii_lowercase());
    let env_max = matches!(
        std::env::var("SHADE_TREE_MAX_ANON")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );
    let max_anon = args.iter().any(|a| a == "--max-anon") || env_max;
    capability::Admission {
        leaf_source,
        max_anon,
    }
}

fn admission_refusal(
    adm: &capability::Admission,
    before: &[shade_tree_proto::GatewayEntry],
) -> String {
    if adm.max_anon {
        if adm.leaf_source.as_deref() == Some("demo") {
            return "--max-anon: your leaf is in the demo set; demo admission is linked to the one-shot access request. Max-anon requires an invited (members.json) leaf -- drop --max-anon to use a demo gateway.".to_string();
        }
        return format!(
            "--max-anon: no invited-only gateway in the directory (a gateway qualifies only when its signed caps say admits=[invited]); fleet: {}",
            capability::describe_fleet_admits(before)
        );
    }
    format!(
        "no gateway admits a {} leaf (your leaf source); fleet: {} -- pick a gateway that admits it, or obtain a leaf in a set the fleet admits (docs/CLIENTS.md \"Leaf source\")",
        adm.leaf_source.as_deref().unwrap_or("?"),
        capability::describe_fleet_admits(before)
    )
}

/// Validate the admission inputs before any dial (a bad name or max-anon over a staked/paid
/// leaf is a precise refusal, never a wasted proof).
fn check_admission(adm: &capability::Admission) -> Result<(), String> {
    if let Some(src) = &adm.leaf_source {
        if src != "demo" && !shade_tree_proto::ADMIT_PATHS.contains(&src.as_str()) {
            return Err(format!(
                "--leaf-source: expected invited, staked, paid or demo (got {src})"
            ));
        }
        if adm.max_anon && src == "demo" {
            return Err("--max-anon: your leaf is in the demo set; demo admission is linked to the one-shot access request. Max-anon requires an invited (members.json) leaf -- drop --max-anon to use a demo gateway.".to_string());
        }
        if adm.max_anon && src != "invited" {
            return Err(format!("--max-anon: your leaf is in the {src} set; an invited-only gateway would reject it (wrong-group-root). Max-anon requires an invited (members.json) leaf -- drop --max-anon to use gateways that admit {src}."));
        }
    }
    Ok(())
}

/// Extract `--flag <value>` from args, returning the value and the remaining args.
fn take_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

fn signer_spec(args: &[String]) -> Option<String> {
    take_flag(args, "--signers").or_else(|| take_flag(args, "--signer"))
}

fn cmd_verify_directory(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("verify-directory: missing <file>\n\n{HELP}");
        return ExitCode::from(2);
    };
    let Some(signer) = signer_spec(args) else {
        eprintln!("verify-directory: missing --signer <hex[,hex...]> (or --signers)");
        return ExitCode::from(2);
    };
    let raw = match read_file(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match dircache::parse_and_verify_document(&raw, &signer) {
        Ok(document) => {
            println!("ok");
            if document.dir.threshold.is_some() {
                println!("threshold: {}", document.dir.threshold.unwrap_or_default());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_select(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("select: missing <dir-file>\n\n{HELP}");
        return ExitCode::from(2);
    };
    let Some(signer) = signer_spec(args) else {
        eprintln!("select: missing --signer <hex[,hex...]> (or --signers)");
        return ExitCode::from(2);
    };
    let seed = take_flag(args, "--seed")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(default_seed);

    let raw = match read_file(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let document = match dircache::parse_and_verify_document(&raw, &signer) {
        Ok(d) => d,
        Err(e) => {
            println!("not-ok: {e}");
            return ExitCode::from(1);
        }
    };
    let demo = document.demo;
    let mut dir = document.dir;

    // Cross-session gateway deprioritization (T-RUST-3, reportResult parity): when a
    // --health-cache is given, seed each gateway's health from the persisted liveness
    // written by past `egress` failover feedback, so a gateway that failed enough last
    // session starts `health:"down"` and is deprioritized (decay-pruned if long-idle).
    // Absent the flag, selection is byte-identical to before.
    if let Some(hc) = take_flag(args, "--health-cache") {
        let path = std::path::PathBuf::from(hc);
        let mut cache = health::load(Some(&path));
        health::seed(&mut dir, &mut cache, now_ms());
    }

    // Opt-in capability-aware filter (T-FEAT-10c). --port/--proto/--region form a
    // capability requirement; only gateways whose SIGNED caps meet it survive (a no-caps
    // gateway meets only the conservative 443/v4 floor). Absent all three => INACTIVE =>
    // byte-identical selection. Active but no gateway qualifies => FAIL CLOSED (never
    // dial an incapable gateway). Mirrors selectCandidates(req) in client/selection.mjs.
    let req = capability::Requirement {
        port: take_flag(args, "--port").and_then(|s| s.parse::<u64>().ok()),
        proto: take_flag(args, "--proto").and_then(|s| s.parse::<u64>().ok()),
        region: take_flag(args, "--region"),
    };
    if req.is_active() {
        capability::filter_by_capability(&mut dir.gateways, &req);
        if dir.gateways.is_empty() {
            println!(
                "not-ok: no gateway meets capability requirement: {}",
                req.describe()
            );
            return ExitCode::from(1);
        }
    }
    // Admission-aware filter (T-FEAT-9). --leaf-source names the set the member's leaf is in;
    // only gateways whose SIGNED caps.admits include it survive (no policy advertised = kept,
    // rollout compat). --max-anon keeps ONLY invited-only gateways. Absent both => byte-identical.
    let adm = admission_from_args(args);
    if let Err(e) = check_admission(&adm) {
        println!("not-ok: {e}");
        return ExitCode::from(1);
    }
    if adm.is_active() {
        let before = dir.gateways.clone();
        capability::filter_by_admission_with_demo(
            &mut dir.gateways,
            &adm,
            demo.as_ref().map(|d| d.gateways.as_slice()),
        );
        if dir.gateways.is_empty() {
            println!("not-ok: {}", admission_refusal(&adm, &before));
            return ExitCode::from(1);
        }
    }

    let mut rng = mulberry32(seed);
    let empty = HashSet::new();
    let Some(chosen) = pick_gateway(&dir, &empty, &mut rng) else {
        println!("not-ok: no-gateways");
        return ExitCode::from(1);
    };
    println!("ok");
    println!("chosen: {}", chosen.onion);
    // Fresh rng from the same seed so the printed order starts with the same weighted pick.
    let mut rng2 = mulberry32(seed);
    let order = selection_order(&dir, &mut rng2);
    println!("failover-order:");
    for (i, g) in order.iter().enumerate() {
        println!("  {}. {}", i + 1, g.onion);
    }
    ExitCode::SUCCESS
}

fn cmd_verify_receipt(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("verify-receipt: missing <receipt-file>\n\n{HELP}");
        return ExitCode::from(2);
    };
    let Some(onion) = take_flag(args, "--onion") else {
        eprintln!("verify-receipt: missing --onion <onion>");
        return ExitCode::from(2);
    };
    let raw = match read_file(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let dto: ReceiptDto = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            println!("not-ok: parse: {e}");
            return ExitCode::from(1);
        }
    };
    // Bind to the dialed onion; skip the epoch-freshness check (a CLI has no live epoch —
    // it verifies the onion<->pubkey binding + signature, matching a client verifying an
    // offline/archived receipt).
    match verify_receipt(&dto.into_proto(), Some(&onion), None, 1) {
        Ok(v) => {
            println!("ok");
            println!("onion: {}", v.onion);
            println!("pubkey: {}", hex::encode(v.pubkey));
            println!("epoch: {}", v.epoch);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(feature = "live")]
fn identity_creation_limit_setting(
    flag: Option<&str>,
    env: Option<&str>,
    bundled_default: u64,
) -> Result<u64, String> {
    let raw = flag.or(env);
    let limit = match raw {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| "limit must be an integer".to_string())?,
        None => bundled_default,
    };
    if !(1..=u16::MAX as u64).contains(&limit) {
        return Err(format!("limit must be in 1..={}", u16::MAX));
    }
    Ok(limit)
}

fn cmd_identity(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        use serde::Serialize;
        use std::io::Write;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IdentityOutput<'a> {
            identity_secret: &'a str,
            leaf: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            limit: Option<u64>,
        }

        let (secret, source) = if let Some(secret) = take_flag(args, "--secret") {
            (secret, "--secret".to_string())
        } else if let Some(path) = take_flag(args, "--secret-file") {
            match read_file(&path) {
                Ok(secret) => (secret.trim().to_string(), format!("--secret-file {path}")),
                Err(e) => {
                    eprintln!("identity: {e}");
                    return ExitCode::from(2);
                }
            }
        } else if let Ok(secret) = std::env::var("SHADE_TREE_SECRET") {
            (secret, "SHADE_TREE_SECRET".to_string())
        } else {
            match read_file(".secret") {
                Ok(secret) => (secret.trim().to_string(), "./.secret".to_string()),
                Err(_) => {
                    eprintln!("identity: no secret; pass --secret/--secret-file, set SHADE_TREE_SECRET, or create ./.secret");
                    return ExitCode::from(2);
                }
            }
        };
        let limit_flag = take_flag(args, "--limit");
        let limit_env = std::env::var("SHADE_TREE_LIMIT").ok();
        let bundled_limit = match default_staked_limit() {
            Ok(limit) => limit,
            Err(error) => {
                eprintln!("identity: {error}");
                return ExitCode::from(2);
            }
        };
        let limit = match identity_creation_limit_setting(
            limit_flag.as_deref(),
            limit_env.as_deref(),
            bundled_limit,
        ) {
            Ok(limit) => limit,
            Err(error) => {
                eprintln!("identity: {error}");
                return ExitCode::from(2);
            }
        };
        let material = match shade_tree_rln::identity::derive_identity(&secret, limit) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("identity: {e}");
                return ExitCode::from(2);
            }
        };
        let output = IdentityOutput {
            identity_secret: &material.identity_secret,
            leaf: &material.leaf,
            // Always persist the tier: the same identity can later be used with
            // either the bundled limit-1 profile or a custom limit-8 Grove.
            limit: Some(limit),
        };
        let mut body = serde_json::to_string_pretty(&output).expect("serialize identity");
        body.push('\n');
        if let Some(path) = take_flag(args, "--out") {
            #[cfg(unix)]
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut options = std::fs::OpenOptions::new();
            options.create(true).write(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("identity: write {path}: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Err(e) = file.write_all(body.as_bytes()) {
                eprintln!("identity: write {path}: {e}");
                return ExitCode::from(2);
            }
            #[cfg(unix)]
            if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            {
                eprintln!("identity: chmod {path}: {e}");
                return ExitCode::from(2);
            }
            eprintln!(
                "shade-tree identity — {source}; public leaf {}; wrote {path}",
                material.leaf
            );
        } else {
            print!("{body}");
            eprintln!(
                "shade-tree identity — {source}; public leaf {}",
                material.leaf
            );
        }
        ExitCode::SUCCESS
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("identity: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_enroll(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        enroll::cmd_enroll(args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("enroll: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_register_member(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        register::cmd_register_member(args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("register-member: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_member(action: &str, args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        let action = match action {
            "member-status" => member::Action::Status,
            "exit-member" => member::Action::Exit,
            "withdraw-member" => member::Action::Withdraw,
            _ => unreachable!(),
        };
        member::cmd_member(action, args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = (action, args);
        eprintln!("{action}: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_proxy_token(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        enroll::cmd_proxy_token(args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("proxy-token: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_leaves(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        let contract = take_flag(args, "--contract")
            .or_else(|| std::env::var("SHADE_TREE_PAID_ACCESS_CONTRACT").ok())
            .or_else(|| {
                std::env::var("SHADE_TREE_GROUP_CONTRACT")
                    .ok()
                    .and_then(|v| v.split(',').next().map(str::trim).map(str::to_string))
            });
        let Some(contract) = contract.filter(|s| !s.is_empty()) else {
            eprintln!("leaves: no contract; pass --contract or set SHADE_TREE_GROUP_CONTRACT/SHADE_TREE_PAID_ACCESS_CONTRACT");
            return ExitCode::from(2);
        };
        let rpc_url = take_flag(args, "--rpc-url")
            .or_else(|| std::env::var("SHADE_TREE_RPC_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
        let from = take_flag(args, "--from-block")
            .or_else(|| std::env::var("SHADE_TREE_FROM_BLOCK").ok())
            .unwrap_or_else(|| "0".to_string());
        let from_block = if let Some(hex) = from.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            from.parse::<u64>()
        };
        let Ok(from_block) = from_block else {
            eprintln!("leaves: invalid --from-block {from:?}");
            return ExitCode::from(2);
        };
        let block_tag = take_flag(args, "--block-tag").unwrap_or_else(|| "latest".to_string());
        let rln_identifier = take_flag(args, "--rln-identifier")
            .or_else(|| std::env::var("SHADE_TREE_RLN_IDENTIFIER").ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1);
        let discovered = match leaves::fetch_members(
            &rpc_url,
            &contract,
            from_block,
            &block_tag,
            rln_identifier,
        ) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("leaves: {e}");
                return ExitCode::from(1);
            }
        };
        let mut body =
            serde_json::to_string_pretty(&discovered.document).expect("serialize members document");
        body.push('\n');
        if let Some(path) = take_flag(args, "--out") {
            if let Err(e) = std::fs::write(&path, &body) {
                eprintln!("leaves: write {path}: {e}");
                return ExitCode::from(2);
            }
            eprintln!(
                "shade-tree leaves — {contract}: {} live leaves in {} slots; root {}; wrote {path}",
                discovered.live_count,
                discovered.document.members.len(),
                discovered.root
            );
        } else {
            print!("{body}");
            eprintln!(
                "shade-tree leaves — {contract}: {} live leaves in {} slots; root {}",
                discovered.live_count,
                discovered.document.members.len(),
                discovered.root
            );
        }
        ExitCode::SUCCESS
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("leaves: requires a --features live build");
        ExitCode::from(3)
    }
}

fn cmd_egress(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        live::run_egress(args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        match live_egress() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("not-implemented: {e}");
                ExitCode::from(3)
            }
        }
    }
}

fn cmd_proxy(args: &[String]) -> ExitCode {
    #[cfg(feature = "live")]
    {
        live::run_proxy(args)
    }
    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        eprintln!("proxy: requires a --features live build");
        ExitCode::from(3)
    }
}

// --------------------------------------------------------------------------
// LIVE egress implementation (feature = "live"): RLN prover + native tree +
// transport (embedded Tor via arti, or plain-TCP escape hatch). T-RUST-2d/2e.
// --------------------------------------------------------------------------
//
// The wire framing here is byte-matched to the JS reference so the real JS gateway
// (gateway/gateway.mjs) accepts the Rust envelope, IDENTICALLY over both transports:
//   - SEND: `JSON.stringify(envelope) + "\n"` — client/shade-tree-client.mjs:313,341.
//     envelope = { v, target, nonce, proof, nullifier, externalNullifier, share }
//     (buildEnvelope, client/shade-tree-client.mjs:123); the nested `proof` is the wire-safe
//     RLNFullProof { snarkProof:{proof,publicSignals}, epoch, rlnIdentifier } assembled
//     exactly as rust/shade-tree-rln/interop/verify-envelope.mjs:13-25.
//   - RECV: the gateway replies `JSON.stringify(ack) + "\n"` (gateway.mjs reply(),
//     :333-335; successAck `{ ok: true }` at :594) once verifyEnvelope passes, the target
//     policy admits, the spent-set admits, and the upstream :target connects. So `ok:true`
//     is a full end-to-end ACCEPT (version gate + Groth16 verify + proxy established).
//
// TRANSPORT (T-RUST-2e): `--directory/--signer` (or `--onion`) dials the gateway's `.onion`
// over EMBEDDED TOR — arti bootstraps its own Tor client (no system tor daemon, no SOCKS)
// and `TorClient::connect((onion, 80))` opens an anonymous stream to the gateway HS virtual
// port 80 (bootstrap.sh: `HiddenServicePort 80 127.0.0.1:8443`), matching the JS client's
// `destination: { host: onion+".onion", port: 80 }` (client/shade-tree-client.mjs:271). The
// `--plain-tcp <host:port>` escape hatch keeps the loop-22 plain-socket path (the CI
// harness egress-run.sh uses it) so the always-green Layer-3 accept is unaffected.
#[cfg(feature = "live")]
mod live {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::Deserialize;
    use shade_tree_proto::{selection_order, spread_selection_order, SmoothWeightedState};

    use super::{
        admission_from_args, admission_refusal, capability, check_admission, default_discovery,
        default_public_profile, default_seed, dircache, health, mulberry32, now_ms, parse_max_age,
        read_file, signer_spec, take_flag, PublicStakedProfile,
    };

    /// One dial target in the failover order. Plain-TCP is the loop-22 escape hatch;
    /// Onion is the default T-RUST-2e path (dialed over embedded Tor).
    enum Transport {
        /// `--plain-tcp <host:port>` — dial plain TCP, no Tor (the CI-harness / socket path).
        PlainTcp(String),
        /// `--onion <addr>`, a directory selection, or bootnode discovery — dial
        /// `<onion>.onion:<port>` over embedded Tor. `artifacts` is the gateway's SIGNED
        /// accepted-ZK-artifact ad (`caps.artifacts`, T-HARD-8) when it came from a verified
        /// directory entry that advertises one; `None` = unknown (no ad / explicit --onion).
        Onion {
            onion: String,
            port: u16,
            artifacts: Option<Vec<String>>,
        },
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RelayMode {
        None,
        Stdio,
        ProxyResponse,
    }

    impl RelayMode {
        fn from_args(args: &[String]) -> Self {
            if args.iter().any(|arg| arg == "--proxy-response") {
                Self::ProxyResponse
            } else if args.iter().any(|arg| arg == "--stdio") {
                Self::Stdio
            } else {
                Self::None
            }
        }
    }

    impl Transport {
        /// Human-readable dial label (printed on success + used as the health-cache key
        /// for onion transports).
        fn label(&self) -> String {
            match self {
                Transport::PlainTcp(hp) => hp.clone(),
                Transport::Onion { onion, port, .. } => format!("{onion}.onion:{port}"),
            }
        }
        /// The onion (with suffix) this transport reports liveness for, or `None` for a
        /// plain-TCP dial (which is never a signed-directory gateway).
        fn health_onion(&self) -> Option<String> {
            match self {
                Transport::Onion { onion, .. } => Some(format!("{onion}.onion")),
                Transport::PlainTcp(_) => None,
            }
        }

        fn gateway(&self) -> shade_tree_egress::Gateway {
            match self {
                Transport::PlainTcp(address) => shade_tree_egress::Gateway::PlainTcp {
                    address: address.clone(),
                },
                Transport::Onion { onion, port, .. } => shade_tree_egress::Gateway::Onion {
                    onion: onion.clone(),
                    port: *port,
                },
            }
        }
    }

    /// Cross-session liveness feedback context (only set for the directory / bootnode
    /// paths, where the candidate onions come from a SIGNED directory). Mirrors
    /// `selection.mjs` reportResult: after each dial we fold the outcome into the local
    /// health cache so a failing gateway starts deprioritized next session.
    struct HealthCtx {
        cache_path: PathBuf,
        known: HashSet<String>,
        cache: health::HealthCache,
    }

    type DirectoryCandidates = (
        Vec<Transport>,
        Option<HealthCtx>,
        Option<dircache::DemoAdvert>,
    );

    /// The full egress plan: the ordered candidates + optional health feedback.
    struct EgressPlan {
        transports: Vec<Transport>,
        health: Option<HealthCtx>,
        demo: Option<dircache::DemoAdvert>,
        /// Present only for the zero-configuration bundled public path. Any
        /// explicit transport/member contract/leaf source keeps legacy custom
        /// discovery defaults instead. An RPC-only override retains this profile.
        profile: Option<PublicStakedProfile>,
    }

    #[derive(Deserialize)]
    struct IdentityFile {
        #[serde(rename = "identitySecret")]
        identity_secret: String,
        leaf: String,
        /// Optional tier limit (T-FEAT-8): the `userMessageLimit` this leaf was enrolled
        /// with. `shade-tree identity` writes it only for a non-default tier; absent uses the
        /// bundled public defaultLimit on the zero-config path, otherwise K_SLOTS.
        #[serde(default)]
        limit: Option<u64>,
    }

    #[derive(Deserialize)]
    struct MembersFile {
        members: Vec<String>,
    }

    fn epoch_seconds_setting(env: Option<&str>, profile: Option<&PublicStakedProfile>) -> u64 {
        env.and_then(|s| s.parse().ok())
            .filter(|&n: &u64| n > 0)
            .or_else(|| profile.map(|profile| profile.rate_policy.epoch_seconds))
            .unwrap_or(120)
    }

    // Custom discovery retains the historical 120-second fallback. The zero-config bundled
    // profile takes its signed 60-second window from deployment metadata; an explicit env wins.
    fn epoch_seconds(profile: Option<&PublicStakedProfile>) -> u64 {
        epoch_seconds_setting(
            std::env::var("SHADE_TREE_EPOCH_SECONDS").ok().as_deref(),
            profile,
        )
    }

    fn current_epoch(epoch_seconds: u64) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now / epoch_seconds
    }

    fn member_limit_setting(
        flag: Option<&str>,
        env: Option<&str>,
        identity: Option<u64>,
        profile: Option<&PublicStakedProfile>,
    ) -> Result<u64, String> {
        let raw = flag
            .map(str::to_string)
            .or_else(|| env.map(str::to_string))
            .or_else(|| identity.map(|limit| limit.to_string()))
            .or_else(|| profile.map(|profile| profile.default_limit.to_string()));
        match raw {
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| format!("member limit must be an integer (got {value:?})")),
            None => Ok(shade_tree_egress::slot::DEFAULT_LIMIT),
        }
    }

    fn egress_block_tag_setting(flag: Option<&str>, public_profile: bool) -> String {
        flag.map(str::to_string).unwrap_or_else(|| {
            if public_profile {
                "finalized".into()
            } else {
                "latest".into()
            }
        })
    }

    // Exact override first; otherwise use the JS-compatible default under the public leaf.
    // Empty/off is rejected: only the explicit slashing-test flag below can bypass safety.
    fn slot_cursor_path(
        rest: &[String],
        leaf: &str,
    ) -> Result<PathBuf, shade_tree_egress::slot::Error> {
        if let Some(f) = take_flag(rest, "--slot-cursor") {
            let f = f.trim();
            if f.is_empty() || f == "0" || f.eq_ignore_ascii_case("off") {
                return Err(shade_tree_egress::slot::Error::Unavailable(
                    "--slot-cursor cannot disable safety".into(),
                ));
            }
            return Ok(PathBuf::from(f));
        }
        if let Ok(v) = std::env::var("SHADE_TREE_SLOT_CURSOR") {
            let v = v.trim();
            if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("off") {
                return Err(shade_tree_egress::slot::Error::Unavailable(
                    "SHADE_TREE_SLOT_CURSOR cannot disable safety".into(),
                ));
            }
            return Ok(PathBuf::from(v));
        }
        shade_tree_egress::slot::default_path(leaf)
    }

    // Per-step embedded-Tor timeout (bootstrap + connect each), SHADE_TREE_TOR_TIMEOUT_SECS.
    fn tor_timeout_secs() -> u64 {
        std::env::var("SHADE_TREE_TOR_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &u64| n > 0)
            .unwrap_or(180)
    }

    fn gateway_ack_timeout_secs() -> u64 {
        std::env::var("SHADE_TREE_GATEWAY_ACK_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &u64| n > 0)
            .unwrap_or(15)
    }

    // A 16-byte random nonce -> 32 hex chars, matching client/shade-tree-client.mjs
    // `randomBytes(16).toString("hex")`. No `rand` runtime dep: splitmix64 over a
    // clock+pid seed is ample for a per-request nonce (uniqueness, not secrecy). A
    // `--nonce` flag overrides it for reproducible runs.
    fn gen_nonce() -> String {
        let mut seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ (u64::from(std::process::id())).rotate_left(32);
        let mut out = [0u8; 16];
        for chunk in out.chunks_mut(8) {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        hex::encode(out)
    }

    fn load_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
        let raw = read_file(path)?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    static ROTATION_STATE: OnceLock<Mutex<SmoothWeightedState>> = OnceLock::new();

    fn parse_rotation_value(raw: &str) -> Option<bool> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    fn rotation_spread_setting(args: &[String], env: Option<&str>) -> bool {
        if args.iter().any(|arg| arg == "--no-rotation-spread") {
            return false;
        }
        if let Some(raw) = args
            .iter()
            .find_map(|arg| arg.strip_prefix("--rotation-spread="))
        {
            return parse_rotation_value(raw).unwrap_or(true);
        }
        if let Some(index) = args.iter().position(|arg| arg == "--rotation-spread") {
            return args
                .get(index + 1)
                .and_then(|raw| parse_rotation_value(raw))
                .unwrap_or(true);
        }
        env.and_then(parse_rotation_value).unwrap_or(true)
    }

    fn rotation_spread_enabled(args: &[String]) -> bool {
        rotation_spread_setting(
            args,
            std::env::var("SHADE_TREE_ROTATION_SPREAD").ok().as_deref(),
        )
    }

    fn has_value_flag(args: &[String], names: &[&str]) -> bool {
        args.iter().any(|arg| {
            names
                .iter()
                .any(|name| arg == name || arg.starts_with(&format!("{name}=")))
        })
    }

    fn use_bundled_public_profile_setting(
        args: &[String],
        group_contract: Option<&str>,
        paid_contract: Option<&str>,
        _rpc_url: Option<&str>,
        leaf_source: Option<&str>,
    ) -> bool {
        let nonempty = |value: Option<&str>| value.is_some_and(|value| !value.trim().is_empty());
        // An RPC override changes only the route to the same bundled contract. It
        // intentionally does not discard the contract, tier, admission path, epoch,
        // or signed rate policy. Contract/member/path inputs do select a custom Grove.
        !has_value_flag(args, &["--members", "--contract", "--leaf-source"])
            && !nonempty(group_contract)
            && !nonempty(paid_contract)
            && !nonempty(leaf_source)
    }

    fn use_bundled_public_profile(args: &[String]) -> bool {
        let group_contract = std::env::var("SHADE_TREE_GROUP_CONTRACT").ok();
        let paid_contract = std::env::var("SHADE_TREE_PAID_ACCESS_CONTRACT").ok();
        let rpc_url = std::env::var("SHADE_TREE_RPC_URL").ok();
        let leaf_source = std::env::var("SHADE_TREE_LEAF_SOURCE").ok();
        use_bundled_public_profile_setting(
            args,
            group_contract.as_deref(),
            paid_contract.as_deref(),
            rpc_url.as_deref(),
            leaf_source.as_deref(),
        )
    }

    fn filter_public_gateway_rates(
        gateways: &mut Vec<shade_tree_proto::GatewayEntry>,
        expected: &shade_tree_proto::CanonicalRate,
    ) -> usize {
        let before = gateways.len();
        gateways.retain(|gateway| {
            gateway
                .caps
                .as_ref()
                .and_then(|caps| shade_tree_proto::canonical_caps(caps).rate)
                .is_some_and(|actual| actual == *expected)
        });
        before - gateways.len()
    }

    // Turn a FRESH directory (a file read, or a bootnode fetch over Tor) into the ordered
    // onion candidate list for failover — the SAME LKG-cache + guards + weighted
    // selection_order the JS client runs (selection.mjs ensureLoaded -> selectCandidates):
    //   1. dircache::resolve_directory verifies the fresh directory against the pinned
    //      signer, applies the rollback + optional max-age guards vs the LKG --cache, and
    //      writes the cache — or falls back to the verified LKG cache when fresh fails
    //      (never an unverified list).
    //   2. When a --health-cache is given, seed each gateway's health from persisted
    //      cross-session liveness so a gateway that failed last session starts deprioritized.
    //   3. Smooth weighted round-robin chooses the first gateway by default on each new tunnel;
    //      the existing weighted-random selection_order fills the failover tail. An explicit
    //      --no-rotation-spread / SHADE_TREE_ROTATION_SPREAD=0 restores the old full ordering.
    // Returns the candidate transports + the health feedback context (recorded after each
    // dial so this session's failures deprioritize the gateway next session).
    fn directory_candidates(
        fresh: Result<String, String>,
        rest: &[String],
        signer: &str,
        public_profile: Option<&PublicStakedProfile>,
    ) -> Result<DirectoryCandidates, String> {
        let cache_path = take_flag(rest, "--cache").map(PathBuf::from);
        let max_age = parse_max_age(rest);
        let out =
            dircache::resolve_directory(fresh, cache_path.as_deref(), signer, max_age, now_ms())?;
        if out.source == dircache::Source::Cache {
            eprintln!(
                "egress: using last-known-good directory cache ({})",
                out.fresh_error.as_deref().unwrap_or("fresh unavailable")
            );
        }
        let demo = out.demo;
        let mut dir = out.dir;

        // Cross-session deprioritization (reportResult parity): seed health, keep the cache
        // + known-onion set for post-dial feedback.
        let health_ctx = if let Some(hc) = take_flag(rest, "--health-cache") {
            let path = PathBuf::from(hc);
            let mut cache = health::load(Some(&path));
            health::seed(&mut dir, &mut cache, now_ms());
            let known: HashSet<String> = dir.gateways.iter().map(|g| g.onion.clone()).collect();
            Some(HealthCtx {
                cache_path: path,
                known,
                cache,
            })
        } else {
            None
        };

        // Admission-aware filter (T-FEAT-9): route only to gateways whose signed policy admits
        // this member's leaf source (--leaf-source / SHADE_TREE_LEAF_SOURCE), --max-anon = invited-only.
        let mut adm = admission_from_args(rest);
        if adm.leaf_source.is_none() {
            adm.leaf_source = public_profile.map(|profile| profile.default_path.clone());
        }
        check_admission(&adm)?;
        if adm.is_active() {
            let before = dir.gateways.clone();
            capability::filter_by_admission_with_demo(
                &mut dir.gateways,
                &adm,
                demo.as_ref().map(|d| d.gateways.as_slice()),
            );
            if dir.gateways.is_empty() {
                return Err(admission_refusal(&adm, &before));
            }
            eprintln!(
                "egress: admission filter ({}) kept {} of {} gateway(s)",
                adm.describe(),
                dir.gateways.len(),
                before.len()
            );
        }
        // The zero-config public profile is useful only if the same policy is signed by every
        // gateway we may dial. Missing/mismatched caps fail here, before identity loading, slot
        // allocation, or proof construction. Custom discovery retains rollout compatibility.
        if let Some(profile) = public_profile {
            let before = dir.gateways.len();
            let removed = filter_public_gateway_rates(&mut dir.gateways, &profile.rate_policy);
            if dir.gateways.is_empty() {
                return Err(format!(
                    "public-profile-rate-unavailable: none of {before} admitted gateway(s) signs the bundled ratePolicy"
                ));
            }
            if removed > 0 {
                eprintln!(
                    "egress: public rate filter kept {} of {} gateway(s)",
                    dir.gateways.len(),
                    before
                );
            }
        }
        let mut rng = mulberry32(default_seed());
        let order = if rotation_spread_enabled(rest) {
            let mutex = ROTATION_STATE.get_or_init(|| Mutex::new(SmoothWeightedState::default()));
            let mut state = mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            spread_selection_order(&dir, &mut state, &mut rng)
        } else {
            selection_order(&dir, &mut rng)
        };
        if order.is_empty() {
            return Err("no gateways in directory".into());
        }
        let mut transports = Vec::with_capacity(order.len());
        for g in &order {
            let (onion, _) = parse_onion_addr(&g.onion, 80)?;
            // Carry the gateway's signed accepted-artifact ad (already capsSig-verified by
            // verify_directory) so the artifact pick happens BEFORE proving (T-HARD-8).
            let artifacts = g
                .caps
                .as_ref()
                .and_then(|c| shade_tree_proto::canonical_caps(c).artifacts);
            transports.push(Transport::Onion {
                onion,
                port: 80,
                artifacts,
            });
        }
        eprintln!(
            "egress: {} candidate gateway(s) from verified directory; first = {}",
            transports.len(),
            transports[0].label()
        );
        Ok((transports, health_ctx, demo))
    }

    // Fetch GET /directory from the bootnode onion over EMBEDDED TOR (arti), returning the
    // raw JSON body — the dynamic-fleet source (loadFromBootnode, selection.mjs). The body is
    // then handed to directory_candidates, which VERIFIES it against the pinned signer before
    // anything is used, so a lying/MITM'd bootnode cannot forge an entry. Speaks minimal
    // HTTP/1.1 over the Tor stream (dircache::http_get_request / parse_http_body), exactly
    // like bootnode/fetch.mjs does over its SOCKS tunnel.
    fn fetch_directory_over_tor(
        bootnode_onion: &str,
        client: &shade_tree_egress::Client,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (onion, port) = parse_onion_addr(bootnode_onion, 80)?;
        let host = format!("{onion}.onion");
        let timeout_secs = tor_timeout_secs();
        let timeout = Duration::from_secs(timeout_secs);
        runtime.block_on(async move {
            tokio::time::timeout(timeout, async move {
                eprintln!("egress: fetching /directory from {host}:{port} over Tor ...");
                let gateway = shade_tree_egress::Gateway::Onion { onion, port };
                let mut stream = client
                    .open(&gateway)
                    .await
                    .map_err(|e| format!("connect bootnode {host}:{port}: {e}"))?;

                let req = dircache::http_get_request(&host, "/directory");
                stream
                    .write_all(req.as_bytes())
                    .await
                    .map_err(|e| format!("write request: {e}"))?;
                stream.flush().await.map_err(|e| format!("flush: {e}"))?;

                let mut buf: Vec<u8> = Vec::with_capacity(4096);
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream
                        .read(&mut chunk)
                        .await
                        .map_err(|e| format!("read response: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > dircache::MAX_HTTP_RESP {
                        return Err(format!(
                            "bootnode response exceeded {} bytes",
                            dircache::MAX_HTTP_RESP
                        ));
                    }
                }
                dircache::parse_http_body(&buf)
            })
            .await
            .map_err(|_| format!("bootnode HTTP exchange timed out after {timeout_secs}s"))?
        })
    }

    // Parse `<addr[:port]>` into (onion-without-suffix, port). Default port 80 = the gateway
    // HS virtual port. The `.onion` suffix is normalized off here and re-added at dial time,
    // exactly like the JS client (client/shade-tree-client.mjs:221,271).
    fn parse_onion_addr(addr: &str, default_port: u16) -> Result<(String, u16), String> {
        let (host, port) = match addr.rsplit_once(':') {
            // Only treat a trailing `:NNN` as a port if it parses as one; otherwise the whole
            // string is the host (an .onion never contains a colon).
            Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse::<u16>().unwrap()),
            _ => (addr, default_port),
        };
        let onion = host.trim_end_matches(".onion").to_string();
        if onion.is_empty() {
            return Err(format!("empty onion address in {addr:?}"));
        }
        Ok((onion, port))
    }

    async fn relay_async<S>(stream: S, rest: &[u8], mode: RelayMode) -> Result<(), String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{copy, split, AsyncWriteExt};

        let (mut reader, mut writer) = split(stream);
        let mut stdout = tokio::io::stdout();
        if mode == RelayMode::ProxyResponse {
            stdout
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: shade-tree-rust\r\n\r\n",
                )
                .await
                .map_err(|e| format!("write proxy response: {e}"))?;
        }
        if !rest.is_empty() {
            stdout
                .write_all(rest)
                .await
                .map_err(|e| format!("write early tunnel bytes: {e}"))?;
        }
        stdout
            .flush()
            .await
            .map_err(|e| format!("flush stdout: {e}"))?;

        let mut stdin = tokio::io::stdin();
        let up = async {
            copy(&mut stdin, &mut writer)
                .await
                .map_err(|e| format!("relay stdin to tunnel: {e}"))?;
            // The current gateway treats a client FIN as a full tunnel close (its Node socket
            // is not allowHalfOpen), so a finite `printf ... | --stdio` must keep the tunnel's
            // write half open long enough to receive the destination response. CONNECT clients
            // are long-lived and do need their EOF propagated so abandoned proxy children exit.
            if mode == RelayMode::ProxyResponse {
                writer
                    .shutdown()
                    .await
                    .map_err(|e| format!("shutdown tunnel write: {e}"))?;
            }
            Ok::<(), String>(())
        };
        let down = async {
            copy(&mut reader, &mut stdout)
                .await
                .map_err(|e| format!("relay tunnel to stdout: {e}"))?;
            stdout
                .flush()
                .await
                .map_err(|e| format!("flush stdout: {e}"))
        };
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            result = &mut down => result,
            result = &mut up => {
                result?;
                down.await
            }
        }
    }

    // Dial plain TCP, send the framed envelope, read one newline-terminated ack, parse it.
    #[allow(dead_code)] // retained for the plain-socket relay regression tests/history
    fn send_envelope(
        dial: &str,
        wire: &str,
        relay: RelayMode,
    ) -> Result<serde_json::Value, String> {
        let mut stream = TcpStream::connect(dial).map_err(|e| format!("connect {dial}: {e}"))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
        stream
            .write_all(wire.as_bytes())
            .map_err(|e| format!("write envelope: {e}"))?;
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let mut rest = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| format!("read ack: {e}"))?;
            if n == 0 {
                return Err("gateway closed the connection before an ack".into());
            }
            if let Some(nl) = chunk[..n].iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&chunk[..nl]);
                rest.extend_from_slice(&chunk[nl + 1..n]);
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 64 * 1024 {
                return Err("ack exceeded 64KiB without a newline".into());
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let ack = serde_json::from_str::<serde_json::Value>(&line).map_err(|e| {
            format!(
                "bad ack json ({e}): {}",
                line.chars().take(160).collect::<String>()
            )
        })?;
        if ack.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
            && relay != RelayMode::None
        {
            if let Err(e) = relay_plain(stream, &rest, relay) {
                eprintln!("egress: accepted tunnel relay ended with error: {e}");
            }
        }
        Ok(ack)
    }

    #[allow(dead_code)] // retained to preserve the bounded-stdin shutdown regression fix
    fn relay_plain(stream: TcpStream, rest: &[u8], mode: RelayMode) -> Result<(), String> {
        // Drive both directions on one runtime. A detached blocking stdin thread can lose
        // already-buffered application bytes if the peer closes concurrently and the process
        // returns first; the async relay keeps the upload future owned until its bytes and FIN
        // have reached the tunnel (and is the same code path used by Arti).
        stream
            .set_nonblocking(true)
            .map_err(|e| format!("set tunnel nonblocking: {e}"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("create relay runtime: {e}"))?;
        let result = runtime.block_on(async move {
            let stream = tokio::net::TcpStream::from_std(stream)
                .map_err(|e| format!("adopt tunnel socket: {e}"))?;
            relay_async(stream, rest, mode).await
        });
        // Tokio implements async stdin with a blocking read. If the destination closes
        // first, `relay_async` correctly returns on the downstream branch, but an unbounded
        // Runtime drop would still wait for client stdin and deadlock the Proxy child. The
        // process is isolated per CONNECT, so a bounded shutdown safely lets its OS teardown
        // close the abandoned pipe reader after all downstream bytes have been flushed.
        runtime.shutdown_timeout(Duration::from_millis(100));
        result
    }

    // Resolve the ordered FAILOVER plan from the CLI flags. Order of precedence:
    //   --plain-tcp (escape hatch) > --onion > --bootnode-onion > --directory > bundled Elder.
    // A comma-separated --plain-tcp/--onion is an explicit failover LIST (dead first,
    // live second, ...); --directory/--bootnode-onion derive the ordered list from the
    // signed directory's weighted selection_order (with LKG caching + health).
    fn resolve_plan(
        rest: &[String],
        client: &shade_tree_egress::Client,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<EgressPlan, String> {
        if let Some(list) = take_flag(rest, "--plain-tcp") {
            let transports: Vec<Transport> = list
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| Transport::PlainTcp(s.to_string()))
                .collect();
            if transports.is_empty() {
                return Err("--plain-tcp: no targets".into());
            }
            return Ok(EgressPlan {
                transports,
                health: None,
                demo: None,
                profile: None,
            });
        }
        if let Some(list) = take_flag(rest, "--onion") {
            let mut transports = Vec::new();
            for addr in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let (onion, port) = parse_onion_addr(addr, 80)?;
                transports.push(Transport::Onion {
                    onion,
                    port,
                    artifacts: None,
                });
            }
            if transports.is_empty() {
                return Err("--onion: no targets".into());
            }
            return Ok(EgressPlan {
                transports,
                health: None,
                demo: None,
                profile: None,
            });
        }
        if let Some(bootnode) = take_flag(rest, "--bootnode-onion") {
            let Some(signer) = signer_spec(rest) else {
                return Err("--bootnode-onion needs --signer <hex>".into());
            };
            // Discovery over Tor is the FRESH source; a fetch failure still degrades to the
            // verified LKG cache inside directory_candidates (never nothing / never unverified).
            let fresh = fetch_directory_over_tor(&bootnode, client, runtime);
            let (transports, health, demo) = directory_candidates(fresh, rest, &signer, None)?;
            return Ok(EgressPlan {
                transports,
                health,
                demo,
                profile: None,
            });
        }
        if let Some(dirf) = take_flag(rest, "--directory") {
            let Some(signer) = signer_spec(rest) else {
                return Err("--directory needs --signer <hex>".into());
            };
            let fresh = read_file(&dirf); // a read failure -> LKG cache fallback
            let (transports, health, demo) = directory_candidates(fresh, rest, &signer, None)?;
            return Ok(EgressPlan {
                transports,
                health,
                demo,
                profile: None,
            });
        }
        let (bootnode, signer) = default_discovery()?;
        let profile = if use_bundled_public_profile(rest) {
            Some(default_public_profile()?)
        } else {
            None
        };
        let fresh = fetch_directory_over_tor(&bootnode, client, runtime);
        let (transports, health, demo) =
            directory_candidates(fresh, rest, &signer, profile.as_ref())?;
        Ok(EgressPlan {
            transports,
            health,
            demo,
            profile,
        })
    }

    // Fold one dial outcome into the health cache (reportResult parity). No-op unless a
    // health context is present (directory/bootnode paths) and the transport is a
    // signed-directory onion.
    fn report(health: &mut Option<HealthCtx>, t: &Transport, ok: bool) {
        let (Some(ctx), Some(onion)) = (health.as_mut(), t.health_onion()) else {
            return;
        };
        health::update(&mut ctx.cache, &ctx.known, &onion, ok, None, now_ms());
    }

    fn proxy_args(rest: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut index = 0;
        while index < rest.len() {
            match rest[index].as_str() {
                "--listen" | "--target" => index += 2,
                "--once" | "--stdio" | "--proxy-response" => index += 1,
                value if value.starts_with("--listen=") || value.starts_with("--target=") => {
                    index += 1
                }
                _ => {
                    out.push(rest[index].clone());
                    index += 1;
                }
            }
        }
        out
    }

    #[derive(Debug)]
    enum ProxyRequest {
        Health,
        Connect { target: String, early: Vec<u8> },
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        left.iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    fn read_proxy_request(
        stream: &mut TcpStream,
        auth_token: &str,
    ) -> Result<ProxyRequest, String> {
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        let mut bytes = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let end = loop {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| format!("read CONNECT request: {e}"))?;
            if n == 0 {
                if bytes.is_empty() {
                    return Err("empty-health-probe".into());
                }
                return Err("client closed before CONNECT request completed".into());
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > 16 * 1024 {
                return Err("CONNECT request headers exceeded 16KiB".into());
            }
            if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        stream.set_read_timeout(None).ok();
        let header = std::str::from_utf8(&bytes[..end])
            .map_err(|_| "CONNECT request headers are not UTF-8".to_string())?;
        use base64::Engine as _;
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("shade-tree:{auth_token}"))
        );
        let credentials = header
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("Proxy-Authorization")
                    .then_some(value.trim())
            })
            .collect::<Vec<_>>();
        if credentials.len() != 1
            || !constant_time_eq(credentials[0].as_bytes(), expected.as_bytes())
        {
            return Err("proxy-auth-required".into());
        }

        let first = header.lines().next().unwrap_or("");
        let mut fields = first.split_whitespace();
        let method = fields.next();
        if method == Some("GET")
            && fields.next() == Some("/_shade_tree/health")
            && fields
                .next()
                .is_some_and(|version| version.starts_with("HTTP/1."))
        {
            return Ok(ProxyRequest::Health);
        }
        if method != Some("CONNECT") {
            return Err("only HTTP CONNECT is supported".into());
        }
        let target = fields
            .next()
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .ok_or_else(|| "CONNECT target is missing or too long".to_string())?;
        let (_, port) = target
            .rsplit_once(':')
            .ok_or_else(|| "CONNECT target must be host:port".to_string())?;
        if port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
            return Err("CONNECT target has an invalid port".into());
        }
        Ok(ProxyRequest::Connect {
            target: target.to_string(),
            early: bytes[end..].to_vec(),
        })
    }

    fn serve_proxy_client(
        mut stream: TcpStream,
        base_args: &[String],
        auth_token: &str,
        client: &shade_tree_egress::Client,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<bool, String> {
        let (target, early) = match read_proxy_request(&mut stream, auth_token) {
            Ok(ProxyRequest::Health) => {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .map_err(|e| format!("write health response: {e}"))?;
                return Ok(false);
            }
            Ok(ProxyRequest::Connect { target, early }) => (target, early),
            Err(e) if e == "empty-health-probe" => return Ok(false),
            Err(e) if e == "proxy-auth-required" => {
                let response = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"shade-tree\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response);
                return Err("proxy authentication required".into());
            }
            Err(e) => {
                let body = format!("Shade Tree proxy: {e}\n");
                let response = format!(
                    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                return Err(e);
            }
        };
        let mut args = base_args.to_vec();
        args.push("--target".into());
        args.push(target);
        let status = execute_egress(&args, client, runtime, Some((&mut stream, &early)));
        if status != ExitCode::SUCCESS {
            let body = b"Shade Tree tunnel setup failed\n";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            return Err("egress setup failed".into());
        }
        Ok(true)
    }

    fn bind_proxy_listener(listen: &str) -> Result<std::net::TcpListener, String> {
        let listener =
            std::net::TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
        let address = listener
            .local_addr()
            .map_err(|e| format!("inspect bound address for {listen}: {e}"))?;
        if !address.ip().is_loopback() {
            return Err(format!(
                "REFUSING non-loopback Proxy listener {address}; the agent Proxy must stay loopback-only"
            ));
        }
        Ok(listener)
    }

    pub fn run_proxy(rest: &[String]) -> ExitCode {
        let auth_token = match std::env::var("SHADE_TREE_PROXY_TOKEN").ok() {
            Some(token) => match super::run::validate_auth_token(&token) {
                Ok(()) => std::sync::Arc::new(token),
                Err(error) => {
                    eprintln!("proxy: {error}");
                    return ExitCode::from(2);
                }
            },
            None => {
                eprintln!("proxy: missing authentication; set SHADE_TREE_PROXY_TOKEN");
                return ExitCode::from(2);
            }
        };
        let runtime = match new_runtime() {
            Ok(runtime) => std::sync::Arc::new(runtime),
            Err(e) => {
                eprintln!("proxy: {e}");
                return ExitCode::from(2);
            }
        };
        // One in-process client for the entire proxy lifetime: its Arti once-cell and
        // bounded prover are shared by every CONNECT worker.
        let client = std::sync::Arc::new(new_client());
        let listen = take_flag(rest, "--listen").unwrap_or_else(|| "127.0.0.1:8118".into());
        let once = rest.iter().any(|arg| arg == "--once");
        let listener = match bind_proxy_listener(&listen) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("proxy: {e}");
                return ExitCode::from(2);
            }
        };
        let bound = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or(listen);
        eprintln!("shade-tree proxy listening on http://{bound}");
        let base_args = proxy_args(rest);
        let worker_count = prover_workers();
        let (sender, receiver) = std::sync::mpsc::sync_channel::<TcpStream>(worker_count);
        let receiver = std::sync::Arc::new(std::sync::Mutex::new(receiver));
        if !once {
            for _ in 0..worker_count {
                let args = base_args.clone();
                let auth_token = std::sync::Arc::clone(&auth_token);
                let client = std::sync::Arc::clone(&client);
                let runtime = std::sync::Arc::clone(&runtime);
                let receiver = std::sync::Arc::clone(&receiver);
                std::thread::spawn(move || loop {
                    let stream = match receiver.lock() {
                        Ok(receiver) => match receiver.recv() {
                            Ok(stream) => stream,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };
                    if let Err(e) =
                        serve_proxy_client(stream, &args, &auth_token, &client, &runtime)
                    {
                        eprintln!("proxy: {e}");
                    }
                });
            }
        }
        for incoming in listener.incoming() {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("proxy: accept failed: {e}");
                    continue;
                }
            };
            if once {
                match serve_proxy_client(stream, &base_args, &auth_token, &client, &runtime) {
                    Ok(false) => continue,
                    Ok(true) => return ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("proxy: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
            match sender.try_send(stream) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(mut stream)) => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n",
                    );
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    eprintln!("proxy: worker pool stopped");
                    return ExitCode::from(1);
                }
            }
        }
        ExitCode::SUCCESS
    }

    fn execute_egress(
        rest: &[String],
        client: &shade_tree_egress::Client,
        runtime: &tokio::runtime::Runtime,
        mut proxy: Option<(&mut TcpStream, &[u8])>,
    ) -> ExitCode {
        let relay = if proxy.is_some() {
            RelayMode::ProxyResponse
        } else {
            RelayMode::from_args(rest)
        };
        let (identity_path, target) = match (
            take_flag(rest, "--identity"),
            take_flag(rest, "--target"),
        ) {
            (Some(i), Some(t)) => (i, t),
            _ => {
                eprintln!(
                    "egress (live): need --identity <f> --target <host:port> and either --members <f> or an on-chain source\n\n{}",
                    super::HELP
                );
                return ExitCode::from(2);
            }
        };
        // --circuits is OPTIONAL (T-RUST-4): omit it to use the RLN artifacts EMBEDDED in
        // this `live` binary (no external circuit files), or pass a dir to load them from disk.
        let circuits = take_flag(rest, "--circuits");

        // Resolve the ordered failover plan up front so a missing/ambiguous transport (or an
        // unusable directory with no LKG fallback) fails BEFORE the expensive proof build.
        let mut plan = match resolve_plan(rest, client, runtime) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("egress (live): {e}");
                return ExitCode::from(2);
            }
        };
        let effective_epoch_seconds = epoch_seconds(plan.profile.as_ref());
        if let Some(profile) = plan.profile.as_ref() {
            if effective_epoch_seconds != profile.rate_policy.epoch_seconds {
                eprintln!(
                    "egress (live): SHADE_TREE_EPOCH_SECONDS={effective_epoch_seconds} conflicts with the bundled/signed public rate policy ({}); refusing before proving",
                    profile.rate_policy.epoch_seconds
                );
                return ExitCode::from(2);
            }
        }
        let epoch = take_flag(rest, "--epoch")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| current_epoch(effective_epoch_seconds));
        let identity: IdentityFile = match load_json(&identity_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        let members: MembersFile = if let Some(members_path) = take_flag(rest, "--members") {
            match load_json(&members_path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            }
        } else {
            let source = admission_from_args(rest).leaf_source.or_else(|| {
                plan.profile
                    .as_ref()
                    .map(|profile| profile.default_path.clone())
            });
            let advertised_demo = source.as_deref() == Some("demo");
            let contract = take_flag(rest, "--contract")
                .or_else(|| {
                    advertised_demo
                        .then(|| plan.demo.as_ref().map(|d| d.contract.clone()))
                        .flatten()
                })
                .or_else(|| {
                    (source.as_deref() == Some("paid"))
                        .then(|| std::env::var("SHADE_TREE_PAID_ACCESS_CONTRACT").ok())
                        .flatten()
                })
                .or_else(|| {
                    std::env::var("SHADE_TREE_GROUP_CONTRACT")
                        .ok()
                        .and_then(|v| v.split(',').next().map(str::trim).map(str::to_string))
                })
                .or_else(|| {
                    plan.profile
                        .as_ref()
                        .map(|profile| profile.contract.clone())
                });
            let Some(contract) = contract.filter(|s| !s.is_empty()) else {
                eprintln!("egress (live): no --members file and no on-chain contract source; pass --contract, configure SHADE_TREE_GROUP_CONTRACT/SHADE_TREE_PAID_ACCESS_CONTRACT, or use a valid directory demo advert with --leaf-source demo");
                return ExitCode::from(2);
            };
            let rpc_url = take_flag(rest, "--rpc-url")
                .or_else(|| std::env::var("SHADE_TREE_RPC_URL").ok())
                .or_else(|| plan.profile.as_ref().map(|profile| profile.rpc_url.clone()))
                .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
            let from = take_flag(rest, "--from-block")
                .or_else(|| std::env::var("SHADE_TREE_FROM_BLOCK").ok())
                .or_else(|| {
                    plan.profile
                        .as_ref()
                        .map(|profile| profile.deploy_block.to_string())
                })
                .unwrap_or_else(|| "0".to_string());
            let parsed_from = if let Some(hex) = from.strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
            } else {
                from.parse::<u64>()
            };
            let Ok(from_block) = parsed_from else {
                eprintln!("egress (live): invalid --from-block {from:?}");
                return ExitCode::from(2);
            };
            let block_tag_flag = take_flag(rest, "--block-tag");
            let block_tag =
                egress_block_tag_setting(block_tag_flag.as_deref(), plan.profile.is_some());
            let rln_id = take_flag(rest, "--rln-identifier")
                .unwrap_or_else(|| "1".into())
                .parse::<u64>()
                .unwrap_or(1);
            let discovered = match super::leaves::fetch_members(
                &rpc_url, &contract, from_block, &block_tag, rln_id,
            ) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("egress (live): leaf discovery failed: {e}");
                    return ExitCode::from(2);
                }
            };
            if !discovered
                .document
                .members
                .iter()
                .any(|m| m == &identity.leaf)
            {
                eprintln!("egress (live): your leaf {}.. is not present in discovered {} ({} live leaves); for public-stake-v1, wait until the registration block reaches finality", identity.leaf.chars().take(12).collect::<String>(), contract, discovered.live_count);
                return ExitCode::from(2);
            }
            eprintln!(
                "egress: discovered {} live leaves from {} (root {})",
                discovered.live_count, contract, discovered.root
            );
            MembersFile {
                members: discovered.document.members,
            }
        };
        // K = this member's tier limit (T-FEAT-8): `--k`, SHADE_TREE_LIMIT, and an identity's
        // explicit limit win, in that order. Otherwise use the bundled public defaultLimit (1)
        // only on its zero-config path; custom discovery keeps the historical app default 8.
        // It MUST be the limit the member's leaf was enrolled with — the prover looks the leaf
        // up in `members`, so a wrong K fails there ("member_leaf not present"), never on the wire.
        let k_flag = take_flag(rest, "--k");
        let k_env = std::env::var("SHADE_TREE_LIMIT").ok();
        let k = match member_limit_setting(
            k_flag.as_deref(),
            k_env.as_deref(),
            identity.limit,
            plan.profile.as_ref(),
        ) {
            Ok(limit) => limit,
            Err(error) => {
                eprintln!("egress (live): {error}");
                return ExitCode::from(2);
            }
        };
        if !(1..=shade_tree_egress::slot::MAX_LIMIT).contains(&k) {
            eprintln!(
                "egress (live): K={k} out of range 1..{} (RLN(20,16) range check is 16-bit)",
                shade_tree_egress::slot::MAX_LIMIT
            );
            return ExitCode::from(2);
        }
        // Default-on persistent allocation is durably committed BEFORE proof construction.
        // This intentionally burns a slot on a crash/local failure rather than allowing a
        // restarted process to reuse a nullifier. Manual slots are test-only and gated by an
        // unmistakable flag so production callers cannot casually disable the coordinator.
        let unsafe_reuse = rest
            .iter()
            .any(|s| s == "--unsafe-allow-slot-reuse-for-slashing-tests");
        let explicit_slot = take_flag(rest, "--slot");
        if explicit_slot.is_some() && !unsafe_reuse {
            eprintln!("egress (live): --slot bypasses crash-safe allocation; it requires --unsafe-allow-slot-reuse-for-slashing-tests and is only for isolated slashing tests");
            return ExitCode::from(2);
        }
        let slots = if unsafe_reuse {
            let message_id = match explicit_slot {
                Some(s) => match s.parse::<u64>() {
                    Ok(slot) => slot,
                    Err(_) => {
                        eprintln!("egress (live): --slot must be an integer (got {s:?})");
                        return ExitCode::from(2);
                    }
                },
                None => 0,
            };
            if message_id >= k {
                eprintln!("egress (live): --slot {message_id} >= K {k} (out of this member's tier; the circuit would reject it)");
                return ExitCode::from(2);
            }
            shade_tree_egress::SlotPolicy::UnsafeForSlashingTest { message_id }
        } else {
            let cursor = match slot_cursor_path(rest, &identity.leaf) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("egress (live): REFUSING to prove — {e}");
                    return ExitCode::from(3);
                }
            };
            shade_tree_egress::SlotPolicy::CrashSafe { cursor }
        };
        let rln_identifier = take_flag(rest, "--rln-identifier").unwrap_or_else(|| "1".to_string());
        let nonce = take_flag(rest, "--nonce").unwrap_or_else(gen_nonce);

        // ZK artifact set (T-HARD-8). Embedded: hash-check the binary's own artifacts against
        // the lock it embeds, FAIL CLOSED on any drift, and take the set's content-derived id.
        // External --circuits dir: derive the id from that dir's verification_key.json.
        let client_artifact = match circuits.as_deref() {
            None => match shade_tree_rln::artifacts::verify_embedded() {
                Ok(c) => {
                    eprintln!(
                        "egress: embedded artifacts verified against zk-artifacts lock (artifact={}, trust={}, provenance={})",
                        c.artifact_id, c.trust, c.provenance
                    );
                    c.artifact_id
                }
                Err(e) => {
                    eprintln!("egress: REFUSING to prove — {e}");
                    return ExitCode::from(3);
                }
            },
            Some(dir) => {
                let vkey_path = format!("{dir}/verification_key.json");
                match std::fs::read(&vkey_path) {
                    Ok(bytes) => shade_tree_proto::artifact_id_of("rln", &bytes),
                    Err(e) => {
                        eprintln!("egress: cannot read {vkey_path} to derive the artifact id: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
        };
        // Pick the artifact id against the first candidate that ADVERTISES an accepted set
        // (parity with client/shade-tree-client.mjs _pickArtifact): this binary holds ONE set, so
        // the pick is "ours if listed, else fail closed"; with no ad anywhere, optimistically ours.
        let gateway_ad: Option<&[String]> = plan.transports.iter().find_map(|t| match t {
            Transport::Onion {
                artifacts: Some(a), ..
            } if !a.is_empty() => Some(a.as_slice()),
            _ => None,
        });
        let artifact = match shade_tree_proto::select_artifact(
            gateway_ad,
            std::slice::from_ref(&client_artifact),
        ) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("egress: artifact negotiation failed: {e}");
                return ExitCode::from(2);
            }
        };

        // Build the REAL envelope on shade-tree-egress's bounded blocking worker, then
        // connect through its service-lifetime transport. The proof is built once and
        // reused byte-for-byte across failover candidates inside the crate.
        eprintln!(
            "egress: building RLN envelope (epoch={epoch}, slot=crash-safe, target={target}, artifact={artifact}, {}) ...",
            match circuits.as_deref() {
                Some(d) => format!("circuits={d}"),
                None => "circuits=embedded".to_string(),
            }
        );
        let proof = shade_tree_egress::ProofRequest {
            identity_secret: identity.identity_secret,
            member_leaf: identity.leaf,
            members: members.members,
            target: target.clone(),
            nonce,
            epoch,
            rln_identifier,
            user_message_limit: k,
            circuits_dir: circuits,
        };
        let gateways = plan.transports.iter().map(Transport::gateway).collect();
        let request = shade_tree_egress::ConnectRequest {
            gateways,
            proof,
            slots,
            artifact,
        };
        let outcome = runtime.block_on(client.connect(request));
        let attempts = match &outcome {
            Ok(connected) => connected.attempts.as_slice(),
            Err(shade_tree_egress::Error::GatewayRefused { attempts, .. })
            | Err(shade_tree_egress::Error::AllCandidatesFailed { attempts }) => {
                attempts.as_slice()
            }
            Err(_) => &[],
        };
        for attempt in attempts {
            if let Some(transport) = plan
                .transports
                .iter()
                .find(|transport| transport.label() == attempt.gateway.label())
            {
                report(&mut plan.health, transport, attempt.dial_succeeded);
                if !attempt.dial_succeeded {
                    eprintln!(
                        "egress: candidate {} failed ({}); rotating",
                        transport.label(),
                        attempt
                            .error
                            .as_deref()
                            .unwrap_or("unknown transport error")
                    );
                }
            }
        }
        if let Some(ctx) = plan.health.as_mut() {
            health::save(Some(&ctx.cache_path), &mut ctx.cache);
        }

        let connected = match outcome {
            Ok(connected) => connected,
            Err(shade_tree_egress::Error::GatewayRefused {
                kind: shade_tree_egress::GatewayRefusalKind::PayloadLimit,
                ..
            }) => {
                eprintln!(
                    "egress: gateway payload budget exhausted for this RLN epoch slot; open a new tunnel with another slot or wait for the protocol epoch to advance"
                );
                return ExitCode::from(4);
            }
            Err(shade_tree_egress::Error::GatewayRefused { ack, .. }) => {
                let err = ack
                    .get("err")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(no err field)");
                if proxy.is_none() {
                    println!("not-ok: gate-refused: {err}");
                }
                // An artifact reject (T-HARD-8) advertises the gateway's accepted ids back; surface
                // them + whether ours is among them (parity with client/shade-tree-client.mjs connect()).
                if let Some(list) = ack.get("artifacts").and_then(serde_json::Value::as_array) {
                    let ids: Vec<String> = list
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    let hint = match shade_tree_proto::select_artifact(
                        Some(&ids),
                        std::slice::from_ref(&client_artifact),
                    ) {
                        Ok(id) => format!("retry with {id}"),
                        Err(e) => e.to_string(),
                    };
                    if proxy.is_none() {
                        println!("gateway accepts artifacts: {} ({hint})", ids.join(","));
                    }
                }
                return ExitCode::from(1);
            }
            Err(shade_tree_egress::Error::Slot(shade_tree_egress::slot::Error::Exhausted {
                epoch,
                limit,
            })) => {
                eprintln!("egress: epoch budget exhausted: used {limit}/{limit} slots in epoch {epoch}; wait for the protocol epoch to advance");
                return ExitCode::from(4);
            }
            Err(e) => {
                eprintln!("egress: {e}");
                return ExitCode::from(3);
            }
        };

        let gateway_label = connected.gateway.label();
        if let Some((client_stream, early_request)) = proxy.as_mut() {
            let downstream = match client_stream.try_clone() {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("proxy: clone client socket: {e}");
                    return ExitCode::from(3);
                }
            };
            if let Err(e) = downstream.set_nonblocking(true) {
                eprintln!("proxy: set client socket nonblocking: {e}");
                return ExitCode::from(3);
            }
            let result = runtime.block_on(async move {
                use tokio::io::AsyncWriteExt;
                let mut tunnel = connected.stream;
                if !early_request.is_empty() {
                    tunnel
                        .write_all(early_request)
                        .await
                        .map_err(|e| format!("forward early client bytes: {e}"))?;
                    tunnel
                        .flush()
                        .await
                        .map_err(|e| format!("flush early client bytes: {e}"))?;
                }
                let mut downstream = tokio::net::TcpStream::from_std(downstream)
                    .map_err(|e| format!("adopt proxy client socket: {e}"))?;
                downstream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: shade-tree-rust\r\n\r\n",
                    )
                    .await
                    .map_err(|e| format!("write proxy response: {e}"))?;
                let relay_result = async {
                    if !connected.early_data.is_empty() {
                        downstream
                            .write_all(&connected.early_data)
                            .await
                            .map_err(|e| format!("write early tunnel bytes: {e}"))?;
                    }
                    downstream
                        .flush()
                        .await
                        .map_err(|e| format!("flush proxy response: {e}"))?;
                    tokio::io::copy_bidirectional(&mut downstream, &mut tunnel)
                        .await
                        .map_err(|e| format!("relay proxy tunnel: {e}"))?;
                    Ok::<(), String>(())
                }
                .await;
                Ok::<Option<String>, String>(relay_result.err())
            });
            match result {
                Err(e) => {
                    eprintln!("proxy: tunnel setup failed before CONNECT acceptance: {e}");
                    return ExitCode::from(3);
                }
                Ok(Some(e)) => {
                    // The gateway accepted the proof and the Proxy sent 200 Connection
                    // Established. A later relay error (including a benign platform-specific
                    // ENOTCONN while both peers close) can only terminate that established
                    // tunnel; it is too late to turn the exchange back into an HTTP 502.
                    // Report the close, but finish this accepted request normally. This also
                    // matches the one-shot relay path below.
                    eprintln!("proxy: accepted tunnel relay ended with error: {e}");
                }
                Ok(None) => {}
            }
        } else if relay == RelayMode::None {
            println!("ok");
            println!("gateway: {gateway_label}");
            println!("target: {}", connected.proof.target);
            println!("nullifier: {}", connected.proof.nullifier);
            if let Some(receipt) = connected.ack.get("receipt") {
                println!("receipt: {receipt}");
            }
        } else {
            let result =
                runtime.block_on(relay_async(connected.stream, &connected.early_data, relay));
            if let Err(e) = result {
                eprintln!("egress: accepted tunnel relay ended with error: {e}");
            }
            eprintln!("egress: tunnel via {gateway_label} closed");
        }
        ExitCode::SUCCESS
    }

    fn new_runtime() -> Result<tokio::runtime::Runtime, String> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))
    }

    fn prover_workers() -> usize {
        std::env::var("SHADE_TREE_PROVER_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|workers| (1..=64).contains(workers))
            .unwrap_or(2)
    }

    fn new_client() -> shade_tree_egress::Client {
        shade_tree_egress::Client::new(
            Duration::from_secs(tor_timeout_secs()),
            Duration::from_secs(gateway_ack_timeout_secs()),
            prover_workers(),
        )
    }

    pub fn run_egress(rest: &[String]) -> ExitCode {
        let runtime = match new_runtime() {
            Ok(runtime) => runtime,
            Err(e) => {
                eprintln!("egress: {e}");
                return ExitCode::from(2);
            }
        };
        let client = new_client();
        execute_egress(rest, &client, &runtime, None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn public_profile() -> PublicStakedProfile {
            PublicStakedProfile {
                default_path: "staked".into(),
                rate_policy: shade_tree_proto::CanonicalRate {
                    scope: "grove-v4".into(),
                    window: "fixed".into(),
                    epoch_seconds: 60,
                    previous_epochs_accepted: 1,
                    root_freshness_seconds: 60,
                    payload_bytes_per_slot: 41_943_040,
                },
                contract: "0x1111111111111111111111111111111111111111".into(),
                rpc_url: "https://rpc.example".into(),
                chain_id: 11_155_111,
                deploy_block: 12_345,
                default_limit: 1,
            }
        }

        fn gateway_with_rate(
            rate: Option<shade_tree_proto::RateCaps>,
        ) -> shade_tree_proto::GatewayEntry {
            shade_tree_proto::GatewayEntry {
                onion: "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd.onion".into(),
                pubkey: String::new(),
                weight: 100,
                health: "up".into(),
                operator: None,
                staked: None,
                caps: Some(shade_tree_proto::Caps {
                    admits: Some(vec!["staked".into()]),
                    rate,
                    ..Default::default()
                }),
                caps_sig: None,
            }
        }

        fn public_rate() -> shade_tree_proto::RateCaps {
            shade_tree_proto::RateCaps {
                scope: "grove-v4".into(),
                window: "fixed".into(),
                epoch_seconds: 60,
                previous_epochs_accepted: 1,
                root_freshness_seconds: 60,
                payload_bytes_per_slot: 41_943_040,
            }
        }

        #[test]
        fn bundled_and_custom_rate_defaults_stay_separate() {
            let profile = public_profile();
            assert_eq!(epoch_seconds_setting(None, Some(&profile)), 60);
            assert_eq!(
                member_limit_setting(None, None, None, Some(&profile)),
                Ok(1)
            );
            assert_eq!(epoch_seconds_setting(None, None), 120);
            assert_eq!(
                member_limit_setting(None, None, None, None),
                Ok(shade_tree_egress::slot::DEFAULT_LIMIT)
            );
        }

        #[test]
        fn only_public_egress_defaults_to_finalized_membership_reads() {
            assert_eq!(egress_block_tag_setting(None, true), "finalized");
            assert_eq!(egress_block_tag_setting(None, false), "latest");
            assert_eq!(egress_block_tag_setting(Some("safe"), true), "safe");
        }

        #[test]
        fn explicit_epoch_and_member_limit_values_win() {
            let profile = public_profile();
            assert_eq!(epoch_seconds_setting(Some("90"), Some(&profile)), 90);
            assert_eq!(
                member_limit_setting(Some("32"), Some("16"), Some(8), Some(&profile)),
                Ok(32)
            );
            assert_eq!(
                member_limit_setting(None, Some("16"), Some(8), Some(&profile)),
                Ok(16)
            );
            assert_eq!(
                member_limit_setting(None, None, Some(8), Some(&profile)),
                Ok(8)
            );
            assert!(member_limit_setting(Some("many"), None, None, Some(&profile)).is_err());
        }

        #[test]
        fn rpc_only_override_keeps_the_bundled_public_profile() {
            assert!(use_bundled_public_profile_setting(
                &["--rpc-url".into(), "https://rpc.example".into()],
                None,
                None,
                None,
                None
            ));
            assert!(use_bundled_public_profile_setting(
                &[],
                None,
                None,
                Some("https://rpc.example"),
                None
            ));
        }

        #[test]
        fn explicit_member_inputs_select_the_custom_profile_path() {
            for args in [
                vec!["--members".into(), "members.json".into()],
                vec!["--contract=0x1111".into()],
                vec!["--leaf-source".into(), "invited".into()],
            ] {
                assert!(!use_bundled_public_profile_setting(
                    &args, None, None, None, None
                ));
            }
            assert!(!use_bundled_public_profile_setting(
                &[],
                Some("0x1111"),
                None,
                Some("https://rpc.example"),
                None
            ));
            assert!(!use_bundled_public_profile_setting(
                &[],
                None,
                Some("0x2222"),
                None,
                None
            ));
            assert!(!use_bundled_public_profile_setting(
                &[],
                None,
                None,
                None,
                Some("invited")
            ));
        }

        #[test]
        fn public_gateway_rate_filters_bad_nodes_without_bricking_the_fleet() {
            let profile = public_profile();
            let matching = gateway_with_rate(Some(public_rate()));
            let missing = gateway_with_rate(None);
            let mut different = public_rate();
            different.epoch_seconds = 120;
            let mismatch = gateway_with_rate(Some(different));
            let mut mixed = vec![missing, matching.clone(), mismatch];
            assert_eq!(
                filter_public_gateway_rates(&mut mixed, &profile.rate_policy),
                2
            );
            assert_eq!(mixed.len(), 1);
            assert_eq!(mixed[0].onion, matching.onion);
            assert_eq!(
                mixed[0]
                    .caps
                    .as_ref()
                    .and_then(|caps| shade_tree_proto::canonical_caps(caps).rate),
                Some(profile.rate_policy.clone())
            );

            let mut unavailable = vec![gateway_with_rate(None)];
            assert_eq!(
                filter_public_gateway_rates(&mut unavailable, &profile.rate_policy),
                1
            );
            assert!(unavailable.is_empty());
        }

        #[test]
        fn smooth_rotation_defaults_on_and_has_explicit_opt_outs() {
            assert!(rotation_spread_setting(&[], None));
            assert!(rotation_spread_setting(&[], Some("1")));
            assert!(!rotation_spread_setting(&[], Some("off")));
            assert!(!rotation_spread_setting(
                &["--no-rotation-spread".into()],
                Some("1")
            ));
            assert!(rotation_spread_setting(
                &["--rotation-spread".into()],
                Some("0")
            ));
        }

        #[test]
        fn empty_proxy_preflight_is_not_a_connect_attempt() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let stream = TcpStream::connect(address).unwrap();
                drop(stream);
            });
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                read_proxy_request(&mut stream, "0123456789abcdef0123456789abcdef").unwrap_err(),
                "empty-health-probe"
            );
            peer.join().unwrap();
        }

        #[test]
        fn proxy_listener_refuses_non_loopback_bindings() {
            let error = bind_proxy_listener("0.0.0.0:0").unwrap_err();
            assert!(error.contains("REFUSING non-loopback"));
            let listener = bind_proxy_listener("127.0.0.1:0").unwrap();
            assert!(listener.local_addr().unwrap().ip().is_loopback());
        }

        #[test]
        fn proxy_health_check_requires_the_exact_token() {
            use base64::Engine as _;
            let token = "0123456789abcdef0123456789abcdef";
            let credential =
                base64::engine::general_purpose::STANDARD.encode(format!("shade-tree:{token}"));
            for (presented, expected_ok) in [
                (credential, true),
                (
                    base64::engine::general_purpose::STANDARD.encode("shade-tree:wrong"),
                    false,
                ),
            ] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let peer = std::thread::spawn(move || {
                    let mut stream = TcpStream::connect(address).unwrap();
                    write!(
                        stream,
                        "GET /_shade_tree/health HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic {presented}\r\n\r\n"
                    )
                    .unwrap();
                });
                let (mut stream, _) = listener.accept().unwrap();
                let result = read_proxy_request(&mut stream, token);
                assert_eq!(matches!(result, Ok(ProxyRequest::Health)), expected_ok);
                peer.join().unwrap();
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first() else {
        println!("{HELP}");
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    match sub.as_str() {
        "verify-directory" => cmd_verify_directory(rest),
        "fetch-directory" => cmd_fetch_directory(rest),
        "select" => cmd_select(rest),
        "verify-receipt" => cmd_verify_receipt(rest),
        "enroll" => cmd_enroll(rest),
        "register-member" => cmd_register_member(rest),
        "member-status" | "exit-member" | "withdraw-member" => cmd_member(sub, rest),
        "proxy-token" => cmd_proxy_token(rest),
        "identity" => cmd_identity(rest),
        "leaves" => cmd_leaves(rest),
        "egress" => cmd_egress(rest),
        "proxy" => cmd_proxy(rest),
        "run" => run::run(rest),
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        "version" | "--version" | "-V" => {
            println!("shade-tree {VERSION}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown subcommand: {other}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}
