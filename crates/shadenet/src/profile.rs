//! Network profiles: the deployment record that pins a canopy's Elder Tree, its canopy signer(s)
//! and, for a public network, the staking contract and rate policy.
//!
//! The record is data, not code. Tier bonds, the default tier, unbonding times and the rate policy
//! are read from the record and validated for shape and internal consistency only, so a network
//! whose economics change (or a staging network with placeholder economics) needs a new record,
//! not a new binary. The mutable list of nodes is never here: it comes from the signed canopy.

use std::path::Path;

use crate::Error;

/// Name of the network compiled into this build.
pub const DEFAULT_NETWORK: &str = "sepolia";
/// The Sepolia deployment record compiled into this build.
pub const SEPOLIA_DEPLOYMENT: &str = include_str!("../../../network/sepolia/deployment.json");
/// Tier used for custom (non-public) canopies when nothing else says otherwise.
pub const LEGACY_DEFAULT_LIMIT: u64 = 8;
/// Largest `userMessageLimit` the RLN(20,16) circuit can range-check.
pub const MAX_LIMIT: u64 = 65_535;

/// One bond tier of a staking root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier {
    /// Tunnels per epoch (`userMessageLimit`).
    pub limit: u64,
    /// Bond in wei, as a decimal string.
    pub bond_wei: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakedRoot {
    pub profile: Option<String>,
    pub contract: String,
    pub rpc_url: String,
    pub chain_id: Option<u64>,
    pub deploy_tx: Option<String>,
    pub deploy_block: Option<u64>,
    pub hasher: Option<String>,
    pub withdraw_verifier: Option<String>,
    pub default_limit: Option<u64>,
    pub tiers: Option<Vec<Tier>>,
    pub unbonding_seconds: Option<u64>,
    pub min_unbonding_seconds: Option<u64>,
}

/// A parsed deployment record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub elder_onion: String,
    /// Comma-separated pinned canopy signer(s), hex ed25519 public keys.
    pub canopy_signer: String,
    pub default_path: Option<String>,
    pub rate_policy: Option<shadenet_proto::CanonicalRate>,
    pub staked: Option<StakedRoot>,
}

/// The zero-configuration public path of a network: staked admission, one signed rate policy and
/// the contract that holds the members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProfile {
    pub default_path: String,
    pub rate_policy: shadenet_proto::CanonicalRate,
    pub contract: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub deploy_block: u64,
    pub default_limit: u64,
    pub tiers: Vec<Tier>,
    pub unbonding_seconds: u64,
    pub min_unbonding_seconds: u64,
}

/// A named deployment record: the bundled one, or one loaded from a file for staging or a custom
/// canopy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub name: String,
    pub deployment: Deployment,
}

impl Network {
    /// The record compiled into this build under `name`.
    pub fn bundled(name: &str) -> Result<Self, Error> {
        match name {
            DEFAULT_NETWORK => Self::from_json(DEFAULT_NETWORK, SEPOLIA_DEPLOYMENT),
            other => Err(Error::Config(format!(
                "unknown bundled network {other:?}; pass a deployment.json path instead (bundled: {DEFAULT_NETWORK})"
            ))),
        }
    }

    /// Parse a deployment record.
    pub fn from_json(name: &str, raw: &str) -> Result<Self, Error> {
        Ok(Self {
            name: name.to_string(),
            deployment: parse_deployment(name, raw).map_err(Error::Config)?,
        })
    }

    /// Load a deployment record from disk (for example `network/sepolia-staging/deployment.json`).
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| Error::Config(format!("{} is not JSON: {e}", path.display())))?;
        let name = value
            .get("network")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| path.display().to_string());
        Self::from_json(&name, &raw)
    }

    /// Resolve `--network` / `SHADENET_NETWORK`: a bundled name, or a path to a deployment record.
    pub fn resolve(spec: &str) -> Result<Self, Error> {
        let spec = spec.trim();
        if spec.is_empty() || spec == DEFAULT_NETWORK {
            return Self::bundled(DEFAULT_NETWORK);
        }
        let path = Path::new(spec);
        if path.is_file() {
            return Self::from_file(path);
        }
        if path.is_dir() && path.join("deployment.json").is_file() {
            return Self::from_file(&path.join("deployment.json"));
        }
        Self::bundled(spec)
    }

    /// The Elder Tree onion and the canopy signer(s) this network pins.
    pub fn discovery(&self) -> (String, String) {
        (
            self.deployment.elder_onion.clone(),
            self.deployment.canopy_signer.clone(),
        )
    }

    /// The staked root's default tier, falling back to the historical custom-canopy default.
    pub fn staked_default_limit(&self) -> Result<u64, Error> {
        let limit = self
            .deployment
            .staked
            .as_ref()
            .ok_or_else(|| {
                Error::Config(format!(
                    "network {} has no live staked admission root",
                    self.name
                ))
            })?
            .default_limit
            .unwrap_or(LEGACY_DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(Error::Config(format!(
                "network {} staked admission root has an invalid defaultLimit",
                self.name
            )));
        }
        Ok(limit)
    }

    /// The zero-configuration public profile, validated for internal consistency.
    pub fn public_profile(&self) -> Result<PublicProfile, Error> {
        public_profile_from(self.deployment.clone()).map_err(Error::Config)
    }
}

fn optional_u64(object: &serde_json::Value, name: &str) -> Result<Option<u64>, String> {
    match object.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("deployment {name} must be an unsigned integer")),
    }
}

fn parse_rate(value: &serde_json::Value) -> Result<shadenet_proto::CanonicalRate, String> {
    let string = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("deployment ratePolicy.{name} is missing or invalid"))
    };
    let integer = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .filter(|number| *number <= i64::MAX as u64)
            .map(|number| number as i64)
            .ok_or_else(|| format!("deployment ratePolicy.{name} is missing or invalid"))
    };
    let raw = shadenet_proto::RateCaps {
        scope: string("scope")?,
        window: string("window")?,
        epoch_seconds: integer("epochSeconds")?,
        previous_epochs_accepted: integer("previousEpochsAccepted")?,
        root_freshness_seconds: integer("rootFreshnessSeconds")?,
        payload_bytes_per_slot: integer("payloadBytesPerSlot")?,
    };
    shadenet_proto::canonical_rate(&raw).ok_or_else(|| {
        "deployment ratePolicy is outside the supported grove-v4 fixed-window bounds".into()
    })
}

fn is_address(value: Option<&str>) -> bool {
    value
        .and_then(|address| address.strip_prefix("0x"))
        .is_some_and(|hex_address| {
            hex_address.len() == 40 && hex::decode(hex_address).is_ok_and(|bytes| bytes.len() == 20)
        })
}

/// Parse and structurally validate a deployment record.
pub fn parse_deployment(name: &str, raw: &str) -> Result<Deployment, String> {
    let deployment: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("{name} deployment is invalid JSON: {e}"))?;
    if deployment.get("status").and_then(serde_json::Value::as_str) != Some("live") {
        return Err(format!("{name} deployment is not live"));
    }
    let protocol = deployment
        .get("protocol")
        .ok_or_else(|| format!("{name} deployment has no protocol range"))?;
    let min = protocol
        .get("min")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{name} deployment has no protocol.min"))?;
    let max = protocol
        .get("max")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{name} deployment has no protocol.max"))?;
    if !(min..=max).contains(&shadenet_proto::PROTO_MAX) {
        return Err(format!(
            "{name} deployment does not support protocol v{}",
            shadenet_proto::PROTO_MAX
        ));
    }
    let elder = deployment
        .get("elder")
        .ok_or_else(|| format!("{name} deployment has no Elder Tree"))?;
    let onion = elder
        .get("onion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{name} deployment has no Elder Tree onion"))?;
    // Parse the onion now, before Tor is involved. Canopy verification validates the signer.
    shadenet_proto::onion_to_pubkey(onion)
        .map_err(|e| format!("{name} deployment has an invalid Elder Tree onion: {e}"))?;
    let pins: Vec<&str> = match elder.get("canopySigner") {
        Some(serde_json::Value::String(pin)) => vec![pin.as_str()],
        Some(serde_json::Value::Array(pins)) => pins
            .iter()
            .map(|pin| {
                pin.as_str()
                    .ok_or_else(|| format!("{name} deployment has a non-string canopy signer"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(format!("{name} deployment has no canopy signer")),
    };
    if pins.is_empty()
        || pins
            .iter()
            .any(|pin| pin.len() != 64 || hex::decode(pin).map_or(true, |bytes| bytes.len() != 32))
    {
        return Err(format!("{name} deployment has an invalid canopy signer"));
    }
    let admission = deployment.get("admission");
    let default_path = admission
        .and_then(|value| value.get("defaultPath"))
        .or_else(|| deployment.get("defaultPath"))
        .map(|value| {
            value
                .as_str()
                .map(|path| path.to_ascii_lowercase())
                .ok_or_else(|| format!("{name} deployment defaultPath must be a string"))
        })
        .transpose()?;
    let rate_policy = deployment
        .get("ratePolicy")
        .or_else(|| admission.and_then(|value| value.get("ratePolicy")))
        .map(parse_rate)
        .transpose()?;
    let staked = admission
        .and_then(|value| value.pointer("/roots/staked"))
        .filter(|value| !value.is_null())
        .map(parse_staked)
        .transpose()?;
    Ok(Deployment {
        elder_onion: onion.to_string(),
        canopy_signer: pins.join(","),
        default_path,
        rate_policy,
        staked,
    })
}

fn parse_staked(value: &serde_json::Value) -> Result<StakedRoot, String> {
    let contract = value
        .get("contract")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "staked root has no contract".to_string())?;
    let rpc_url = value
        .get("rpcUrl")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "staked root has no RPC".to_string())?;
    let optional_string = |name: &str| {
        value
            .get(name)
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("staked root {name} must be a string"))
            })
            .transpose()
    };
    let tiers = value
        .get("tiers")
        .map(|tiers| {
            tiers
                .as_array()
                .ok_or_else(|| "staked root tiers must be an array".to_string())?
                .iter()
                .map(|tier| {
                    let limit = tier
                        .get("limit")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| {
                            "staked tier limit must be an unsigned integer".to_string()
                        })?;
                    let bond_wei = tier
                        .get("bondWei")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| "staked tier bondWei must be a string".to_string())?;
                    Ok(Tier {
                        limit,
                        bond_wei: bond_wei.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .transpose()?;
    Ok(StakedRoot {
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
}

/// Validate the public staking path. Values are checked for shape and consistency, never against
/// constants: the economics belong to the record.
pub fn public_profile_from(deployment: Deployment) -> Result<PublicProfile, String> {
    let default_path = deployment
        .default_path
        .ok_or_else(|| "deployment has no admission.defaultPath".to_string())?;
    if default_path != "staked" {
        return Err(format!(
            "deployment defaultPath={default_path:?}; the public profile requires staked"
        ));
    }
    let rate_policy = deployment
        .rate_policy
        .ok_or_else(|| "deployment has no ratePolicy".to_string())?;
    let staked = deployment
        .staked
        .ok_or_else(|| "deployment has no staked admission root".to_string())?;
    if staked.profile.as_deref() != Some("public-stake-v1") {
        return Err("staking root does not declare profile public-stake-v1".into());
    }
    let chain_id = staked
        .chain_id
        .filter(|chain_id| *chain_id > 0)
        .ok_or_else(|| "public staking profile must pin a chainId".to_string())?;
    if !is_address(Some(&staked.contract)) {
        return Err("public staking profile has an invalid contract address".into());
    }
    let tiers = staked
        .tiers
        .clone()
        .filter(|tiers| !tiers.is_empty())
        .ok_or_else(|| "public staking profile must list at least one tier".to_string())?;
    let mut seen = std::collections::BTreeSet::new();
    for tier in &tiers {
        if !(1..=MAX_LIMIT).contains(&tier.limit) || !seen.insert(tier.limit) {
            return Err(format!(
                "public staking tier limit {} is out of range or repeated",
                tier.limit
            ));
        }
        if tier.bond_wei.is_empty()
            || !tier.bond_wei.bytes().all(|b| b.is_ascii_digit())
            || tier.bond_wei.bytes().all(|b| b == b'0')
        {
            return Err(format!(
                "public staking tier {} must bond a positive decimal wei amount",
                tier.limit
            ));
        }
    }
    if !is_address(staked.hasher.as_deref()) || !is_address(staked.withdraw_verifier.as_deref()) {
        return Err("public staking profile must pin hasher and withdrawVerifier addresses".into());
    }
    if staked
        .deploy_tx
        .as_deref()
        .is_none_or(|tx| tx.len() != 66 || !tx.starts_with("0x") || hex::decode(&tx[2..]).is_err())
    {
        return Err("public staking profile must pin a deployment transaction".into());
    }
    let (unbonding_seconds, min_unbonding_seconds) =
        match (staked.unbonding_seconds, staked.min_unbonding_seconds) {
            (Some(unbonding), Some(minimum)) if minimum > 0 && unbonding >= minimum => {
                (unbonding, minimum)
            }
            _ => {
                return Err(
                    "public staking profile must pin unbondingSeconds >= minUnbondingSeconds > 0"
                        .into(),
                )
            }
        };
    let deploy_block = staked
        .deploy_block
        .ok_or_else(|| "staked admission root has no deployBlock".to_string())?;
    let default_limit = staked
        .default_limit
        .filter(|limit| (1..=MAX_LIMIT).contains(limit))
        .ok_or_else(|| "staked admission root has no valid defaultLimit".to_string())?;
    if !tiers.iter().any(|tier| tier.limit == default_limit) {
        return Err(format!(
            "staked defaultLimit {default_limit} is not one of the listed tiers"
        ));
    }
    Ok(PublicProfile {
        default_path,
        rate_policy,
        contract: staked.contract,
        rpc_url: staked.rpc_url,
        chain_id,
        deploy_block,
        default_limit,
        tiers,
        unbonding_seconds,
        min_unbonding_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn public_fixture() -> serde_json::Value {
        let mut deployment: serde_json::Value = serde_json::from_str(SEPOLIA_DEPLOYMENT).unwrap();
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
        staked["contract"] = json!("0x3333333333333333333333333333333333333333");
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

    fn profile_of(value: &serde_json::Value) -> Result<PublicProfile, String> {
        public_profile_from(parse_deployment("test", &value.to_string())?)
    }

    #[test]
    fn bundled_elder_and_signer_are_valid() {
        let (onion, signer) = Network::bundled(DEFAULT_NETWORK).unwrap().discovery();
        assert!(onion.ends_with(".onion"));
        assert_eq!(signer.len(), 64);
    }

    #[test]
    fn public_profile_reads_economics_from_the_record() {
        let profile = profile_of(&public_fixture()).unwrap();
        assert_eq!(profile.default_path, "staked");
        assert_eq!(profile.default_limit, 1);
        assert_eq!(profile.chain_id, 11_155_111);
        assert_eq!(profile.deploy_block, 12_345);
        assert_eq!(profile.rate_policy.epoch_seconds, 60);
        assert_eq!(profile.tiers.len(), 2);

        // A re-priced network (the H2 economics pass) is a record change, not a code change.
        let mut repriced = public_fixture();
        let staked = &mut repriced["admission"]["roots"]["staked"];
        staked["tiers"] = json!([
            { "limit": 2, "bondWei": "50000000000000000" },
            { "limit": 16, "bondWei": "400000000000000000" }
        ]);
        staked["defaultLimit"] = json!(2);
        staked["unbondingSeconds"] = json!(172_800);
        repriced["ratePolicy"]["epochSeconds"] = json!(120);
        let profile = profile_of(&repriced).unwrap();
        assert_eq!(profile.default_limit, 2);
        assert_eq!(profile.tiers[1].bond_wei, "400000000000000000");
        assert_eq!(profile.rate_policy.epoch_seconds, 120);
        assert_eq!(profile.unbonding_seconds, 172_800);
    }

    #[test]
    fn public_profile_rejects_inconsistent_records() {
        let mut absent = public_fixture();
        absent.as_object_mut().unwrap().remove("ratePolicy");
        absent["admission"]
            .as_object_mut()
            .unwrap()
            .remove("ratePolicy");
        assert!(profile_of(&absent).unwrap_err().contains("no ratePolicy"));

        let mut default_not_a_tier = public_fixture();
        default_not_a_tier["admission"]["roots"]["staked"]["defaultLimit"] = json!(4);
        assert!(profile_of(&default_not_a_tier)
            .unwrap_err()
            .contains("not one of the listed tiers"));

        let mut zero_bond = public_fixture();
        zero_bond["admission"]["roots"]["staked"]["tiers"][0]["bondWei"] = json!("0");
        assert!(profile_of(&zero_bond).unwrap_err().contains("positive"));

        let mut short_unbonding = public_fixture();
        short_unbonding["admission"]["roots"]["staked"]["unbondingSeconds"] = json!(60);
        assert!(profile_of(&short_unbonding)
            .unwrap_err()
            .contains("unbondingSeconds"));

        let mut no_chain = public_fixture();
        no_chain["admission"]["roots"]["staked"]
            .as_object_mut()
            .unwrap()
            .remove("chainId");
        assert!(profile_of(&no_chain).unwrap_err().contains("chainId"));
    }

    #[test]
    fn resolve_accepts_a_name_or_a_record_path() {
        assert_eq!(Network::resolve("sepolia").unwrap().name, "sepolia");
        assert_eq!(Network::resolve("").unwrap().name, "sepolia");
        assert!(Network::resolve("no-such-network").is_err());
        let dir = std::env::temp_dir().join(format!("shadenet-profile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut record = public_fixture();
        record["network"] = json!("sepolia-staging");
        std::fs::write(dir.join("deployment.json"), record.to_string()).unwrap();
        let network = Network::resolve(dir.to_str().unwrap()).unwrap();
        assert_eq!(network.name, "sepolia-staging");
        assert_eq!(network.public_profile().unwrap().default_limit, 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
