//! Network flags shared by `status`, `doctor`, `proxy`, `mcp`, `fetch` and `egress`, and how they
//! become a [`shadenet::Config`]. Precedence: flag, then `SHADENET_*` (or `SHADE_TREE_*`), then the
//! config file, then the network record's defaults.

use std::path::PathBuf;

use clap::Args;

use crate::config_file::ConfigFile;

/// Global state every command can read.
pub struct Context {
    pub network: Option<String>,
    pub file: ConfigFile,
}

#[derive(Args, Debug, Default, Clone)]
#[command(next_help_heading = "Network")]
pub struct NetArgs {
    /// Identity file [env: SHADENET_IDENTITY]
    #[arg(long, value_name = "PATH")]
    pub identity: Option<PathBuf>,
    /// Member set file instead of on-chain discovery
    #[arg(long, value_name = "PATH")]
    pub members: Option<PathBuf>,
    /// Staking or paid-access contract [env: SHADENET_GROUP_CONTRACT, SHADENET_PAID_ACCESS_CONTRACT]
    #[arg(long)]
    pub contract: Option<String>,
    /// JSON-RPC URL for member discovery [env: SHADENET_RPC_URL]
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// First block of member events (decimal or 0x hex) [env: SHADENET_FROM_BLOCK]
    #[arg(long)]
    pub from_block: Option<String>,
    /// Block tag for member reads (the public network uses finalized)
    #[arg(long)]
    pub block_tag: Option<String>,
    /// Which set your leaf is in: invited, staked, paid or demo [env: SHADENET_LEAF_SOURCE]
    #[arg(long)]
    pub leaf_source: Option<String>,
    /// Use only invited-only nodes [env: SHADENET_MAX_ANON]
    #[arg(long)]
    pub max_anon: bool,
    /// Tier (userMessageLimit) of your leaf [env: SHADENET_LIMIT]
    #[arg(long, alias = "limit")]
    pub k: Option<u64>,
    /// Prove for this epoch instead of the current one
    #[arg(long)]
    pub epoch: Option<u64>,
    /// RLN identifier [env: SHADENET_RLN_IDENTIFIER] [default: 1]
    #[arg(long)]
    pub rln_identifier: Option<String>,
    /// Directory with rln.wasm, rln_final.zkey and verification_key.json (default: embedded)
    #[arg(long, value_name = "DIR")]
    pub circuits: Option<PathBuf>,
    /// Exact slot-state file [env: SHADENET_SLOT_CURSOR]
    #[arg(long, value_name = "PATH")]
    pub slot_cursor: Option<PathBuf>,
    /// Fixed slot; needs --unsafe-allow-slot-reuse-for-slashing-tests
    #[arg(long, hide = true)]
    pub slot: Option<u64>,
    /// Reuse slots without persistence. Gets a funded member slashed. Isolated tests only.
    #[arg(long, hide = true)]
    pub unsafe_allow_slot_reuse_for_slashing_tests: bool,
    /// Fixed 32-hex nonce (reproducible runs)
    #[arg(long, hide = true)]
    pub nonce: Option<String>,

    /// Read the signed canopy from this file
    #[arg(long, value_name = "PATH", help_heading = "Discovery")]
    pub directory: Option<PathBuf>,
    /// Pinned canopy signer(s), comma-separated hex
    #[arg(long, alias = "signers", help_heading = "Discovery")]
    pub signer: Option<String>,
    /// Fetch the canopy from this Elder Tree onion
    #[arg(
        long,
        alias = "elder",
        value_name = "ONION",
        help_heading = "Discovery"
    )]
    pub bootnode_onion: Option<String>,
    /// Dial these node onions in order, skipping the canopy
    #[arg(long, value_name = "ONION[:PORT],...", help_heading = "Discovery")]
    pub onion: Option<String>,
    /// Dial host:port without Tor (debug builds only; test harnesses)
    #[arg(long, value_name = "HOST:PORT,...", hide = true)]
    pub plain_tcp: Option<String>,
    /// Canopy last-known-good file
    #[arg(long, value_name = "PATH", help_heading = "Discovery")]
    pub cache: Option<PathBuf>,
    /// Node health file
    #[arg(long, value_name = "PATH", help_heading = "Discovery")]
    pub health_cache: Option<PathBuf>,
    /// Keep the canopy and node health in memory only
    #[arg(long, help_heading = "Discovery")]
    pub no_cache: bool,
    /// Refuse a fresh canopy older than this
    #[arg(long, help_heading = "Discovery")]
    pub max_age_ms: Option<u64>,
    #[arg(long, hide = true)]
    pub max_age_skew_ms: Option<u64>,
    /// Spread first picks across nodes (default on) [env: SHADENET_ROTATION_SPREAD]
    #[arg(long, num_args = 0..=1, default_missing_value = "true", help_heading = "Discovery")]
    pub rotation_spread: Option<String>,
    #[arg(long, hide = true)]
    pub no_rotation_spread: bool,
    /// Require nodes that egress to this port
    #[arg(long, help_heading = "Discovery")]
    pub port: Option<u64>,
    /// Require nodes that accept this protocol version
    #[arg(long, help_heading = "Discovery")]
    pub proto: Option<u64>,
    /// Require nodes in this region bucket
    #[arg(long, help_heading = "Discovery")]
    pub region: Option<String>,
}

fn env(name: &str) -> Result<Option<String>, String> {
    Ok(shadenet::env::var(name)?.filter(|value| !value.trim().is_empty()))
}

fn parse_block(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .map_err(|_| format!("invalid block number {raw:?}"))
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Context {
    /// The selected network record.
    pub fn network(&self) -> Result<shadenet::Network, String> {
        let spec = match &self.network {
            Some(spec) => Some(spec.clone()),
            None => env("NETWORK")?.or_else(|| self.file.network.clone()),
        };
        shadenet::Network::resolve(
            spec.as_deref()
                .unwrap_or(shadenet::profile::DEFAULT_NETWORK),
        )
        .map_err(|e| e.to_string())
    }

    /// Identity path from flag, env or config file.
    pub fn identity_path(&self, flag: Option<&PathBuf>) -> Result<Option<PathBuf>, String> {
        Ok(match flag {
            Some(path) => Some(path.clone()),
            None => env("IDENTITY")?
                .map(PathBuf::from)
                .or_else(|| self.file.identity.clone()),
        })
    }
}

impl NetArgs {
    /// Build the SDK configuration. `need_identity` makes a missing identity an error.
    pub fn to_config(
        &self,
        ctx: &Context,
        need_identity: bool,
    ) -> Result<shadenet::Config, String> {
        use shadenet::{Discovery, Members, Slots};

        let network = ctx.network()?;
        let mut builder = shadenet::Config::builder().network(network);

        // Identity.
        match ctx.identity_path(self.identity.as_ref())? {
            Some(path) => builder = builder.identity_file(path),
            None if need_identity => {
                return Err(
                    "no identity: pass --identity, set SHADENET_IDENTITY, or run `shadenet init`"
                        .into(),
                )
            }
            None => {}
        }

        // Discovery, most specific first.
        let discovery = if let Some(list) = &self.plain_tcp {
            if !cfg!(debug_assertions) {
                return Err(
                    "--plain-tcp bypasses Tor and exposes your IP to the node; it exists only in debug builds for test harnesses"
                        .into(),
                );
            }
            Discovery::PlainTcp(split_list(list))
        } else if let Some(list) = &self.onion {
            Discovery::Onions(split_list(list))
        } else if let Some(onion) = &self.bootnode_onion {
            let signers = self
                .signer
                .clone()
                .ok_or("--bootnode-onion needs --signer <hex>")?;
            Discovery::ElderTree {
                onion: onion.clone(),
                signers,
            }
        } else if let Some(path) = &self.directory {
            let signers = self
                .signer
                .clone()
                .ok_or("--directory needs --signer <hex>")?;
            Discovery::CanopyFile {
                path: path.clone(),
                signers,
            }
        } else {
            Discovery::Network
        };
        builder = builder.discovery(discovery);

        // Admission.
        let leaf_source = match &self.leaf_source {
            Some(source) => Some(source.trim().to_ascii_lowercase()),
            None => env("LEAF_SOURCE")?
                .or_else(|| ctx.file.leaf_source.clone())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| s != "auto"),
        };
        let max_anon =
            self.max_anon || env("MAX_ANON")?.as_deref().and_then(parse_bool) == Some(true);
        builder = builder.leaf_source(leaf_source.clone()).max_anon(max_anon);

        // Members: explicit file or contract, then environment (never over a demo advert), then
        // the config file, then the network's staking contract.
        let members = if let Some(path) = self.members.clone().or_else(|| ctx.file.members.clone())
        {
            Members::File(path)
        } else if let Some(contract) = &self.contract {
            Members::Contract(contract.clone())
        } else if leaf_source.as_deref() == Some("demo") {
            Members::Auto
        } else if let Some(paid) =
            env("PAID_ACCESS_CONTRACT")?.filter(|_| leaf_source.as_deref() == Some("paid"))
        {
            Members::Contract(paid)
        } else if let Some(group) = env("GROUP_CONTRACT")? {
            Members::Contract(split_list(&group).into_iter().next().unwrap_or_default())
        } else if let Some(contract) = &ctx.file.contract {
            Members::Contract(contract.clone())
        } else {
            Members::Auto
        };
        builder = builder.members(members);

        let rpc_url = match &self.rpc_url {
            Some(url) => Some(url.clone()),
            None => env("RPC_URL")?.or_else(|| ctx.file.rpc_url.clone()),
        };
        builder = builder.rpc_url(rpc_url);
        let from_block = match &self.from_block {
            Some(raw) => Some(raw.clone()),
            None => env("FROM_BLOCK")?,
        };
        builder = builder.from_block(from_block.as_deref().map(parse_block).transpose()?);
        builder = builder.block_tag(self.block_tag.clone());

        // Tier, epoch, slots.
        let limit = match self.k {
            Some(k) => Some(k),
            None => env("LIMIT")?
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| format!("SHADENET_LIMIT must be an integer (got {v:?})"))
                })
                .transpose()?,
        };
        builder = builder.limit(limit).epoch(self.epoch);
        if let Some(seconds) = env("EPOCH_SECONDS")? {
            builder = builder.epoch_seconds(Some(
                seconds
                    .parse::<u64>()
                    .ok()
                    .filter(|s| *s > 0)
                    .ok_or("SHADENET_EPOCH_SECONDS must be a positive integer")?,
            ));
        }
        let rln_identifier = match &self.rln_identifier {
            Some(id) => id.clone(),
            None => env("RLN_IDENTIFIER")?.unwrap_or_else(|| "1".into()),
        };
        builder = builder.rln_identifier(rln_identifier);
        let slots = if self.unsafe_allow_slot_reuse_for_slashing_tests {
            Slots::UnsafeForSlashingTest(self.slot.unwrap_or(0))
        } else if self.slot.is_some() {
            return Err("--slot bypasses crash-safe allocation; it requires --unsafe-allow-slot-reuse-for-slashing-tests and is only for isolated slashing tests".into());
        } else {
            let cursor = match &self.slot_cursor {
                Some(path) => Some(path.display().to_string()),
                None => env("SLOT_CURSOR")?,
            };
            match cursor {
                Some(value) => {
                    let value = value.trim().to_string();
                    if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("off") {
                        return Err("the slot cursor cannot disable slot safety".into());
                    }
                    Slots::Cursor(PathBuf::from(value))
                }
                None => Slots::CrashSafe,
            }
        };
        builder = builder
            .slots(slots)
            .circuits_dir(self.circuits.clone())
            .nonce(self.nonce.clone());

        // Caches.
        if self.no_cache {
            builder = builder.cache_dir(None);
        } else if let Some(dir) = &ctx.file.cache_dir {
            builder = builder.cache_dir(Some(dir.clone()));
        }
        builder = builder
            .canopy_cache(self.cache.clone())
            .health_cache(self.health_cache.clone());
        let mut max_age = shadenet::dircache::MaxAge {
            max_age_ms: self.max_age_ms,
            skew_ms: 5 * 60 * 1000,
        };
        if let Some(skew) = self.max_age_skew_ms {
            max_age.skew_ms = skew;
        }
        builder = builder.max_age(max_age);
        let rotation = if self.no_rotation_spread {
            false
        } else if let Some(raw) = &self.rotation_spread {
            parse_bool(raw).unwrap_or(true)
        } else {
            env("ROTATION_SPREAD")?
                .as_deref()
                .and_then(parse_bool)
                .unwrap_or(true)
        };
        builder =
            builder
                .rotation_spread(rotation)
                .requirement(shadenet::capability::Requirement {
                    port: self.port,
                    proto: self.proto,
                    region: self.region.clone(),
                });

        // Timeouts and pool size.
        if let Some(secs) = shadenet::env::parse::<u64>("TOR_TIMEOUT_SECS").filter(|s| *s > 0) {
            builder = builder.tor_timeout(std::time::Duration::from_secs(secs));
        }
        if let Some(secs) =
            shadenet::env::parse::<u64>("GATEWAY_ACK_TIMEOUT_SECS").filter(|s| *s > 0)
        {
            builder = builder.ack_timeout(std::time::Duration::from_secs(secs));
        }
        if let Some(workers) =
            shadenet::env::parse::<usize>("PROVER_WORKERS").or(ctx.file.prover_workers)
        {
            builder = builder.prover_workers(workers);
        }
        builder.build().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            network: None,
            file: ConfigFile::default(),
        }
    }

    #[test]
    fn flags_map_onto_the_sdk_config() {
        let args = NetArgs {
            identity: Some("id.json".into()),
            members: Some("m.json".into()),
            k: Some(4),
            directory: Some("canopy.json".into()),
            signer: Some("ab".into()),
            no_cache: true,
            rotation_spread: Some("0".into()),
            ..NetArgs::default()
        };
        let config = args.to_config(&ctx(), true).unwrap();
        assert_eq!(config.limit, Some(4));
        assert_eq!(config.members, shadenet::Members::File("m.json".into()));
        assert!(matches!(
            config.discovery,
            shadenet::Discovery::CanopyFile { .. }
        ));
        assert!(config.cache_dir.is_none());
        assert!(!config.rotation_spread);
        assert!(!config.uses_public_profile());
    }

    #[test]
    fn unsafe_slots_need_the_loud_flag() {
        let args = NetArgs {
            slot: Some(1),
            ..NetArgs::default()
        };
        assert!(args
            .to_config(&ctx(), false)
            .unwrap_err()
            .contains("unsafe"));
        let args = NetArgs {
            slot_cursor: Some("off".into()),
            ..NetArgs::default()
        };
        assert!(args.to_config(&ctx(), false).is_err());
    }

    #[test]
    fn identity_is_required_only_when_asked() {
        let args = NetArgs::default();
        assert!(args.to_config(&ctx(), false).is_ok());
        let error = args.to_config(&ctx(), true);
        // SHADENET_IDENTITY may be set in a developer shell; only assert when it is not.
        if shadenet::env::var("IDENTITY").ok().flatten().is_none() {
            assert!(error.unwrap_err().contains("no identity"));
        }
    }

    #[test]
    fn blocks_parse_in_decimal_and_hex() {
        assert_eq!(parse_block("0x10").unwrap(), 16);
        assert_eq!(parse_block("16").unwrap(), 16);
        assert!(parse_block("sixteen").is_err());
    }
}
