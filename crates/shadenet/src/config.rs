//! Client configuration.
//!
//! [`Config::builder`] starts from the zero-configuration public path of a network (the bundled
//! Sepolia record by default). Every override is explicit; nothing here reads the environment.
//! The CLI maps flags and `SHADENET_*` variables onto this builder.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::capability::Requirement;
use crate::dircache::MaxAge;
use crate::profile::Network;
use crate::Error;

/// Where the candidate nodes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// Fetch the signed canopy from the network record's Elder Tree over Tor.
    Network,
    /// Fetch the signed canopy from this Elder Tree onion, verified against `signers`.
    ElderTree { onion: String, signers: String },
    /// Read a signed canopy from a file (offline and tests), verified against `signers`.
    CanopyFile { path: PathBuf, signers: String },
    /// Dial these onion services in order. No canopy, no caps checks.
    Onions(Vec<String>),
    /// Dial these `host:port` addresses in order without Tor. Test harnesses only: it exposes the
    /// client's IP to the node. Not available in release builds of the CLI.
    PlainTcp(Vec<String>),
}

/// Where the ordered member set comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Members {
    /// The network's staking contract (or, for `leaf_source = demo`, the canopy's demo advert).
    Auto,
    /// A local `{ "members": [...] }` file.
    File(PathBuf),
    /// Reconstruct the set from this contract's events.
    Contract(String),
}

/// The member identity used to prove.
#[derive(Clone)]
pub enum Identity {
    /// A `{ identitySecret, leaf, limit }` file written by `shadenet init` / `enroll`.
    File(PathBuf),
    /// Identity material held in memory (zeroized on drop).
    Material {
        secret: Zeroizing<String>,
        leaf: String,
        limit: Option<u64>,
    },
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Material { leaf, limit, .. } => f
                .debug_struct("Material")
                .field("secret", &"<redacted>")
                .field("leaf", leaf)
                .field("limit", limit)
                .finish(),
        }
    }
}

/// How RLN message slots are allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slots {
    /// Crash-safe cursor at the default path (shared with the JS client), keyed by the leaf.
    CrashSafe,
    /// Crash-safe cursor at an explicit path.
    Cursor(PathBuf),
    /// A fixed slot with no persistence. Reuses nullifiers: only for isolated slashing tests.
    UnsafeForSlashingTest(u64),
}

/// Everything a [`crate::Client`] needs.
#[derive(Clone)]
pub struct Config {
    pub network: Network,
    pub discovery: Discovery,
    pub identity: Option<Identity>,
    pub members: Members,
    pub rpc_url: Option<String>,
    pub from_block: Option<u64>,
    pub block_tag: Option<String>,
    pub leaf_source: Option<String>,
    pub max_anon: bool,
    pub limit: Option<u64>,
    pub epoch_seconds: Option<u64>,
    /// Prove for this epoch instead of the current one (tests and reproductions).
    pub epoch: Option<u64>,
    pub rln_identifier: String,
    pub slots: Slots,
    pub circuits_dir: Option<PathBuf>,
    /// Directory for the canopy last-known-good copy and node health. `None` keeps both in memory.
    pub cache_dir: Option<PathBuf>,
    /// Explicit canopy LKG file (overrides `cache_dir` for the canopy).
    pub canopy_cache: Option<PathBuf>,
    /// Explicit health file (overrides `cache_dir` for health).
    pub health_cache: Option<PathBuf>,
    pub max_age: MaxAge,
    pub rotation_spread: bool,
    pub requirement: Requirement,
    pub tor_timeout: Duration,
    pub ack_timeout: Duration,
    pub prover_workers: usize,
    /// How often a long-lived client refreshes the canopy.
    pub canopy_refresh: Duration,
    /// How long a member set is reused before it is fetched again.
    pub member_refresh: Duration,
    /// How long a last-known-good canopy may keep serving when EVERY Elder Tree is unreachable
    /// (status reports `canopy.stale` once past it and `connect`/`fetch` fail closed with a
    /// `canopy` error). Default 1 h: long enough to ride out an Elder outage, short enough that
    /// a client cannot keep using a directory the operators retired.
    pub canopy_max_stale: Duration,
    /// Arti state and cache directories. `None` uses ShadeNet's own defaults.
    pub tor_directories: Option<(PathBuf, PathBuf)>,
    /// Fixed per-request nonce (reproducible runs). `None` draws a random one per tunnel.
    pub nonce: Option<String>,
    /// Session tickets (#103): off until the economics pass turns them on.
    pub session_tickets: bool,
    /// Passphrase for an encrypted identity file. Never printed by `Debug`.
    pub passphrase: Option<Zeroizing<String>>,
    /// Queue a tunnel whose epoch budget is spent for at most this long before refusing it
    /// (ADR 0013). `None` refuses at once with `budget_exhausted`. The CLI defaults the proxy,
    /// `mcp` and `fetch` to two epochs; SDK callers opt in.
    pub queue_max_wait: Option<Duration>,
    /// After a node refuses a tunnel for an `upstream:*` reason, try once more on another node
    /// when the budget allows (ADR 0013).
    pub retry_other_node: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network.name)
            .field("discovery", &self.discovery)
            .field("identity", &self.identity)
            .field("members", &self.members)
            .field("leaf_source", &self.leaf_source)
            .field("limit", &self.limit)
            .field("slots", &self.slots)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// True when this configuration uses the network's zero-configuration public profile: bundled
    /// discovery, staking-contract members and no explicit leaf source. An RPC override keeps it.
    pub fn uses_public_profile(&self) -> bool {
        self.discovery == Discovery::Network
            && self.members == Members::Auto
            && self.leaf_source.is_none()
    }
}

/// Builder for [`Config`].
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    config: Config,
    network_error: Option<String>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        let (network, network_error) = match Network::bundled(crate::profile::DEFAULT_NETWORK) {
            Ok(network) => (network, None),
            Err(error) => (
                Network {
                    name: crate::profile::DEFAULT_NETWORK.into(),
                    deployment: crate::profile::Deployment {
                        elder_onion: String::new(),
                        canopy_signer: String::new(),
                        elders: Vec::new(),
                        default_path: None,
                        rate_policy: None,
                        staked: None,
                        session_tickets: false,
                        node_commit: None,
                    },
                },
                Some(error.to_string()),
            ),
        };
        Self {
            config: Config {
                network,
                discovery: Discovery::Network,
                identity: None,
                members: Members::Auto,
                rpc_url: None,
                from_block: None,
                block_tag: None,
                leaf_source: None,
                max_anon: false,
                limit: None,
                epoch_seconds: None,
                epoch: None,
                rln_identifier: "1".into(),
                slots: Slots::CrashSafe,
                circuits_dir: None,
                cache_dir: default_cache_dir(),
                canopy_cache: None,
                health_cache: None,
                max_age: MaxAge {
                    max_age_ms: None,
                    skew_ms: 5 * 60 * 1000,
                },
                rotation_spread: true,
                requirement: Requirement::default(),
                tor_timeout: Duration::from_secs(180),
                ack_timeout: Duration::from_secs(15),
                prover_workers: 2,
                canopy_refresh: Duration::from_secs(300),
                member_refresh: Duration::from_secs(30),
                canopy_max_stale: Duration::from_secs(3600),
                tor_directories: default_tor_directories(),
                nonce: None,
                session_tickets: false,
                passphrase: None,
                queue_max_wait: None,
                retry_other_node: true,
            },
            network_error,
        }
    }
}

macro_rules! setter {
    ($(#[$meta:meta])* $name:ident: $ty:ty) => {
        $(#[$meta])*
        pub fn $name(mut self, value: $ty) -> Self {
            self.config.$name = value;
            self
        }
    };
}

impl ConfigBuilder {
    /// Use this network record (bundled or loaded from a file).
    pub fn network(mut self, network: Network) -> Self {
        // The record decides the session-ticket default (H2 flips `sessionTickets`); an explicit
        // `session_tickets(..)` after this call still wins.
        self.config.session_tickets = network.deployment.session_tickets;
        self.config.network = network;
        self.network_error = None;
        self
    }

    /// Identity from an identity file.
    pub fn identity_file(mut self, path: impl AsRef<Path>) -> Self {
        self.config.identity = Some(Identity::File(path.as_ref().to_path_buf()));
        self
    }

    setter!(identity: Option<Identity>);
    setter!(discovery: Discovery);
    setter!(members: Members);
    setter!(rpc_url: Option<String>);
    setter!(from_block: Option<u64>);
    setter!(block_tag: Option<String>);
    setter!(leaf_source: Option<String>);
    setter!(max_anon: bool);
    setter!(limit: Option<u64>);
    setter!(epoch_seconds: Option<u64>);
    setter!(epoch: Option<u64>);
    setter!(rln_identifier: String);
    setter!(slots: Slots);
    setter!(circuits_dir: Option<PathBuf>);
    setter!(cache_dir: Option<PathBuf>);
    setter!(canopy_cache: Option<PathBuf>);
    setter!(health_cache: Option<PathBuf>);
    setter!(max_age: MaxAge);
    setter!(rotation_spread: bool);
    setter!(requirement: Requirement);
    setter!(tor_timeout: Duration);
    setter!(ack_timeout: Duration);
    setter!(prover_workers: usize);
    setter!(canopy_refresh: Duration);
    setter!(member_refresh: Duration);
    setter!(canopy_max_stale: Duration);
    setter!(tor_directories: Option<(PathBuf, PathBuf)>);
    setter!(nonce: Option<String>);
    setter!(
        /// Passphrase for an encrypted identity file.
        passphrase: Option<Zeroizing<String>>
    );
    setter!(
        /// Session tickets are a research flag (#103) and off by default.
        session_tickets: bool
    );
    setter!(
        /// Hold a tunnel whose budget is spent for at most this long instead of refusing it.
        queue_max_wait: Option<Duration>
    );
    setter!(
        /// Retry once on another node after an `upstream:*` refusal.
        retry_other_node: bool
    );

    /// Validate and finish.
    pub fn build(self) -> Result<Config, Error> {
        if let Some(error) = self.network_error {
            return Err(Error::Config(error));
        }
        let config = self.config;
        if let Some(source) = &config.leaf_source {
            if source != "demo" && !shadenet_proto::ADMIT_PATHS.contains(&source.as_str()) {
                return Err(Error::Config(format!(
                    "leaf source must be invited, staked, paid or demo (got {source})"
                )));
            }
            if config.max_anon && source != "invited" {
                return Err(Error::Config(format!(
                    "max-anon requires an invited (members.json) leaf; your leaf is in the {source} set"
                )));
            }
        }
        if let Some(limit) = config.limit {
            if !(1..=crate::profile::MAX_LIMIT).contains(&limit) {
                return Err(Error::Config(format!(
                    "limit {limit} is outside 1..={} (the RLN range check is 16-bit)",
                    crate::profile::MAX_LIMIT
                )));
            }
        }
        if config.epoch_seconds == Some(0) {
            return Err(Error::Config("epoch seconds must be positive".into()));
        }
        if !(1..=64).contains(&config.prover_workers) {
            return Err(Error::Config("prover workers must be in 1..=64".into()));
        }
        if let Discovery::Onions(list) | Discovery::PlainTcp(list) = &config.discovery {
            if list.is_empty() {
                return Err(Error::Config("no dial targets given".into()));
            }
        }
        if let Some(nonce) = &config.nonce {
            if nonce.len() != 32 || hex::decode(nonce).is_err() {
                return Err(Error::Config("nonce must be 32 hex characters".into()));
            }
        }
        Ok(config)
    }
}

fn base_dir(env_key: &str, home_suffix: &[&str], windows_key: &str) -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(env_key).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(value));
    }
    if cfg!(windows) {
        return std::env::var_os(windows_key).map(PathBuf::from);
    }
    let mut path = PathBuf::from(std::env::var_os("HOME")?);
    for part in home_suffix {
        path.push(part);
    }
    Some(path)
}

/// `$XDG_CACHE_HOME/shadenet` (or the platform equivalent): canopy LKG and node health.
pub fn default_cache_dir() -> Option<PathBuf> {
    base_dir("XDG_CACHE_HOME", &[".cache"], "LOCALAPPDATA").map(|base| base.join("shadenet"))
}

/// `$XDG_STATE_HOME/shadenet/arti` and `$XDG_CACHE_HOME/shadenet/arti`: Arti's own directories.
pub fn default_tor_directories() -> Option<(PathBuf, PathBuf)> {
    let state = base_dir("XDG_STATE_HOME", &[".local", "state"], "LOCALAPPDATA")?;
    let cache = default_cache_dir()?;
    Some((state.join("shadenet").join("arti"), cache.join("arti")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_select_the_public_profile() {
        let config = Config::builder().cache_dir(None).build().unwrap();
        assert!(config.uses_public_profile());
        assert_eq!(config.network.name, "sepolia");
        assert!(!config.session_tickets);
        let custom = Config::builder()
            .members(Members::Contract("0x1".into()))
            .build()
            .unwrap();
        assert!(!custom.uses_public_profile());
        let rpc_only = Config::builder()
            .rpc_url(Some("https://rpc.example".into()))
            .build()
            .unwrap();
        assert!(rpc_only.uses_public_profile());
    }

    #[test]
    fn builder_rejects_bad_inputs_before_any_network_io() {
        assert!(Config::builder()
            .leaf_source(Some("vip".into()))
            .build()
            .is_err());
        assert!(Config::builder()
            .leaf_source(Some("staked".into()))
            .max_anon(true)
            .build()
            .is_err());
        assert!(Config::builder().limit(Some(0)).build().is_err());
        assert!(Config::builder().limit(Some(70_000)).build().is_err());
        assert!(Config::builder()
            .discovery(Discovery::Onions(vec![]))
            .build()
            .is_err());
        assert!(Config::builder().nonce(Some("xyz".into())).build().is_err());
    }

    #[test]
    fn identity_debug_never_prints_the_secret() {
        let identity = Identity::Material {
            secret: Zeroizing::new("123456789".into()),
            leaf: "42".into(),
            limit: Some(1),
        };
        let shown = format!("{identity:?}");
        assert!(!shown.contains("123456789"));
        assert!(shown.contains("redacted"));
    }
}
