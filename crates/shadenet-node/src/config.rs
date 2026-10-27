//! Node settings. Two ways in, one `Config` out:
//!
//! - the operator front door: `SHADENET_RECORD` (or `record` in `<state>/node.toml`) names a
//!   deployment record, the few `SHADENET_*` knobs cover the rest, and the `SHADE_TREE_*`
//!   settings are derived from both (`packages/node/lib/node-config.mjs`). The node then runs
//!   Tor and the heartbeat itself.
//! - the advanced layer: every `SHADENET_*` / `SHADE_TREE_*` variable the JavaScript node read
//!   (`packages/node/gateway/gateway.mjs`, `packages/node/bootnode/heartbeat.mjs`,
//!   `packages/node/lib/rln.mjs`, `root-provider.mjs`, `rpc-safety.mjs`), with the same names
//!   and defaults, and an external Tor.
//!
//! An explicitly set `SHADE_TREE_*` variable always wins over a knob or the record.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use num_bigint::BigUint;
use shadenet_proto::{PayCaps, RateCaps};

use crate::alerts;
use crate::chain::{Contract, Kind};
use crate::drain;
use crate::egress;
use crate::error::Error;
use crate::heartbeat::{self, CapsInputs, EgressCheck, OperatorAuth};
use crate::knobs::{self, Knobs, KNOBS};
use crate::light;
use crate::record::{self, Record};
use crate::rpc;
use crate::session;
use crate::tally;
use crate::telemetry;
use crate::torhttp::Socks;
use crate::verify::ArtifactSet;

const DEFAULT_PORT: u16 = 8443;
const DEFAULT_ENVELOPE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_CONNS: u64 = 1024;
const DEFAULT_MAX_CONNS_PER_NULLIFIER: u64 = 8;
const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_REPLAY_WINDOW_MS: u64 = 5_000;
const DEFAULT_EPOCH_SECONDS: u64 = 120;
const DEFAULT_SLOTS: u64 = 8;
const DEFAULT_LOGS_CHUNK: u64 = 10_000;
const DEFAULT_PAID_MIN_LEAVES: usize = 8;
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const MAX_LIMIT: u64 = 65_535;
const DEFAULT_EGRESS_ALLOW: &str = "*:443";
const DEFAULT_HEARTBEAT_TOR_PORT: u16 = 9250;
const DEFAULT_DRAIN_FILE: &str = "deploy-state/draining";
const DEFAULT_RELAY_COUNTER: &str = "tor/hs/relay-telemetry.local.json";
const DEFAULT_RELAY_REPORT: &str = "tor/hs/relay-report.local.json";
/// Secrets a systemd unit may hand over as credentials instead of environment variables.
const CREDENTIALS: [&str; 3] = ["SLASH_KEY", "GW_OPERATOR_KEY", "FLEET_TALLY_TOKEN"];

/// The version and commit this binary reports.
pub(crate) fn build_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The commit this binary runs: a 40-hex `SHADENET_BUILD_COMMIT` from the image, else the one
/// stamped at build time, else `unknown`.
pub(crate) fn build_commit() -> String {
    let pinned = shadenet::env::var_lenient("BUILD_COMMIT")
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()));
    pinned.unwrap_or_else(|| env!("SHADENET_COMMIT").to_string())
}

/// Where settings are read from: the process environment, or the map the front door derived.
enum Vars {
    Process,
    Derived(BTreeMap<String, String>),
}

impl Vars {
    fn get(&self, name: &str) -> Result<Option<String>, Error> {
        match self {
            Self::Process => {
                let value = shadenet::env::var(name).map_err(Error::Environment)?;
                if value.as_deref().is_some_and(|v| !v.is_empty()) {
                    return Ok(value);
                }
                Ok(credential(name))
            }
            Self::Derived(map) => Ok(map
                .get(&format!("SHADENET_{name}"))
                .or_else(|| map.get(&format!("SHADE_TREE_{name}")))
                .cloned()),
        }
    }
}

/// A systemd credential (`LoadCredential=SHADE_TREE_SLASH_KEY:...`) for one of the secrets.
fn credential(name: &str) -> Option<String> {
    if !CREDENTIALS.contains(&name) {
        return None;
    }
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    let bytes = std::fs::read(Path::new(&dir).join(format!("SHADE_TREE_{name}"))).ok()?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).trim().to_string())
}

/// `SHADE_TREE_ROOT_PROVIDER`: how roots are read from the chain.
pub(crate) enum ProviderConfig {
    Node,
    Light {
        mode: light::Mode,
        /// `SHADE_TREE_HELIOS_RPC_URL` and `SHADE_TREE_HELIOS_CHAIN_ID`.
        helios: Option<(String, Option<u64>)>,
    },
}

/// Everything an on-chain root source needs (`SHADE_TREE_ADMIT` names `staked` or `paid`).
pub(crate) struct ChainConfig {
    pub(crate) provider: ProviderConfig,
    pub(crate) contracts: Vec<Contract>,
    pub(crate) rpc_urls: Vec<String>,
    pub(crate) rpc_timeout: Duration,
    pub(crate) rpc_retries: u64,
    pub(crate) root_freshness: Duration,
    pub(crate) confirmations: u64,
    pub(crate) logs_chunk: u64,
    pub(crate) paid_min_leaves: usize,
}

/// Session tickets (`SHADE_TREE_SESSION_TICKETS=1`).
pub(crate) struct SessionConfig {
    pub(crate) max_sessions: usize,
    pub(crate) stream_max: Option<Duration>,
}

/// The operator process around the node: the state directory, the record, Tor.
pub(crate) struct Operator {
    pub(crate) state_dir: PathBuf,
    pub(crate) hs_dir: PathBuf,
    pub(crate) record_source: String,
    pub(crate) record: Record,
    pub(crate) pow: bool,
    pub(crate) tor_log_level: String,
    pub(crate) register_own_node: bool,
}

/// What the operator banner and the ready line say.
pub(crate) struct Summary {
    pub(crate) admits: Vec<&'static str>,
    pub(crate) egress_allow: String,
    pub(crate) log_level: String,
    pub(crate) log_format: String,
    pub(crate) banner: String,
}

pub struct Config {
    listen: SocketAddr,
    envelope_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    dns_timeout: Option<Duration>,
    max_connections: Option<usize>,
    max_connections_per_nullifier: Option<usize>,
    shutdown_timeout: Duration,
    replay_window: Duration,
    epoch_seconds: u64,
    rln_identifier: BigUint,
    slots: u64,
    tiers: Vec<u64>,
    max_payload_bytes: u64,
    allow_private_targets: bool,
    members_file: Option<PathBuf>,
    chain: Option<ChainConfig>,
    slash_key: Option<String>,
    slash_contract: Option<String>,
    slash_receiver: Option<String>,
    artifacts: Arc<ArtifactSet>,
    spent_state_file: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    receipts: bool,
    sessions: Option<SessionConfig>,
    egress: egress::Policy,
    metrics_port: u16,
    drain_file: PathBuf,
    heartbeat: Option<heartbeat::Settings>,
    alerts: Option<alerts::Settings>,
    tally: Option<tally::Settings>,
    relay_counter: Option<PathBuf>,
    summary: Summary,
    operator: Option<Operator>,
}

struct Admission {
    invited: bool,
    staked: bool,
    paid: bool,
    explicit: bool,
}

impl Admission {
    fn paths(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.invited {
            out.push("invited");
        }
        if self.staked {
            out.push("staked");
        }
        if self.paid {
            out.push("paid");
        }
        out
    }
}

impl Config {
    /// Read every setting from the environment, through the front door when a deployment
    /// record is named. Unset or unparsable numeric values take their default; an explicit
    /// `0` disables a limit. Port 0 asks the kernel for a free port.
    pub fn from_env() -> Result<Self, Error> {
        let process = |name: &str| std::env::var(name).ok();
        let resolved = knobs::load(&process).map_err(|message| Error::Setting {
            name: "SHADENET_STATE",
            message,
        })?;
        if resolved.knobs.record.is_none() {
            // the advanced layer: every variable is checked first, so a conflict or a bad
            // value is named; only a node with nothing configured at all is sent to the record
            return match Self::resolve(&Vars::Process) {
                Err(Error::Setting {
                    name: "SHADE_TREE_MEMBERS_FILE",
                    ..
                }) if !advanced_layer_configured() => Err(Error::Setting {
                    name: "SHADENET_RECORD",
                    message: "set SHADENET_RECORD (the deployment record URL or path); nothing else is required. Run `shadenet-node check` for the full picture. (Without a record, the advanced layer needs SHADE_TREE_MEMBERS_FILE for invited admission or SHADE_TREE_GROUP_CONTRACT with SHADE_TREE_ADMIT=staked.)".into(),
                }),
                other => other,
            };
        }
        if !resolved.errors.is_empty() {
            return Err(Error::Knobs(resolved.errors));
        }
        let knobs = resolved.knobs;
        let record_source = knobs.record.clone().unwrap_or_default();
        let record = record::fetch(&record_source, &knobs.state, true).map_err(Error::Record)?;
        let hs_dir = knobs.hs_dir();
        let mut derived = record::derive_env(&knobs, &record, &explicit_overrides(), &hs_dir);
        if let Some(file) = &knobs.operator_key_file {
            let key = knobs::read_operator_key_file(Path::new(file)).map_err(|message| {
                Error::Setting {
                    name: "SHADENET_OPERATOR_KEY_FILE",
                    message,
                }
            })?;
            derived.insert("SHADE_TREE_GW_OPERATOR_KEY".into(), key);
        }
        let mut config = Self::resolve(&Vars::Derived(derived))?;
        config.operator = Some(Operator {
            state_dir: knobs.state.clone(),
            hs_dir,
            record_source,
            record,
            pow: knobs.pow,
            tor_log_level: process("SHADENET_TOR_LOG").unwrap_or_default(),
            register_own_node: process("SHADENET_REGISTER_OWN_NODE").as_deref() != Some("0"),
        });
        Ok(config)
    }

    /// The log format and level the front door knobs name, for the binary to apply before
    /// anything is logged. `None` without a record (the advanced layer uses
    /// `SHADE_TREE_LOG_FORMAT` and `SHADE_TREE_LOG_LEVEL` directly).
    pub fn log_hint() -> Option<(String, String)> {
        let resolved = knobs::load(&|name| std::env::var(name).ok()).ok()?;
        resolved.knobs.record.as_ref()?;
        Some(resolved.knobs.log_parts())
    }

    fn resolve(vars: &Vars) -> Result<Self, Error> {
        let env_str = |name: &str| vars.get(name);
        let env_int = |name: &str, default: u64| -> Result<u64, Error> {
            Ok(vars
                .get(name)?
                .filter(|raw| !raw.is_empty())
                .and_then(|raw| raw.trim().parse().ok())
                .unwrap_or(default))
        };
        let port = env_int("GATEWAY_PORT", u64::from(DEFAULT_PORT))?;
        let port = u16::try_from(port).unwrap_or(DEFAULT_PORT);
        let envelope_timeout = env_int("ENVELOPE_TIMEOUT_MS", DEFAULT_ENVELOPE_TIMEOUT_MS)?;
        let idle_timeout = env_int("TUNNEL_IDLE_TIMEOUT_MS", DEFAULT_IDLE_TIMEOUT_MS)?;
        let dns_timeout = env_int("DNS_TIMEOUT_MS", DEFAULT_DNS_TIMEOUT_MS)?;
        let max_connections = env_int("MAX_CONNS", DEFAULT_MAX_CONNS)?;
        let per_nullifier = env_int("MAX_CONNS_PER_NULLIFIER", DEFAULT_MAX_CONNS_PER_NULLIFIER)?;
        let shutdown_timeout = env_int("SHUTDOWN_TIMEOUT_MS", DEFAULT_SHUTDOWN_TIMEOUT_MS)?;
        let replay_window = env_int("REPLAY_WINDOW_MS", DEFAULT_REPLAY_WINDOW_MS)?;
        let replay_window = if replay_window == 0 {
            DEFAULT_REPLAY_WINDOW_MS
        } else {
            replay_window
        };
        let epoch_raw = env_str("EPOCH_SECONDS")?.filter(|s| !s.trim().is_empty());
        let epoch_seconds = env_int("EPOCH_SECONDS", DEFAULT_EPOCH_SECONDS)?.max(1);
        let rln_identifier = env_str("RLN_IDENTIFIER")?
            .filter(|raw| !raw.trim().is_empty())
            .map(|raw| {
                BigUint::parse_bytes(raw.trim().as_bytes(), 10).ok_or_else(|| Error::Setting {
                    name: "SHADE_TREE_RLN_IDENTIFIER",
                    message: "must be a decimal integer".into(),
                })
            })
            .transpose()?
            .unwrap_or_else(|| BigUint::from(1_u8));
        let slots = limit(
            "SHADE_TREE_SLOTS",
            env_str("SLOTS")?.as_deref(),
            DEFAULT_SLOTS,
        )?;
        let tiers = tiers(env_str("TIERS")?.as_deref(), slots)?;
        let payload_raw = env_str("TUNNEL_MAX_PAYLOAD_BYTES")?.filter(|s| !s.trim().is_empty());
        let max_payload_bytes = env_int(
            "TUNNEL_MAX_PAYLOAD_BYTES",
            shadenet_proto::DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES,
        )?;
        let allow_raw = env_str("EGRESS_ALLOW")?;
        let allow = allow_raw
            .clone()
            .unwrap_or_else(|| DEFAULT_EGRESS_ALLOW.to_string());
        let deny = env_str("EGRESS_DENY")?.unwrap_or_default();

        let admit = admission(env_str("ADMIT")?.as_deref(), env_str("ROOTS")?.as_deref())?;
        let members_file = env_str("MEMBERS_FILE")?
            .filter(|raw| !raw.trim().is_empty())
            .map(PathBuf::from);
        if admit.invited && members_file.is_none() {
            return Err(Error::Setting {
                name: "SHADE_TREE_MEMBERS_FILE",
                message: "is required when SHADE_TREE_ADMIT names `invited`: the path of the member set ({\"members\":[leaf,...]})".into(),
            });
        }
        let group_contracts: Vec<String> = env_str("GROUP_CONTRACT")?
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let paid_contract = env_str("PAID_ACCESS_CONTRACT")?
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        if admit.staked && group_contracts.is_empty() {
            return Err(Error::Setting {
                name: "SHADE_TREE_ADMIT",
                message: "names `staked` but SHADE_TREE_GROUP_CONTRACT is not set".into(),
            });
        }
        if admit.paid && paid_contract.is_none() {
            return Err(Error::Setting {
                name: "SHADE_TREE_ADMIT",
                message: "names `paid` but SHADE_TREE_PAID_ACCESS_CONTRACT is not set".into(),
            });
        }
        let helios_url = non_empty_text(env_str("HELIOS_RPC_URL")?);
        let provider = match env_str("ROOT_PROVIDER")?
            .map(|p| p.trim().to_string())
            .as_deref()
        {
            None | Some("") | Some("node") => {
                if helios_url.is_some() {
                    return Err(Error::Setting {
                        name: "SHADE_TREE_HELIOS_RPC_URL",
                        message: "is set but SHADE_TREE_ROOT_PROVIDER=node; the Helios stateRoot anchor needs SHADE_TREE_ROOT_PROVIDER=light (or point SHADE_TREE_RPC_URL at Helios instead)".into(),
                    });
                }
                ProviderConfig::Node
            }
            Some("light") => {
                let mode = match env_str("LIGHT_MODE")?
                    .map(|m| m.trim().to_string())
                    .as_deref()
                {
                    None | Some("") | Some("proof") => light::Mode::Proof,
                    Some("storageat") => light::Mode::StorageAt,
                    Some(other) => {
                        return Err(Error::Setting {
                            name: "SHADE_TREE_LIGHT_MODE",
                            message: format!("{other:?} is not `proof` or `storageat`"),
                        })
                    }
                };
                let chain_id = match non_empty_text(env_str("HELIOS_CHAIN_ID")?) {
                    Some(raw) => Some(raw.parse::<u64>().ok().filter(|id| *id > 0).ok_or_else(
                        || Error::Setting {
                            name: "SHADE_TREE_HELIOS_CHAIN_ID",
                            message: format!("{raw:?} is not a positive chain id"),
                        },
                    )?),
                    None => None,
                };
                ProviderConfig::Light {
                    mode,
                    helios: helios_url.map(|url| (url, chain_id)),
                }
            }
            Some(other) => {
                return Err(Error::Setting {
                    name: "SHADE_TREE_ROOT_PROVIDER",
                    message: format!("unknown provider {other:?} (expected node|light)"),
                })
            }
        };
        let mut contracts: Vec<Contract> = Vec::new();
        if admit.staked {
            for address in &group_contracts {
                if !contracts.iter().any(|c| &c.address == address) {
                    contracts.push(Contract {
                        address: address.clone(),
                        kind: Kind::Staked,
                        from_block: 0,
                    });
                }
            }
        }
        if admit.paid {
            if let Some(address) = &paid_contract {
                if !contracts.iter().any(|c| &c.address == address) {
                    contracts.push(Contract {
                        address: address.clone(),
                        kind: Kind::Paid,
                        from_block: 0,
                    });
                }
            }
        }
        for contract in &contracts {
            if !knobs::is_eth_address(&contract.address) {
                return Err(Error::Setting {
                    name: "SHADE_TREE_GROUP_CONTRACT",
                    message: format!("{} is not an Ethereum address", contract.address),
                });
            }
        }
        let from_blocks = from_blocks(env_str("FROM_BLOCKS")?.as_deref())?;
        let from_block = env_str("FROM_BLOCK")?
            .as_deref()
            .map(parse_block)
            .transpose()
            .map_err(|message| Error::Setting {
                name: "SHADE_TREE_FROM_BLOCK",
                message,
            })?
            .unwrap_or(0);
        for contract in &mut contracts {
            contract.from_block = from_blocks
                .get(&contract.address)
                .copied()
                .unwrap_or(from_block);
        }
        let tor = Socks {
            host: env_str("TOR_HOST")?
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1".into()),
            port: u16::try_from(env_int("TOR_PORT", u64::from(DEFAULT_HEARTBEAT_TOR_PORT))?)
                .unwrap_or(DEFAULT_HEARTBEAT_TOR_PORT),
        };
        let freshness_raw = env_str("ROOT_FRESHNESS_SECONDS")?.filter(|s| !s.trim().is_empty());
        let chain = if contracts.is_empty() {
            None
        } else {
            let rpc_urls: Vec<String> = env_str("RPC_URL")?
                .unwrap_or_else(|| DEFAULT_RPC_URL.into())
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .take(rpc::MAX_URLS)
                .collect();
            let root_freshness = match env_int("ROOT_FRESHNESS_SECONDS", 0)? {
                0 => epoch_seconds,
                seconds => seconds,
            };
            Some(ChainConfig {
                provider,
                contracts,
                rpc_urls: if rpc_urls.is_empty() {
                    vec![DEFAULT_RPC_URL.into()]
                } else {
                    rpc_urls
                },
                rpc_timeout: Duration::from_millis(
                    env_int("RPC_TIMEOUT_MS", rpc::DEFAULT_TIMEOUT_MS)?.max(1),
                ),
                rpc_retries: env_int("RPC_RETRIES", rpc::DEFAULT_RETRIES)?.min(rpc::MAX_RETRIES),
                root_freshness: Duration::from_secs(root_freshness),
                confirmations: env_int("CONFIRMATIONS", 0)?,
                logs_chunk: env_int("LOGS_CHUNK", DEFAULT_LOGS_CHUNK)?,
                paid_min_leaves: count(env_int("PAID_MIN_LEAVES", DEFAULT_PAID_MIN_LEAVES as u64)?)
                    .unwrap_or(DEFAULT_PAID_MIN_LEAVES),
            })
        };
        let artifacts_raw = env_str("ZK_ARTIFACTS")?.filter(|s| !s.trim().is_empty());
        let artifacts = Arc::new(ArtifactSet::load(
            artifacts_raw.as_deref(),
            env_str("ZK_ARTIFACT_LEGACY")?.as_deref(),
        )?);
        let spent_state_file = env_str("SPENT_STATE_FILE")?
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty() && !raw.eq_ignore_ascii_case("off"))
            .map(PathBuf::from);
        let receipts = env_str("RECEIPTS")?.as_deref() == Some("1");
        let session_tickets = env_str("SESSION_TICKETS")?.as_deref() == Some("1");
        let sessions = if session_tickets {
            Some(SessionConfig {
                max_sessions: count(env_int("SESSION_MAX", session::DEFAULT_MAX_SESSIONS)?)
                    .unwrap_or(usize::MAX),
                stream_max: millis(env_int(
                    "SESSION_STREAM_MAX_MS",
                    session::DEFAULT_STREAM_MAX_MS,
                )?),
            })
        } else {
            None
        };
        let bootnodes = bootnodes(
            env_str("BOOTNODE_ONION")?.as_deref(),
            env_str("BOOTNODE_ONIONS")?.as_deref(),
        );
        let identity_file = env_str("GW_IDENTITY")?
            .filter(|raw| !raw.trim().is_empty())
            .map(PathBuf::from);
        if identity_file.is_none() && (receipts || sessions.is_some() || !bootnodes.is_empty()) {
            return Err(Error::Setting {
                name: "SHADE_TREE_GW_IDENTITY",
                message: if receipts {
                    "is required when SHADE_TREE_RECEIPTS=1".into()
                } else if sessions.is_some() {
                    "is required when SHADE_TREE_SESSION_TICKETS=1 (a book binds to this node's onion)".into()
                } else {
                    "is required to announce to an Elder Tree (SHADE_TREE_BOOTNODE_ONION is set): the onion identity that signs the announce".into()
                },
            });
        }
        let non_empty = |value: Option<String>| {
            value
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let metrics_port =
            u16::try_from(env_int("METRICS_PORT", 0)?).map_err(|_| Error::Setting {
                name: "SHADE_TREE_METRICS_PORT",
                message: "metrics port must be an integer in 0..65535".into(),
            })?;
        if metrics_port != 0 && metrics_port == port {
            return Err(Error::Setting {
                name: "SHADE_TREE_METRICS_PORT",
                message: format!("metrics port {metrics_port} collides with node backend"),
            });
        }
        let drain_file = env_str("DRAIN_FILE")?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map_or_else(|| PathBuf::from(DEFAULT_DRAIN_FILE), PathBuf::from);
        let drain_poll =
            drain::poll_interval(env_str("DRAIN_POLL_MS")?.and_then(|s| s.trim().parse().ok()));
        let relay_telemetry = env_str("RELAY_TELEMETRY")?.as_deref() == Some("1");
        let relay_paths = relay_telemetry.then(|| telemetry::Paths {
            counter: env_str("RELAY_TELEMETRY_STATE")
                .ok()
                .flatten()
                .filter(|s| !s.trim().is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_RELAY_COUNTER), PathBuf::from),
            report: env_str("RELAY_REPORT_STATE")
                .ok()
                .flatten()
                .filter(|s| !s.trim().is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_RELAY_REPORT), PathBuf::from),
        });

        // the heartbeat: on when an elder tree is named
        let heartbeat = if bootnodes.is_empty() {
            None
        } else {
            let operator = non_empty(env_str("GW_OPERATOR")?);
            let operator_sig = non_empty(env_str("GW_OPERATOR_SIG")?);
            let key = non_empty(env_str("GW_OPERATOR_KEY")?);
            let auth = match (operator, operator_sig, key) {
                (Some(operator), Some(sig), _) => OperatorAuth::Pair { operator, sig },
                (None, None, Some(key)) => OperatorAuth::Key(key),
                (None, None, None) => OperatorAuth::None,
                _ => {
                    return Err(Error::Setting {
                        name: "SHADE_TREE_GW_OPERATOR",
                        message: "SHADE_TREE_GW_OPERATOR and SHADE_TREE_GW_OPERATOR_SIG must be set together (or set SHADE_TREE_GW_OPERATOR_KEY instead)".into(),
                    })
                }
            };
            let egress_check =
                (env_str("EGRESS_CHECK")?.as_deref() != Some("0")).then(|| EgressCheck {
                    target: non_empty(env_str("EGRESS_CHECK_TARGET").ok().flatten())
                        .unwrap_or_else(|| heartbeat::DEFAULT_EGRESS_CHECK_TARGET.into()),
                    timeout: Duration::from_millis(
                        env_str("EGRESS_CHECK_TIMEOUT_MS")
                            .ok()
                            .flatten()
                            .and_then(|s| s.trim().parse().ok())
                            .filter(|ms| *ms > 0)
                            .unwrap_or(heartbeat::DEFAULT_EGRESS_CHECK_TIMEOUT_MS),
                    ),
                });
            let mut sets: Vec<String> = group_contracts
                .iter()
                .chain(paid_contract.iter())
                .filter(|a| shadenet_proto::is_set_address(a))
                .cloned()
                .collect();
            sets.sort();
            sets.dedup();
            let rate = match (&epoch_raw, &freshness_raw, &payload_raw) {
                (Some(epoch), Some(freshness), Some(payload)) => Some(RateCaps {
                    scope: "grove-v4".into(),
                    window: "fixed".into(),
                    epoch_seconds: epoch.trim().parse().unwrap_or(-1),
                    previous_epochs_accepted: 1,
                    root_freshness_seconds: freshness.trim().parse().unwrap_or(-1),
                    payload_bytes_per_slot: payload.trim().parse().unwrap_or(-1),
                }),
                _ => None,
            };
            Some(heartbeat::Settings {
                bootnodes,
                interval: Duration::from_secs(
                    env_int("BOOTNODE_HEARTBEAT", heartbeat::DEFAULT_INTERVAL_SECS)?.max(1),
                ),
                weight: env_int("GW_WEIGHT", 100)?,
                socks: tor.clone(),
                egress_check,
                auth,
                caps: CapsInputs {
                    egress_allow: allow_raw.clone(),
                    region: non_empty(env_str("GATEWAY_REGION")?),
                    artifacts: artifacts_raw.as_ref().map(|_| artifacts.ids().to_vec()),
                    admits: admit
                        .explicit
                        .then(|| admit.paths().iter().map(|p| (*p).to_string()).collect()),
                    pay: pay_advert(vars)?,
                    rate,
                    session: session_tickets,
                    sets: (!sets.is_empty()).then_some(sets),
                },
                relay_telemetry: relay_paths.clone(),
                drain_poll,
            })
        };

        let alerts = non_empty(env_str("ALERT_WEBHOOK")?).map(|url| alerts::Settings {
            url,
            format: alerts::Format::parse(
                env_str("ALERT_WEBHOOK_FORMAT").ok().flatten().as_deref(),
            ),
            instance: non_empty(env_str("ALERT_INSTANCE").ok().flatten())
                .unwrap_or_else(alerts::hostname),
            interval: Duration::from_millis(
                env_str("ALERT_INTERVAL_MS")
                    .ok()
                    .flatten()
                    .and_then(|s| s.trim().parse().ok())
                    .filter(|ms| *ms >= 1000)
                    .unwrap_or(alerts::DEFAULT_INTERVAL_MS),
            ),
            repeat: Duration::from_millis(
                env_str("ALERT_REPEAT_MS")
                    .ok()
                    .flatten()
                    .and_then(|s| s.trim().parse().ok())
                    .filter(|ms| *ms >= 60_000)
                    .unwrap_or(alerts::DEFAULT_REPEAT_MS),
            ),
            heartbeat_interval: Duration::from_secs(
                env_str("BOOTNODE_HEARTBEAT")
                    .ok()
                    .flatten()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(heartbeat::DEFAULT_INTERVAL_SECS),
            ),
        });

        let tally = fleet_tally(vars, &tor, epoch_seconds)?;

        Ok(Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            envelope_timeout: millis(envelope_timeout),
            idle_timeout: millis(idle_timeout),
            dns_timeout: millis(dns_timeout),
            max_connections: count(max_connections),
            max_connections_per_nullifier: count(per_nullifier),
            shutdown_timeout: Duration::from_millis(shutdown_timeout),
            replay_window: Duration::from_millis(replay_window),
            epoch_seconds,
            rln_identifier,
            slots,
            tiers,
            max_payload_bytes,
            allow_private_targets: env_str("ALLOW_PRIVATE_TARGETS")?.as_deref() == Some("1"),
            members_file: if admit.invited { members_file } else { None },
            chain,
            slash_key: non_empty(env_str("SLASH_KEY")?),
            slash_contract: non_empty(env_str("SLASH_CONTRACT")?),
            slash_receiver: non_empty(env_str("SLASH_RECEIVER")?),
            artifacts,
            spent_state_file,
            identity_file,
            receipts,
            sessions,
            egress: egress::Policy::parse(&allow, &deny),
            metrics_port,
            drain_file,
            heartbeat,
            alerts,
            tally,
            relay_counter: relay_paths.map(|p| p.counter),
            summary: Summary {
                admits: admit.paths(),
                egress_allow: allow,
                log_level: env_str("LOG_LEVEL")?.unwrap_or_else(|| "info".into()),
                log_format: env_str("LOG_FORMAT")?.unwrap_or_else(|| "auto".into()),
                banner: env_str("BANNER")?.unwrap_or_else(|| "auto".into()),
            },
            operator: None,
        })
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn envelope_timeout(&self) -> Option<Duration> {
        self.envelope_timeout
    }

    pub(crate) fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    pub(crate) fn dns_timeout(&self) -> Option<Duration> {
        self.dns_timeout
    }

    pub(crate) fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    pub(crate) fn max_connections_per_nullifier(&self) -> Option<usize> {
        self.max_connections_per_nullifier
    }

    pub(crate) fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    pub(crate) fn replay_window(&self) -> Duration {
        self.replay_window
    }

    pub(crate) fn epoch_seconds(&self) -> u64 {
        self.epoch_seconds
    }

    pub(crate) fn rln_identifier(&self) -> &BigUint {
        &self.rln_identifier
    }

    pub(crate) fn slots(&self) -> u64 {
        self.slots
    }

    pub(crate) fn tiers(&self) -> &[u64] {
        &self.tiers
    }

    pub(crate) fn max_payload_bytes(&self) -> u64 {
        self.max_payload_bytes
    }

    pub(crate) fn allow_private_targets(&self) -> bool {
        self.allow_private_targets
    }

    pub(crate) fn members_file(&self) -> Option<&PathBuf> {
        self.members_file.as_ref()
    }

    pub(crate) fn chain(&self) -> Option<&ChainConfig> {
        self.chain.as_ref()
    }

    pub(crate) fn slash_key(&self) -> Option<&str> {
        self.slash_key.as_deref()
    }

    pub(crate) fn slash_contract(&self) -> Option<&str> {
        self.slash_contract.as_deref()
    }

    pub(crate) fn slash_receiver(&self) -> Option<&str> {
        self.slash_receiver.as_deref()
    }

    pub(crate) fn artifacts(&self) -> Arc<ArtifactSet> {
        Arc::clone(&self.artifacts)
    }

    pub(crate) fn spent_state_file(&self) -> Option<&PathBuf> {
        self.spent_state_file.as_ref()
    }

    pub(crate) fn identity_file(&self) -> Option<&PathBuf> {
        self.identity_file.as_ref()
    }

    pub(crate) fn receipts(&self) -> bool {
        self.receipts
    }

    pub(crate) fn sessions(&self) -> Option<&SessionConfig> {
        self.sessions.as_ref()
    }

    pub(crate) fn egress(&self) -> &egress::Policy {
        &self.egress
    }

    /// The loopback metrics port; 0 means no listener.
    pub(crate) fn metrics_port(&self) -> u16 {
        self.metrics_port
    }

    pub(crate) fn drain_file(&self) -> &Path {
        &self.drain_file
    }

    pub(crate) fn take_heartbeat(&mut self) -> Option<heartbeat::Settings> {
        self.heartbeat.take()
    }

    pub(crate) fn take_alerts(&mut self) -> Option<alerts::Settings> {
        self.alerts.take()
    }

    pub(crate) fn take_tally(&mut self) -> Option<tally::Settings> {
        self.tally.take()
    }

    pub(crate) fn relay_counter(&self) -> Option<&PathBuf> {
        self.relay_counter.as_ref()
    }

    pub(crate) fn summary(&self) -> &Summary {
        &self.summary
    }

    pub(crate) fn operator(&self) -> Option<&Operator> {
        self.operator.as_ref()
    }
}

fn non_empty_text(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Is any admission source named? Without one and without a record there is nothing to run.
fn advanced_layer_configured() -> bool {
    [
        "ADMIT",
        "ROOTS",
        "MEMBERS_FILE",
        "GROUP_CONTRACT",
        "PAID_ACCESS_CONTRACT",
    ]
    .iter()
    .any(|name| shadenet::env::var_lenient(name).is_some_and(|v| !v.trim().is_empty()))
}

/// The operator's own `SHADE_TREE_*` variables (and `SHADENET_*` ones that are not knobs),
/// which override whatever the knobs and the record would have set.
fn explicit_overrides() -> BTreeMap<String, String> {
    let knob_names: Vec<&str> = KNOBS.iter().map(|k| k.env).collect();
    std::env::vars()
        .filter(|(key, value)| {
            !value.trim().is_empty()
                && (key.starts_with("SHADE_TREE_")
                    || (key.starts_with("SHADENET_")
                        && !knob_names.contains(&key.as_str())
                        && key != "SHADENET_TOR_LOG"
                        && key != "SHADENET_REGISTER_OWN_NODE"))
        })
        .collect()
}

/// `SHADE_TREE_BOOTNODE_ONION` first, then every `SHADE_TREE_BOOTNODE_ONIONS` entry, deduped.
fn bootnodes(primary: Option<&str>, listed: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for onion in primary
        .into_iter()
        .chain(listed.unwrap_or("").split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !out.iter().any(|o| o == onion) {
            out.push(onion.to_string());
        }
    }
    out
}

/// The payment advert this node carries in its caps (`payAdvertFromEnv`): off unless
/// `SHADE_TREE_REGISTRAR_ADVERTISE` is set; a malformed advert is dropped whole.
fn pay_advert(vars: &Vars) -> Result<Option<PayCaps>, Error> {
    let Some(raw) = vars
        .get("REGISTRAR_ADVERTISE")?
        .map(|s| s.trim().to_string())
    else {
        return Ok(None);
    };
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }
    let gateway_onion = vars
        .get("GW_IDENTITY")?
        .and_then(|path| crate::receipt::Signer::load(Path::new(&path)).ok())
        .map(|signer| signer.onion());
    let registrar_onion = vars
        .get("REGISTRAR_ONION")?
        .map(|o| {
            format!(
                "{}.onion",
                o.trim().to_ascii_lowercase().trim_end_matches(".onion")
            )
        })
        .filter(|o| Some(o) != gateway_onion.as_ref());
    if raw.starts_with('{') {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return Ok(None);
        };
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        let strings = |key: &str| {
            object.get(key).and_then(|v| v.as_array()).map(|list| {
                list.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect()
            })
        };
        return Ok(Some(PayCaps {
            protocols: strings("protocols"),
            onion: registrar_onion,
            port: object.get("port").and_then(|v| v.as_i64()),
            asset: object
                .get("asset")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            chain: object
                .get("chain")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            tiers: object
                .get("tiers")
                .and_then(|v| v.as_object())
                .map(|tiers| {
                    tiers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                v.as_str()
                                    .map(str::to_string)
                                    .unwrap_or_else(|| v.to_string()),
                            )
                        })
                        .collect()
                }),
        }));
    }
    let asset = vars.get("PAY_ASSET")?.unwrap_or_default();
    if !knobs::is_eth_address(&asset) {
        return Ok(None);
    }
    let mut tiers = Vec::new();
    for part in vars
        .get("PAY_PRICES")?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some((limit, price)) = part.split_once('=') else {
            return Ok(None);
        };
        let limit_ok = !limit.is_empty()
            && limit.len() <= 5
            && !limit.starts_with('0')
            && limit.bytes().all(|b| b.is_ascii_digit());
        let price_ok = !price.is_empty()
            && !price.starts_with('0')
            && price.bytes().all(|b| b.is_ascii_digit());
        if !limit_ok || !price_ok {
            return Ok(None);
        }
        tiers.push((limit.to_string(), price.to_string()));
    }
    if tiers.is_empty() {
        return Ok(None);
    }
    let chain_id: u64 = vars
        .get("PAY_CHAIN_ID")?
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(11_155_111);
    let protocols: Vec<String> = match vars.get("PAY_PROTOCOLS")?.map(|s| s.trim().to_string()) {
        Some(spec) if !spec.is_empty() => {
            let parts: Vec<String> = spec
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty()
                || !parts
                    .iter()
                    .all(|p| shadenet_proto::PAY_PROTOCOLS.contains(&p.as_str()))
            {
                return Ok(None);
            }
            shadenet_proto::PAY_PROTOCOLS
                .iter()
                .filter(|p| parts.iter().any(|x| x == *p))
                .map(|p| (*p).to_string())
                .collect()
        }
        _ => shadenet_proto::PAY_PROTOCOLS
            .iter()
            .map(|p| (*p).to_string())
            .collect(),
    };
    let port = vars
        .get("REGISTRAR_PORT")?
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|p| *p >= 0)
        .unwrap_or(8878);
    Ok(Some(PayCaps {
        protocols: Some(protocols),
        onion: registrar_onion,
        port: Some(port),
        asset: Some(asset),
        chain: Some(format!("eip155:{chain_id}")),
        tiers: Some(tiers),
    }))
}

/// The fleet tally (`makeConfiguredFleetTally`): off without peers; a bad token or peer list
/// turns it off with a warning rather than refusing to start.
fn fleet_tally(
    vars: &Vars,
    tor: &Socks,
    epoch_seconds: u64,
) -> Result<Option<tally::Settings>, Error> {
    let peers: Vec<String> = vars
        .get("FLEET_TALLY_PEERS")?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if peers.is_empty() {
        if let Some(want) = vars
            .get("FLEET_TALLY")?
            .filter(|w| !w.is_empty() && w != "0")
        {
            tracing::warn!(
                requested = want,
                "SHADE_TREE_FLEET_TALLY set but no peers (SHADE_TREE_FLEET_TALLY_PEERS) configured; staying per-gateway (fail-open)"
            );
        }
        return Ok(None);
    }
    if peers.len() > tally::MAX_PEERS {
        tracing::warn!(
            peers = peers.len(),
            max_peers = tally::MAX_PEERS,
            "fleet tally disabled: peer list exceeds hard cap"
        );
        return Ok(None);
    }
    let Some(token) = vars
        .get("FLEET_TALLY_TOKEN")?
        .filter(|t| tally::valid_token(t))
    else {
        tracing::warn!("fleet tally disabled: SHADE_TREE_FLEET_TALLY_TOKEN must be 32..256 printable non-space characters");
        return Ok(None);
    };
    if peers.iter().any(|p| !tally::valid_peer(p)) {
        tracing::warn!(
            reason = "invalid peer",
            "fleet tally disabled: invalid transport configuration"
        );
        return Ok(None);
    }
    let path = vars
        .get("FLEET_TALLY_PATH")?
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| tally::DEFAULT_PATH.into());
    let path_ok = path.starts_with('/')
        && path.len() <= 128
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'-');
    if !path_ok {
        tracing::warn!(
            reason = "invalid path",
            "fleet tally disabled: invalid transport configuration"
        );
        return Ok(None);
    }
    let bounded = |name: &str, default: usize, max: usize| -> Result<usize, Error> {
        Ok(vars
            .get(name)?
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|n| (1..=max).contains(n))
            .unwrap_or(default))
    };
    let listen = tally::parse_listen(vars.get("FLEET_TALLY_LISTEN")?.as_deref());
    let settings = tally::Settings {
        peers,
        token,
        listen,
        path,
        timeout: Duration::from_millis(bounded(
            "FLEET_TALLY_TIMEOUT_MS",
            tally::DEFAULT_TIMEOUT_MS as usize,
            60_000,
        )? as u64),
        max_per_epoch: bounded(
            "FLEET_TALLY_MAX_PER_EPOCH",
            tally::DEFAULT_MAX_PER_EPOCH,
            200_000,
        )?,
        max_epochs: bounded("FLEET_TALLY_MAX_EPOCHS", tally::DEFAULT_MAX_EPOCHS, 16)?,
        max_total: bounded("FLEET_TALLY_MAX_TOTAL", tally::DEFAULT_MAX_TOTAL, 500_000)?,
        ttl: Duration::from_secs(2 * epoch_seconds),
        socks: tor.clone(),
    };
    Ok(Some(settings))
}

/// `SHADE_TREE_ADMIT=invited[,staked][,paid]` (default `invited`). `SHADE_TREE_ROOTS` is the
/// deprecated alias: `static` is `invited`, `onchain` is `staked,paid`; `ADMIT` wins when both set.
fn admission(admit: Option<&str>, roots: Option<&str>) -> Result<Admission, Error> {
    let (spec, explicit) = match (
        admit.map(str::trim).filter(|s| !s.is_empty()),
        roots.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(admit), _) => (admit.to_string(), true),
        (None, Some("static")) => ("invited".into(), true),
        (None, Some("onchain")) => ("staked,paid".into(), true),
        (None, Some(other)) => {
            return Err(Error::Setting {
                name: "SHADE_TREE_ROOTS",
                message: format!("{other:?} is not `static` or `onchain`"),
            })
        }
        (None, None) => ("invited".into(), false),
    };
    let mut out = Admission {
        invited: false,
        staked: false,
        paid: false,
        explicit,
    };
    for source in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match source {
            "invited" => out.invited = true,
            "staked" => out.staked = true,
            "paid" => out.paid = true,
            other => {
                return Err(Error::Setting {
                    name: "SHADE_TREE_ADMIT",
                    message: format!("{other:?} is not one of invited, staked, paid"),
                })
            }
        }
    }
    if !(out.invited || out.staked || out.paid) {
        return Err(Error::Setting {
            name: "SHADE_TREE_ADMIT",
            message: "names no admission source".into(),
        });
    }
    Ok(out)
}

fn parse_block(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .map_err(|_| format!("{raw:?} is not a block number"))
}

/// `SHADE_TREE_FROM_BLOCKS="0xabc=123,0xdef=0x1f"`: a start block per contract.
fn from_blocks(raw: Option<&str>) -> Result<BTreeMap<String, u64>, Error> {
    let mut out = BTreeMap::new();
    for item in raw
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some((address, block)) = item.split_once('=') else {
            return Err(Error::Setting {
                name: "SHADE_TREE_FROM_BLOCKS",
                message: format!("{item:?} is not address=block"),
            });
        };
        let block = parse_block(block).map_err(|message| Error::Setting {
            name: "SHADE_TREE_FROM_BLOCKS",
            message,
        })?;
        out.insert(address.trim().to_ascii_lowercase(), block);
    }
    Ok(out)
}

fn millis(value: u64) -> Option<Duration> {
    (value > 0).then(|| Duration::from_millis(value))
}

fn count(value: u64) -> Option<usize> {
    (value > 0).then(|| usize::try_from(value).unwrap_or(usize::MAX))
}

/// A tier limit: an integer in `1..=65535` (the circuit range-checks with 16 bits).
fn limit(name: &'static str, raw: Option<&str>, default: u64) -> Result<u64, Error> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(default);
    };
    let bad = |message: String| Error::Setting { name, message };
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!(
            "bad tier {:?} (integers only)",
            raw.chars().take(16).collect::<String>()
        )));
    }
    let value: u64 = raw
        .parse()
        .map_err(|_| bad(format!("tier out of range 1..{MAX_LIMIT}")))?;
    if !(1..=MAX_LIMIT).contains(&value) {
        return Err(bad(format!(
            "tier out of range 1..{MAX_LIMIT} (got {value})"
        )));
    }
    Ok(value)
}

/// `SHADE_TREE_TIERS="8,32"`: the distinct limits a slash may name, always including the
/// default tier, ascending.
fn tiers(raw: Option<&str>, slots: u64) -> Result<Vec<u64>, Error> {
    let mut out = vec![slots];
    for part in raw.unwrap_or("").split(',') {
        if part.trim().is_empty() {
            continue;
        }
        out.push(limit("SHADE_TREE_TIERS", Some(part), slots)?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// The identity file path the front door derives, for `check` and `status`.
pub(crate) fn identity_path(knobs: &Knobs) -> PathBuf {
    knobs.hs_dir().join(crate::onion::IDENTITY_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_always_include_the_default_and_are_sorted_and_distinct() {
        assert_eq!(tiers(None, 8).unwrap(), vec![8]);
        assert_eq!(tiers(Some("32, 8,,1"), 8).unwrap(), vec![1, 8, 32]);
        assert!(tiers(Some("x"), 8).is_err());
        assert!(tiers(Some("0"), 8).is_err());
        assert!(tiers(Some("65536"), 8).is_err());
    }

    #[test]
    fn admission_parses_the_policy_and_its_deprecated_alias() {
        let a = admission(None, None).unwrap();
        assert!(a.invited && !a.staked && !a.paid && !a.explicit);
        let a = admission(Some("staked, paid"), Some("static")).unwrap();
        assert!(!a.invited && a.staked && a.paid && a.explicit);
        assert_eq!(a.paths(), ["staked", "paid"]);
        let a = admission(None, Some("onchain")).unwrap();
        assert!(!a.invited && a.staked && a.paid);
        assert!(admission(Some("trusted"), None).is_err());
        assert!(admission(Some(","), None).is_err());
        assert!(admission(None, Some("magic")).is_err());
    }

    #[test]
    fn block_numbers_take_both_forms() {
        assert_eq!(parse_block("0x1f").unwrap(), 31);
        assert_eq!(parse_block(" 31 ").unwrap(), 31);
        assert!(parse_block("x").is_err());
        let map = from_blocks(Some("0xAbC=0x10, 0xdef=2")).unwrap();
        assert_eq!(map["0xabc"], 16);
        assert_eq!(map["0xdef"], 2);
        assert!(from_blocks(Some("nope")).is_err());
    }

    #[test]
    fn a_derived_map_resolves_like_the_environment() {
        let members = concat!(env!("CARGO_MANIFEST_DIR"), "/../../group/members.json");
        let mut derived = BTreeMap::new();
        derived.insert("SHADE_TREE_MEMBERS_FILE".to_string(), members.to_string());
        derived.insert("SHADE_TREE_ADMIT".to_string(), "invited".to_string());
        derived.insert("SHADE_TREE_GATEWAY_PORT".to_string(), "0".to_string());
        derived.insert("SHADE_TREE_METRICS_PORT".to_string(), "9101".to_string());
        derived.insert(
            "SHADE_TREE_EGRESS_ALLOW".to_string(),
            "*:443,*:8443".to_string(),
        );
        derived.insert("SHADE_TREE_EPOCH_SECONDS".to_string(), "60".to_string());
        derived.insert(
            "SHADE_TREE_ROOT_FRESHNESS_SECONDS".to_string(),
            "60".to_string(),
        );
        derived.insert(
            "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES".to_string(),
            "1000".to_string(),
        );
        derived.insert(
            "SHADE_TREE_BOOTNODE_ONIONS".to_string(),
            "a.onion,b.onion,a.onion".to_string(),
        );
        derived.insert(
            "SHADE_TREE_GW_IDENTITY".to_string(),
            "/nowhere/identity.local.json".to_string(),
        );
        derived.insert(
            "SHADE_TREE_FLEET_TALLY_PEERS".to_string(),
            "127.0.0.1:1".to_string(),
        );
        derived.insert("SHADE_TREE_FLEET_TALLY_TOKEN".to_string(), "t".repeat(40));
        let mut config = Config::resolve(&Vars::Derived(derived)).unwrap();
        assert_eq!(config.metrics_port(), 9101);
        assert_eq!(config.summary().admits, ["invited"]);
        let heartbeat = config.take_heartbeat().unwrap();
        assert_eq!(heartbeat.bootnodes, ["a.onion", "b.onion"]);
        assert_eq!(heartbeat.caps.egress_allow.as_deref(), Some("*:443,*:8443"));
        assert_eq!(heartbeat.caps.admits, Some(vec!["invited".to_string()]));
        assert_eq!(
            heartbeat.caps.rate.as_ref().map(|r| r.epoch_seconds),
            Some(60)
        );
        assert!(
            heartbeat.caps.artifacts.is_none(),
            "advertised only when SHADE_TREE_ZK_ARTIFACTS is explicit"
        );
        assert!(matches!(heartbeat.auth, OperatorAuth::None));
        assert_eq!(config.take_tally().unwrap().peers, ["127.0.0.1:1"]);
        assert!(config.take_alerts().is_none());

        let mut half = BTreeMap::new();
        half.insert("SHADE_TREE_MEMBERS_FILE".to_string(), members.to_string());
        half.insert(
            "SHADE_TREE_BOOTNODE_ONION".to_string(),
            "a.onion".to_string(),
        );
        half.insert("SHADE_TREE_GW_IDENTITY".to_string(), "/nowhere".to_string());
        half.insert("SHADE_TREE_GW_OPERATOR".to_string(), "0x1".to_string());
        let error = match Config::resolve(&Vars::Derived(half)) {
            Ok(_) => String::from("resolved"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains("must be set together"), "{error}");
    }

    #[test]
    fn the_root_provider_is_node_or_light_and_helios_needs_light() {
        let members = concat!(env!("CARGO_MANIFEST_DIR"), "/../../group/members.json");
        let base = |provider: &str, extra: &[(&str, &str)]| {
            let mut vars = BTreeMap::new();
            vars.insert("SHADE_TREE_MEMBERS_FILE".to_string(), members.to_string());
            vars.insert("SHADE_TREE_ADMIT".to_string(), "invited,staked".to_string());
            vars.insert(
                "SHADE_TREE_GROUP_CONTRACT".to_string(),
                format!("0x{}", "ab".repeat(20)),
            );
            vars.insert("SHADE_TREE_ROOT_PROVIDER".to_string(), provider.to_string());
            for (k, v) in extra {
                vars.insert((*k).to_string(), (*v).to_string());
            }
            Config::resolve(&Vars::Derived(vars))
        };
        assert!(matches!(
            base("node", &[])
                .ok()
                .and_then(|c| c.chain.map(|c| c.provider)),
            Some(ProviderConfig::Node)
        ));
        let light = base(
            "light",
            &[
                ("SHADE_TREE_HELIOS_RPC_URL", "http://127.0.0.1:8546"),
                ("SHADE_TREE_HELIOS_CHAIN_ID", "11155111"),
            ],
        )
        .ok()
        .and_then(|c| c.chain.map(|c| c.provider));
        assert!(
            matches!(light, Some(ProviderConfig::Light { mode: light::Mode::Proof, helios: Some((url, Some(11_155_111))) }) if url == "http://127.0.0.1:8546")
        );
        let storage = base("light", &[("SHADE_TREE_LIGHT_MODE", "storageat")])
            .ok()
            .and_then(|c| c.chain.map(|c| c.provider));
        assert!(matches!(
            storage,
            Some(ProviderConfig::Light {
                mode: light::Mode::StorageAt,
                helios: None
            })
        ));
        let text = |r: Result<Config, Error>| r.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            text(base("node", &[("SHADE_TREE_HELIOS_RPC_URL", "http://x")]))
                .contains("needs SHADE_TREE_ROOT_PROVIDER=light")
        );
        assert!(text(base("magic", &[])).contains("expected node|light"));
        assert!(
            text(base("light", &[("SHADE_TREE_LIGHT_MODE", "trust-me")]))
                .contains("not `proof` or `storageat`")
        );
        assert!(
            text(base("light", &[("SHADE_TREE_HELIOS_CHAIN_ID", "zero")]))
                .contains("not a positive chain id")
        );
    }

    #[test]
    fn pay_adverts_need_every_field() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "SHADE_TREE_REGISTRAR_ADVERTISE".to_string(),
            "1".to_string(),
        );
        vars.insert(
            "SHADE_TREE_PAY_ASSET".to_string(),
            format!("0x{}", "ab".repeat(20)),
        );
        assert!(
            pay_advert(&Vars::Derived(vars.clone())).unwrap().is_none(),
            "no prices"
        );
        vars.insert(
            "SHADE_TREE_PAY_PRICES".to_string(),
            "8=100000,32=400000".to_string(),
        );
        let pay = pay_advert(&Vars::Derived(vars.clone())).unwrap().unwrap();
        assert_eq!(pay.port, Some(8878));
        assert_eq!(pay.chain.as_deref(), Some("eip155:11155111"));
        assert_eq!(
            pay.protocols,
            Some(vec!["x402".to_string(), "mpp".to_string()])
        );
        assert_eq!(pay.tiers.as_ref().map(Vec::len), Some(2));
        vars.insert("SHADE_TREE_PAY_PROTOCOLS".to_string(), "mpp".to_string());
        assert_eq!(
            pay_advert(&Vars::Derived(vars.clone()))
                .unwrap()
                .unwrap()
                .protocols,
            Some(vec!["mpp".to_string()])
        );
        vars.insert("SHADE_TREE_PAY_PROTOCOLS".to_string(), "cash".to_string());
        assert!(pay_advert(&Vars::Derived(vars)).unwrap().is_none());
    }
}
