//! The Elder's settings: every `SHADE_TREE_*` variable `packages/node/bootnode/server.mjs`
//! reads, with the same defaults, read under either prefix (`SHADENET_*` first). Every problem
//! is collected and reported at once.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::advert;
use crate::error::Error;

const DEFAULT_PORT: u16 = 8877;
const DEFAULT_TTL_SECS: u64 = 900;
const DEFAULT_MAX_ENTRIES: usize = 10_000;
const DEFAULT_MIN_REANNOUNCE_SECS: u64 = 5;
const DEFAULT_DELTA_HISTORY: usize = 64;
const DEFAULT_HEARTBEAT_SECS: u64 = 300;
const DEFAULT_HEADERS_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_KEEPALIVE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_HEADER_BYTES: usize = 8_192;
const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const DEFAULT_STAKE_CACHE_MS: u64 = 15_000;
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 120;
const DEFAULT_PROBE_FAILS: u32 = 3;
const DEFAULT_PROBE_TIMEOUT_MS: u64 = 20_000;
const DEFAULT_FED_INTERVAL_SECS: u64 = 60;
const DEFAULT_TOR_HOST: &str = "127.0.0.1";
const DEFAULT_TOR_PORT: u16 = 9250;
const DEFAULT_RELAY_MIN_COHORT: u64 = 5;
const DEFAULT_RELAY_DELAY_HOURS: u64 = 6;
const SIGNER_FILE: &str = "bootnode-signer.key";
const INCIDENTS_FILE: &str = "incidents.local.json";
const RELAY_STATE_FILE: &str = "relay-telemetry-state.local.json";

/// Who may be listed: anyone proving onion control, or only a staked operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Open,
    Stake,
}

impl Admission {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Stake => "stake",
        }
    }
}

/// Where "is this operator staked" is answered.
#[derive(Debug, Clone)]
pub(crate) enum StakeSource {
    /// `GatewayRegistry.isStaked(address)` over JSON-RPC.
    Onchain {
        registry: String,
        rpc_url: String,
        confirmations: u64,
        cache: Duration,
    },
    /// Chainless development: an allowlist, or everyone when it is empty.
    Mock { allowlist: Option<Vec<String>> },
}

/// HTTP slow-client limits (`HTTP_LIMITS`); `None` disables a timeout.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    pub(crate) headers_timeout: Option<Duration>,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) keepalive_timeout: Option<Duration>,
    pub(crate) max_header_bytes: usize,
}

/// Where the local Tor SOCKS port is, for the prober and federation.
#[derive(Debug, Clone)]
pub(crate) struct Tor {
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// The whole configuration of one Elder, resolved once at startup.
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) port: u16,
    pub(crate) admission: Admission,
    pub(crate) ttl_secs: u64,
    pub(crate) signer_key: PathBuf,
    pub(crate) store: Option<PathBuf>,
    pub(crate) max_entries: usize,
    pub(crate) min_reannounce_secs: u64,
    pub(crate) delta_history: usize,
    pub(crate) announce_rate: f64,
    pub(crate) announce_burst: f64,
    pub(crate) limits: Limits,
    pub(crate) metrics_port: u16,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) stake: StakeSource,
    pub(crate) pay: Option<Value>,
    pub(crate) tor: Tor,
    pub(crate) probe: Option<Probe>,
    pub(crate) federation: Option<Federation>,
    pub(crate) incidents_file: PathBuf,
    pub(crate) incidents_token: Option<String>,
    pub(crate) relay: Relay,
}

/// Active health probing, on only with `SHADE_TREE_BOOTNODE_PROBE=1`.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub(crate) interval: Duration,
    pub(crate) fail_threshold: u32,
    pub(crate) timeout: Duration,
}

/// Peer Elders to pull from, on only with `SHADE_TREE_BOOTNODE_PEERS`.
#[derive(Debug, Clone)]
pub(crate) struct Federation {
    pub(crate) peers: Vec<String>,
    pub(crate) interval: Duration,
    pub(crate) max_pull: usize,
}

/// The relay telemetry aggregator's settings.
#[derive(Debug, Clone)]
pub(crate) struct Relay {
    pub(crate) state: PathBuf,
    pub(crate) minimum_cohort: u64,
    pub(crate) delay_hours: u64,
}

/// The value, or the fallback with the problem recorded.
fn take<T>(errors: &mut Vec<String>, result: Result<T, String>, fallback: T) -> T {
    match result {
        Ok(value) => value,
        Err(e) => {
            errors.push(e);
            fallback
        }
    }
}

/// `SHADENET_<name>`, else `SHADE_TREE_<name>`; both set to different values is an error.
fn var(name: &str) -> Result<Option<String>, String> {
    let current = std::env::var(format!("SHADENET_{name}")).ok();
    let legacy = std::env::var(format!("SHADE_TREE_{name}")).ok();
    match (current, legacy) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "SHADENET_{name} and SHADE_TREE_{name} are both set to different values; unset one"
        )),
        (Some(a), _) => Ok(Some(a)),
        (None, b) => Ok(b),
    }
}

/// A variable that is set to something other than whitespace.
fn text(name: &str) -> Result<Option<String>, String> {
    Ok(var(name)?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty()))
}

fn number<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match text(name)? {
        None => Ok(default),
        Some(raw) => raw
            .parse()
            .map_err(|_| format!("SHADE_TREE_{name}: expected a number (got \"{raw}\")")),
    }
}

/// A millisecond knob where an explicit `0` disables the timeout.
fn timeout_ms(name: &str, default: u64) -> Result<Option<Duration>, String> {
    let ms: u64 = number(name, default)?;
    Ok((ms > 0).then(|| Duration::from_millis(ms)))
}

/// The state directory: `SHADENET_STATE`, else `/state` in a container, else a directory
/// beside the process.
fn state_dir() -> Result<PathBuf, String> {
    if let Some(state) = text("STATE")? {
        return Ok(PathBuf::from(state));
    }
    Ok(
        if cfg!(target_os = "linux") && Path::new("/state").is_dir() {
            PathBuf::from("/state")
        } else {
            PathBuf::from("./shadenet-elder")
        },
    )
}

fn is_eth_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A bare `<addr>.onion`: scheme and path stripped, lowercased, the suffix added.
pub(crate) fn normalize_onion(raw: &str) -> Option<String> {
    let mut text = raw.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = text.strip_prefix(scheme) {
            text = rest.to_string();
        }
    }
    let host = text.split('/').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    Some(if host.ends_with(".onion") {
        host.to_string()
    } else {
        format!("{host}.onion")
    })
}

/// `SHADE_TREE_BOOTNODE_PEERS` without blanks, duplicates or this Elder's own onion.
pub(crate) fn parse_peers(raw: &str, own: Option<&str>) -> Vec<String> {
    let own = own.and_then(normalize_onion);
    let mut peers = Vec::new();
    for part in raw.split(',') {
        let Some(onion) = normalize_onion(part) else {
            continue;
        };
        if own.as_deref() == Some(onion.as_str()) || peers.contains(&onion) {
            continue;
        }
        peers.push(onion);
    }
    peers
}

impl Config {
    /// Read every knob from the environment.
    pub fn from_env() -> Result<Self, Error> {
        let mut errors = Vec::new();
        let state = take(&mut errors, state_dir(), PathBuf::from("."));
        let port = take(
            &mut errors,
            number("BOOTNODE_PORT", DEFAULT_PORT),
            DEFAULT_PORT,
        );
        let admission = match take(&mut errors, text("BOOTNODE_ADMISSION"), None).as_deref() {
            None | Some("open") => Admission::Open,
            Some("stake") => Admission::Stake,
            Some(other) => {
                errors.push(format!(
                    "SHADE_TREE_BOOTNODE_ADMISSION: expected open or stake (got \"{other}\")"
                ));
                Admission::Open
            }
        };
        let ttl_secs = take(
            &mut errors,
            number("BOOTNODE_TTL", DEFAULT_TTL_SECS),
            DEFAULT_TTL_SECS,
        );
        let signer_key = take(&mut errors, text("BOOTNODE_SIGNER_KEY"), None)
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join(SIGNER_FILE));
        let store = take(&mut errors, text("BOOTNODE_STORE"), None).map(PathBuf::from);
        let max_entries = take(
            &mut errors,
            number("BOOTNODE_MAX_ENTRIES", DEFAULT_MAX_ENTRIES),
            DEFAULT_MAX_ENTRIES,
        );
        let min_reannounce_secs = take(
            &mut errors,
            number("BOOTNODE_MIN_REANNOUNCE", DEFAULT_MIN_REANNOUNCE_SECS),
            DEFAULT_MIN_REANNOUNCE_SECS,
        );
        let delta_history = take(
            &mut errors,
            number("BOOTNODE_DELTA_HISTORY", DEFAULT_DELTA_HISTORY),
            DEFAULT_DELTA_HISTORY,
        );
        let heartbeat_secs = take(
            &mut errors,
            number("BOOTNODE_HEARTBEAT", DEFAULT_HEARTBEAT_SECS),
            DEFAULT_HEARTBEAT_SECS,
        )
        .max(1);
        let (default_rate, default_burst) =
            crate::bucket::defaults(max_entries as f64, heartbeat_secs as f64);
        let announce_rate = take(
            &mut errors,
            number("BOOTNODE_ANNOUNCE_RATE", default_rate),
            default_rate,
        );
        let announce_burst = take(
            &mut errors,
            number("BOOTNODE_ANNOUNCE_BURST", default_burst),
            default_burst,
        );
        if announce_rate < 0.0 || announce_burst < 0.0 {
            errors.push("SHADE_TREE_BOOTNODE_ANNOUNCE_RATE and _BURST must not be negative".into());
        }
        let mut limits = Limits {
            headers_timeout: take(
                &mut errors,
                timeout_ms("BOOTNODE_HEADERS_TIMEOUT_MS", DEFAULT_HEADERS_TIMEOUT_MS),
                None,
            ),
            request_timeout: take(
                &mut errors,
                timeout_ms("BOOTNODE_REQUEST_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS),
                None,
            ),
            keepalive_timeout: take(
                &mut errors,
                timeout_ms(
                    "BOOTNODE_KEEPALIVE_TIMEOUT_MS",
                    DEFAULT_KEEPALIVE_TIMEOUT_MS,
                ),
                None,
            ),
            max_header_bytes: take(
                &mut errors,
                number("BOOTNODE_MAX_HEADER_BYTES", DEFAULT_MAX_HEADER_BYTES),
                DEFAULT_MAX_HEADER_BYTES,
            ),
        };
        // the whole request must be allowed at least as long as its headers
        if let (Some(headers), Some(request)) = (limits.headers_timeout, limits.request_timeout) {
            if headers > request {
                limits.headers_timeout = Some(request);
            }
        }
        let metrics_port = take(&mut errors, number("METRICS_PORT", 0_u16), 0);
        if metrics_port != 0 && metrics_port == port {
            errors.push(format!(
                "SHADE_TREE_METRICS_PORT {metrics_port} collides with the Elder Tree backend port"
            ));
        }
        let shutdown_timeout = Duration::from_millis(take(
            &mut errors,
            number("SHUTDOWN_TIMEOUT_MS", DEFAULT_SHUTDOWN_TIMEOUT_MS),
            DEFAULT_SHUTDOWN_TIMEOUT_MS,
        ));

        let registry = take(&mut errors, text("GATEWAY_REGISTRY"), None);
        let stake_mode = take(&mut errors, text("STAKE_MODE"), None);
        let resolved_mode = stake_mode.clone().unwrap_or_else(|| {
            if registry.is_some() {
                "onchain".into()
            } else {
                "mock".into()
            }
        });
        let stake = match resolved_mode.as_str() {
            "onchain" => match registry.filter(|r| is_eth_address(r)) {
                Some(registry) => StakeSource::Onchain {
                    registry: registry.to_ascii_lowercase(),
                    rpc_url: take(&mut errors, text("RPC_URL"), None)
                        .unwrap_or_else(|| DEFAULT_RPC_URL.into()),
                    confirmations: take(&mut errors, number("CONFIRMATIONS", 0_u64), 0),
                    cache: Duration::from_millis(take(
                        &mut errors,
                        number("STAKE_CACHE_MS", DEFAULT_STAKE_CACHE_MS),
                        DEFAULT_STAKE_CACHE_MS,
                    )),
                },
                None => {
                    errors.push("SHADE_TREE_STAKE_MODE=onchain needs SHADE_TREE_GATEWAY_REGISTRY (the GatewayRegistry address)".into());
                    StakeSource::Mock { allowlist: None }
                }
            },
            "mock" => StakeSource::Mock {
                allowlist: take(&mut errors, text("STAKE_ALLOWLIST"), None).map(|list| {
                    list.split(',')
                        .map(|a| a.trim().to_ascii_lowercase())
                        .filter(|a| !a.is_empty())
                        .collect()
                }),
            },
            other => {
                errors.push(format!(
                    "unknown SHADE_TREE_STAKE_MODE: {other} (expected onchain|mock)"
                ));
                StakeSource::Mock { allowlist: None }
            }
        };

        let pay = take(&mut errors, advert::from_env(), None);

        let tor = Tor {
            host: take(&mut errors, text("TOR_HOST"), None)
                .unwrap_or_else(|| DEFAULT_TOR_HOST.into()),
            port: take(
                &mut errors,
                number("TOR_PORT", DEFAULT_TOR_PORT),
                DEFAULT_TOR_PORT,
            ),
        };
        let probe =
            (take(&mut errors, text("BOOTNODE_PROBE"), None).as_deref() == Some("1")).then(|| {
                Probe {
                    interval: Duration::from_secs(take(
                        &mut errors,
                        number("BOOTNODE_PROBE_INTERVAL", DEFAULT_PROBE_INTERVAL_SECS),
                        DEFAULT_PROBE_INTERVAL_SECS,
                    )),
                    fail_threshold: take(
                        &mut errors,
                        number("BOOTNODE_PROBE_FAILS", DEFAULT_PROBE_FAILS),
                        DEFAULT_PROBE_FAILS,
                    )
                    .max(1),
                    timeout: Duration::from_millis(take(
                        &mut errors,
                        number("BOOTNODE_PROBE_TIMEOUT_MS", DEFAULT_PROBE_TIMEOUT_MS),
                        DEFAULT_PROBE_TIMEOUT_MS,
                    )),
                }
            });
        let own_onion = take(&mut errors, text("BOOTNODE_ONION"), None);
        let peers = take(&mut errors, text("BOOTNODE_PEERS"), None)
            .map(|raw| parse_peers(&raw, own_onion.as_deref()))
            .unwrap_or_default();
        let federation = (!peers.is_empty()).then(|| Federation {
            peers,
            interval: Duration::from_secs(take(
                &mut errors,
                number("BOOTNODE_FED_INTERVAL", DEFAULT_FED_INTERVAL_SECS),
                DEFAULT_FED_INTERVAL_SECS,
            )),
            max_pull: take(
                &mut errors,
                number("BOOTNODE_FED_MAX_PULL", max_entries),
                max_entries,
            ),
        });

        let incidents_file = take(&mut errors, text("BOOTNODE_INCIDENTS_FILE"), None)
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join(INCIDENTS_FILE));
        let incidents_token = take(&mut errors, text("BOOTNODE_INCIDENTS_TOKEN"), None);

        let relay = Relay {
            state: take(&mut errors, text("RELAY_ELDER_STATE"), None)
                .map(PathBuf::from)
                .unwrap_or_else(|| state.join(RELAY_STATE_FILE)),
            minimum_cohort: take(
                &mut errors,
                number("RELAY_MIN_COHORT", DEFAULT_RELAY_MIN_COHORT),
                DEFAULT_RELAY_MIN_COHORT,
            ),
            delay_hours: take(
                &mut errors,
                number("RELAY_DELAY_HOURS", DEFAULT_RELAY_DELAY_HOURS),
                DEFAULT_RELAY_DELAY_HOURS,
            ),
        };
        if relay.minimum_cohort < DEFAULT_RELAY_MIN_COHORT {
            errors.push("relay minimum cohort cannot be below five".into());
        }
        if relay.delay_hours < DEFAULT_RELAY_DELAY_HOURS {
            errors.push("relay publication delay cannot be below six hours".into());
        }

        if !errors.is_empty() {
            return Err(Error::Config(errors));
        }
        Ok(Self {
            port,
            admission,
            ttl_secs,
            signer_key,
            store,
            max_entries,
            min_reannounce_secs,
            delta_history,
            announce_rate,
            announce_burst,
            limits,
            metrics_port,
            shutdown_timeout,
            stake,
            pay,
            tor,
            probe,
            federation,
            incidents_file,
            incidents_token,
            relay,
        })
    }

    /// The front door's `(format, level)` hint for logging, read without the full config.
    pub fn log_hint() -> Option<(String, String)> {
        match (
            text("LOG_FORMAT").ok().flatten(),
            text("LOG_LEVEL").ok().flatten(),
        ) {
            (None, None) => None,
            (format, level) => Some((
                format.unwrap_or_else(|| "auto".into()),
                level.unwrap_or_else(|| "info".into()),
            )),
        }
    }

    /// What `check` prints: one row per setting that matters to an operator.
    pub(crate) fn display_rows(&self) -> Vec<(&'static str, String)> {
        let timeout = |t: Option<Duration>| {
            t.map_or_else(|| "off".to_string(), |d| format!("{} ms", d.as_millis()))
        };
        let mut rows = vec![
            ("listen", format!("127.0.0.1:{}", self.port)),
            ("admission", self.admission.label().to_string()),
            ("ttl", format!("{} s", self.ttl_secs)),
            ("signer key", self.signer_key.display().to_string()),
            (
                "store",
                self.store.as_ref().map_or_else(
                    || "off (in-memory)".to_string(),
                    |p| p.display().to_string(),
                ),
            ),
            ("max entries", self.max_entries.to_string()),
            (
                "announce bucket",
                format!("{:.2}/s, burst {}", self.announce_rate, self.announce_burst),
            ),
            (
                "http limits",
                format!(
                    "headers {}, request {}, keep-alive {}, headers <= {} bytes",
                    timeout(self.limits.headers_timeout),
                    timeout(self.limits.request_timeout),
                    timeout(self.limits.keepalive_timeout),
                    self.limits.max_header_bytes
                ),
            ),
            (
                "stake",
                match &self.stake {
                    StakeSource::Onchain {
                        registry, rpc_url, ..
                    } => format!(
                        "onchain {registry} via {}",
                        shadenet_service::rpc::origin(rpc_url)
                    ),
                    StakeSource::Mock { allowlist: None } => "mock:open".into(),
                    StakeSource::Mock {
                        allowlist: Some(list),
                    } => format!("mock:allowlist({})", list.len()),
                },
            ),
            (
                "metrics",
                if self.metrics_port > 0 {
                    format!("127.0.0.1:{}", self.metrics_port)
                } else {
                    "off".into()
                },
            ),
            (
                "probing",
                self.probe.as_ref().map_or_else(
                    || "off".to_string(),
                    |p| {
                        format!(
                            "every {} s, demote after {} fails",
                            p.interval.as_secs(),
                            p.fail_threshold
                        )
                    },
                ),
            ),
            (
                "federation",
                self.federation.as_ref().map_or_else(
                    || "off".to_string(),
                    |f| {
                        format!(
                            "{} peer(s), every {} s",
                            f.peers.len(),
                            f.interval.as_secs()
                        )
                    },
                ),
            ),
            ("incidents", self.incidents_file.display().to_string()),
            (
                "incidents webhook",
                if self.incidents_token.is_some() {
                    "POST /incidents/alertmanager (bearer)".into()
                } else {
                    "off".into()
                },
            ),
        ];
        if let Some(pay) = &self.pay {
            rows.push(("registrar advert", pay.to_string()));
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_are_normalized_deduped_and_never_self() {
        let own = format!("{}.onion", "o".repeat(56));
        let a = format!("{}.onion", "a".repeat(56));
        let b = format!("{}.onion", "b".repeat(56));
        let raw = format!(
            " {} ,http://{b}/directory,,{a},{},{}",
            a[..56].to_ascii_uppercase(),
            &own[..56],
            own
        );
        assert_eq!(
            parse_peers(&raw, Some(&format!("https://{own}/"))),
            vec![a, b]
        );
        assert!(parse_peers("", None).is_empty());
        assert_eq!(normalize_onion("  "), None);
    }
}
