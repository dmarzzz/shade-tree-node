//! The node process: one listener, one task per connection, a bounded drain on shutdown.
//! Per connection, the order is the JavaScript node's: connection cap, envelope framing,
//! version gate, target policy, proof verification, spent set, per-nullifier cap, payload
//! allowance, DNS, dial, acknowledgement, relay. Around the listener live the operator
//! subsystems the JavaScript supervisor, gateway and heartbeat shared between three
//! processes: Tor, the heartbeat, metrics, alerts, the fleet tally, telemetry and
//! `status.json`.

use std::collections::HashMap;
use std::io::IsTerminal as _;
use std::os::unix::io::FromRawFd as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shadenet_proto::{accept_envelope_version, PROTO_MAX, PROTO_MIN};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::alerts::Alerts;
use crate::canary;
use crate::chain::{ChainSource, Provider};
use crate::config::{self, Config, ProviderConfig};
use crate::drain;
use crate::egress;
use crate::envelope::{self, read_envelope, refusal, refuse, write_line};
use crate::error::Error;
use crate::heartbeat::Heartbeat;
use crate::light::{self, Light};
use crate::members::MemberSet;
use crate::metrics::{self, Readiness, Registry};
use crate::operator;
use crate::receipt;
use crate::record;
use crate::roots::Roots;
use crate::rpc::Rpc;
use crate::session;
use crate::slash::{self, SlashConfig, Slasher};
use crate::spent::{Admission, Share, SpentSet};
use crate::status::{self, Status};
use crate::tally::Tally;
use crate::telemetry::{self, Traffic};
use crate::tor;
use crate::tunnel::{self, Budget, Close};
use crate::verify::{Binding, Refusal, Verified, Verifier};

const REASON_TOO_MANY_CONNECTIONS: &str = "too-many-connections";
const REASON_SESSION_UNSUPPORTED: &str = "session-unsupported";
const REASON_NULLIFIER_CONN_LIMIT: &str = "nullifier-conn-limit";
const REASON_OVER_SPEND_SLASHED: &str = "over-spend-slashed";
const REASON_REPLAYED_ENVELOPE: &str = "replayed-envelope";
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const ROOT_ADVERT_MAX: usize = 16;
const TOR_STOP_SETTLE: Duration = Duration::from_secs(1);

pub struct ShadeNode {
    config: Config,
}

struct Shared {
    config: Config,
    connections: Option<Semaphore>,
    per_nullifier: Mutex<HashMap<String, usize>>,
    verifier: Verifier,
    roots: Roots,
    slasher: Slasher,
    spent: Arc<SpentSet>,
    budget: Arc<Budget>,
    cap: Option<Arc<tunnel::Cap>>,
    receipts: Option<Arc<receipt::Signer>>,
    sessions: Option<Sessions>,
    registry: Arc<Registry>,
    traffic: Arc<Traffic>,
    tally: Option<Arc<Tally>>,
    active_tunnels: AtomicUsize,
    open_connections: AtomicUsize,
}

struct Sessions {
    onion: String,
    books: Arc<session::Books>,
}

impl ShadeNode {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Serve until SIGTERM or SIGINT, then drain open connections for the configured grace.
    pub async fn run(self) -> Result<(), Error> {
        let mut config = self.config;
        let registry = Arc::new(Registry::new(
            "node",
            config::build_version(),
            &config::build_commit(),
        ));
        let drain_flag = Arc::new(drain::Flag::new(config.drain_file().to_path_buf()));
        let readiness = Arc::new(Readiness::new(drain::Flag::new(
            config.drain_file().to_path_buf(),
        )));

        // the front door: identity, own-node registration, status.json, then tor
        let mut tor_child: Option<tor::Tor> = None;
        let mut status_file: Option<Arc<Status>> = None;
        let mut prepared = None;
        if let Some(op) = config.operator() {
            let ready = operator::prepare(op)?;
            let record = &op.record;
            let elders: Vec<String> = record.elders.iter().map(|e| e.onion.clone()).collect();
            let status = Arc::new(Status::new(status::Start {
                state_dir: op.state_dir.clone(),
                onion: ready.signer.onion(),
                network: record.network.clone(),
                set: record.contract.clone(),
                elders: elders.clone(),
                commit: config::build_commit(),
                record_pin: record.node_commit.clone(),
                metrics_port: config.metrics_port(),
            }));
            tracing::info!(
                "node {} joining {} (set {}) with {} Elder Tree(s); admit {}; tickets {}",
                ready.signer.onion(),
                record.network,
                record.contract,
                elders.len(),
                config.summary().admits.join(","),
                if config.sessions().is_some() {
                    "on"
                } else {
                    "off"
                }
            );
            let commit = config::build_commit();
            if let Some(pin) = record.node_commit.as_deref().filter(|p| !p.is_empty()) {
                if commit != "unknown" && !pin.starts_with(&commit) {
                    tracing::warn!(
                        "warning: build {} differs from the record's pin {}",
                        commit.chars().take(7).collect::<String>(),
                        pin.chars().take(7).collect::<String>()
                    );
                }
            }
            let settings = tor::TorrcSettings {
                state_dir: &op.state_dir,
                hs_dir: &op.hs_dir,
                gateway_port: config.listen().port(),
                socks_port: crate::knobs::TOR_SOCKS_PORT,
                pow: op.pow && ready.tor_info.pow,
                fleet_tally_port: None,
                log_level: &op.tor_log_level,
            };
            let tor = tor::start(&settings, tor::DEFAULT_BOOTSTRAP_TIMEOUT)
                .await
                .map_err(Error::Operator)?;
            status.set_pid("tor", tor.pid());
            tracing::info!("tor bootstrapped; onion descriptor publishes in about 30 s");
            tor_child = Some(tor);
            status_file = Some(status);
            prepared = Some(ready);
        }

        let members = match config.members_file() {
            Some(path) => Some(Arc::new(MemberSet::load(
                path.clone(),
                config.rln_identifier().clone(),
            )?)),
            None => None,
        };
        if members.is_some() {
            registry.gauge(
                "shade_tree_gateway_trusted_roots",
                &[("source", "invited")],
                1.0,
            );
        }
        let rln_id = config
            .rln_identifier()
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(1);
        let mut rpc = None;
        let chain = match config.chain() {
            Some(chain_config) => {
                let client = Arc::new(
                    Rpc::new(
                        chain_config.rpc_urls.clone(),
                        chain_config.rpc_timeout,
                        chain_config.rpc_retries,
                        Some(Arc::clone(&registry)),
                    )
                    .map_err(|message| Error::Setting {
                        name: "SHADE_TREE_RPC_URL",
                        message,
                    })?,
                );
                rpc = Some(Arc::clone(&client));
                let provider = match &chain_config.provider {
                    ProviderConfig::Node => Provider::Node,
                    ProviderConfig::Light { mode, helios } => {
                        let anchor = match helios {
                            Some((url, chain_id)) => Some(Arc::new(
                                light::Anchor::new(url.clone(), *chain_id).map_err(|message| {
                                    Error::Setting {
                                        name: "SHADE_TREE_HELIOS_RPC_URL",
                                        message,
                                    }
                                })?,
                            )),
                            None => None,
                        };
                        Provider::Light(Light::new(*mode, anchor))
                    }
                };
                match &provider {
                    Provider::Node => tracing::info!(
                        provider = "node",
                        contracts = chain_config.contracts.len(),
                        state_root_source =
                            "trusted node (RPC trusted by design; solo-staker path)",
                        "root source: on-chain RootProvider"
                    ),
                    Provider::Light(light) => tracing::info!(
                        provider = "light",
                        mode = light.mode().label(),
                        contracts = chain_config.contracts.len(),
                        state_root_source = light.state_root_source(),
                        state_root_verified = light.state_root_verified(),
                        "root source: on-chain RootProvider"
                    ),
                }
                let source = Arc::new(ChainSource::new(
                    client,
                    chain_config.contracts.clone(),
                    chain_config.root_freshness,
                    chain_config.confirmations,
                    chain_config.logs_chunk,
                    rln_id,
                    provider,
                    chain_config.paid_min_leaves,
                    Some(Arc::clone(&registry)),
                ));
                let healthy = source.refresh().await;
                if healthy == 0 && members.is_none() {
                    return Err(Error::NoAdmissionRoot(
                        "every on-chain root source failed its first read and no member file is admitted"
                            .into(),
                    ));
                }
                if healthy < chain_config.contracts.len() {
                    tracing::warn!(
                        "{} of {} on-chain root sources failed their first read; serving with the rest and retrying",
                        chain_config.contracts.len() - healthy,
                        chain_config.contracts.len()
                    );
                }
                Some(source)
            }
            None => None,
        };
        let roots = Roots::new(members.clone(), chain.clone());
        let slasher = Slasher::setup(
            SlashConfig {
                key: config.slash_key().map(str::to_string),
                primary: config.slash_contract().map(str::to_string),
                receiver: config.slash_receiver().map(str::to_string),
                admitted: chain
                    .as_ref()
                    .map(|c| {
                        c.contracts()
                            .into_iter()
                            .map(|c| (c.address, c.kind))
                            .collect()
                    })
                    .unwrap_or_default(),
                tiers: config.tiers().to_vec(),
                default_limit: config.slots(),
            },
            rpc,
        )
        .await
        .map_err(Error::Slash)?;
        let identity: Option<Arc<receipt::Signer>> = match (&prepared, config.identity_file()) {
            (Some(ready), _) => Some(Arc::clone(&ready.signer)),
            (None, Some(path)) => match receipt::Signer::load(path) {
                Ok(identity) => Some(Arc::new(identity)),
                Err(e) => {
                    tracing::warn!("onion identity unavailable; receipts, session tickets and the heartbeat are DISABLED: {e}");
                    None
                }
            },
            (None, None) => None,
        };
        let sessions = match (config.sessions(), &identity) {
            (Some(settings), Some(identity)) => {
                tracing::info!(
                    onion = identity.onion(),
                    classes = session::CLASSES.map(|c| c.class).join(","),
                    "session tickets enabled"
                );
                Some(Sessions {
                    onion: identity.onion(),
                    books: Arc::new(session::Books::new(
                        settings.max_sessions,
                        settings.stream_max,
                    )),
                })
            }
            _ => None,
        };
        let receipts = match (config.receipts(), &identity) {
            (true, Some(identity)) => {
                tracing::info!("egress receipts enabled (signer: onion control key)");
                Some(Arc::clone(identity))
            }
            _ => None,
        };
        let spent = Arc::new(SpentSet::new(
            config.epoch_seconds(),
            config.replay_window(),
            config.spent_state_file().cloned(),
        ));
        let budget = Arc::new(Budget::new(
            config.max_payload_bytes(),
            config.epoch_seconds(),
        ));
        let verifier = Verifier::new(
            config.artifacts(),
            config.epoch_seconds(),
            config.rln_identifier().clone(),
        );
        tracing::info!(
            "accepted artifacts: {}",
            verifier.artifacts().ids().join(",")
        );
        let telemetry_counter = config
            .relay_counter()
            .map(|path| Arc::new(telemetry::Counter::new(path.clone())));
        let traffic = Arc::new(Traffic::new(
            Arc::clone(&registry),
            telemetry_counter.clone(),
        ));
        let tally = match config.take_tally() {
            Some(settings) => {
                let listener =
                    TcpListener::bind(settings.listen)
                        .await
                        .map_err(|source| Error::Bind {
                            addr: settings.listen,
                            source,
                        })?;
                let bound = listener.local_addr().map_err(|source| Error::LocalAddr {
                    addr: settings.listen,
                    source,
                })?;
                tracing::info!(
                    peers = settings.peers.len(),
                    listen = %bound,
                    path = settings.path,
                    max_per_epoch = settings.max_per_epoch,
                    max_epoch_buckets = settings.max_epochs,
                    max_total = settings.max_total,
                    "fleet tally transport: authenticated HTTP push (nullifier+epoch only; 1-hop; fail-open)"
                );
                let tally = Arc::new(Tally::new(settings));
                Some((tally, listener))
            }
            None => None,
        };
        let heartbeat = match (config.take_heartbeat(), &identity) {
            (Some(settings), Some(identity)) => Some(Arc::new(
                Heartbeat::new(
                    settings,
                    Arc::clone(identity),
                    Arc::clone(&registry),
                    Arc::clone(&drain_flag),
                )
                .map_err(|message| Error::Setting {
                    name: "SHADE_TREE_BOOTNODE_ONION",
                    message,
                })?,
            )),
            _ => None,
        };
        let alerts = match config.take_alerts() {
            Some(settings) => Some(Arc::new(
                Alerts::new(
                    settings,
                    Arc::clone(&registry),
                    Arc::clone(&drain_flag),
                    heartbeat.is_some(),
                )
                .map_err(|message| Error::Setting {
                    name: "SHADE_TREE_ALERT_WEBHOOK",
                    message,
                })?,
            )),
            None => None,
        };

        let canary = match config.take_canary() {
            Some(settings) => Some(
                canary::Canary::new(
                    settings,
                    config.drain_file(),
                    Arc::clone(&registry),
                    alerts.clone(),
                )
                .map_err(|message| Error::Setting {
                    name: "SHADE_TREE_CANARY",
                    message,
                })?,
            ),
            None => None,
        };

        let addr = config.listen();
        let inherited = inherited_listener();
        let activated = inherited.is_some();
        let listener = match inherited {
            Some(socket) => socket
                .set_nonblocking(true)
                .and_then(|()| TcpListener::from_std(socket))
                .map_err(Error::Inherited)?,
            None => TcpListener::bind(addr)
                .await
                .map_err(|source| Error::Bind { addr, source })?,
        };
        let bound = listener
            .local_addr()
            .map_err(|source| Error::LocalAddr { addr, source })?;
        let metrics_listener = match config.metrics_port() {
            0 => None,
            port => Some(metrics::bind(port).await.map_err(|source| Error::Bind {
                addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                source,
            })?),
        };
        let mut shutdown = Shutdown::install()?;
        let (retire_tx, retire_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            connections: config.max_connections().map(Semaphore::new),
            per_nullifier: Mutex::new(HashMap::new()),
            verifier,
            roots,
            slasher,
            spent: Arc::clone(&spent),
            budget,
            cap: config
                .bandwidth_bytes_per_second()
                .map(|rate| Arc::new(tunnel::Cap::new(rate))),
            receipts,
            sessions,
            registry: Arc::clone(&registry),
            traffic,
            tally: tally.as_ref().map(|(t, _)| Arc::clone(t)),
            active_tunnels: AtomicUsize::new(0),
            open_connections: AtomicUsize::new(0),
            config,
        });
        let mut background = JoinSet::new();
        if let Some(members) = members {
            background.spawn(members.watch());
        }
        if let Some(chain) = chain {
            background.spawn(chain.poll());
        }
        if let Some(sessions) = &shared.sessions {
            background.spawn(Arc::clone(&sessions.books).sweep());
        }
        background.spawn(async move { spent.flush_periodically().await });
        if let Some(counter) = telemetry_counter {
            background.spawn(counter.flush_periodically());
        }
        if let Some((tally, listener)) = tally {
            background.spawn(tally.serve(listener));
        }
        if let Some(listener) = metrics_listener {
            readiness.set_listening(true);
            tracing::info!(
                listen = format!("127.0.0.1:{}", shared.config.metrics_port()),
                "operator metrics ready"
            );
            background.spawn(metrics::serve(
                listener,
                Arc::clone(&registry),
                Arc::clone(&readiness),
            ));
        }
        if let Some(heartbeat) = &heartbeat {
            background.spawn(Arc::clone(heartbeat).run(retire_rx));
        }
        if let Some(alerts) = &alerts {
            tracing::info!(
                format = alerts.format().label(),
                interval_ms = alerts.interval().as_millis() as u64,
                "alert webhook configured"
            );
            alerts
                .lifecycle("GatewayStarted", &format!("gateway up on {bound}"))
                .await;
            if let Some(heartbeat) = &heartbeat {
                let count = heartbeat.bootnodes();
                alerts
                    .lifecycle(
                        "HeartbeatStarted",
                        &format!(
                            "heartbeat up ({count} Elder Tree{})",
                            if count == 1 { "" } else { "s" }
                        ),
                    )
                    .await;
            }
            background.spawn(Arc::clone(alerts).run());
        }
        if let Some(canary) = canary {
            tracing::info!("{}", canary.describe());
            background.spawn(canary.run());
        }
        if let Some(hosts) = shared.config.egress().blocklist_hosts() {
            shared
                .registry
                .gauge("shade_tree_gateway_blocklist_hosts", &[], hosts as f64);
            tracing::info!(
                hosts,
                "egress blocklist loaded (SHADE_TREE_EGRESS_DENY_FILE); re-read when the file changes"
            );
            let shared = Arc::clone(&shared);
            background.spawn(async move {
                loop {
                    tokio::time::sleep(egress::BLOCKLIST_POLL).await;
                    if let Some(hosts) = shared.config.egress().reload_blocklist() {
                        shared.registry.gauge(
                            "shade_tree_gateway_blocklist_hosts",
                            &[],
                            hosts as f64,
                        );
                    }
                }
            });
        }
        if let Some(rate) = shared.config.bandwidth_bytes_per_second() {
            tracing::info!(
                bytes_per_second = rate,
                "bandwidth cap: ON across every tunnel, both directions (SHADE_TREE_BANDWIDTH_BYTES_PER_SECOND)"
            );
        }
        if let Some(status) = &status_file {
            let pid = Some(std::process::id());
            status.set_pid("gateway", pid);
            if heartbeat.is_some() {
                status.set_pid("heartbeat", pid);
            }
            if let Some(op) = shared.config.operator() {
                background.spawn(watch_record(
                    op.record_source.clone(),
                    op.record.value.clone(),
                    Arc::clone(status),
                ));
            }
            tracing::info!("node and heartbeat started; `heartbeat accepted` in the log means an Elder lists this node, `heartbeat rejected` says why one does not");
        }
        banner(&shared, &bound, activated, &drain_flag, alerts.is_some());
        if activated {
            tracing::info!("serving the listening socket systemd handed over (socket activation); restarts keep queueing connects");
        }
        // the exact "gateway up on <addr>" line: the interop harness and the tests wait for it
        tracing::info!("gateway up on {bound}");
        tracing::debug!(
            epoch = shared.verifier.current_epoch(),
            epoch_seconds = shared.config.epoch_seconds(),
            metrics_port = shared.config.metrics_port(),
            socket_activation = activated,
            "service ready"
        );
        if drain_flag.is_set() {
            tracing::warn!(
                path = %drain_flag.path().display(),
                "drain flag is set at start; readyz reports 503 until it is removed"
            );
        }
        if shared.config.allow_private_targets() {
            tracing::warn!("private and special-purpose egress targets are ENABLED; use only for isolated local development");
        }
        if shared.tally.is_some() {
            tracing::info!("fleet tally: ON; best-effort per-epoch replay suppression after peer propagation (nullifier+epoch only; fail-open)");
        }

        let mut connections = JoinSet::new();
        let outcome = {
            // the borrow of the tor child ends with this block, before it is stopped below
            let mut tor_exit = std::pin::pin!(async {
                match tor_child.as_mut() {
                    Some(tor) => tor.exited().await,
                    None => std::future::pending().await,
                }
            });
            loop {
                tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            connections.spawn(serve(Arc::clone(&shared), stream));
                        }
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                        }
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    signal = shutdown.recv() => match signal {
                        Signal::Terminate(name) => break Ok(name),
                        Signal::Retire => {
                            if heartbeat.is_some() && retire_tx.send(true).is_ok() {
                                if let Some(status) = &status_file {
                                    status.set_pid("heartbeat", None);
                                }
                            }
                        }
                    },
                    code = &mut tor_exit => {
                        let code = code.map_or("a signal".to_string(), |c| c.to_string());
                        tracing::error!("tor exited ({code}); stopping everything so the supervisor restarts cleanly");
                        break Err(Error::Operator(format!("tor exited ({code})")));
                    }
                }
            }
        };
        drop(listener);
        readiness.set_listening(false);
        background.abort_all();
        let signal = match &outcome {
            Ok(name) => *name,
            Err(_) => "tor-exit",
        };
        tracing::info!(
            "{signal} received; draining {} connections",
            connections.len()
        );
        if let Some(alerts) = &alerts {
            alerts
                .lifecycle(
                    "GatewayStopping",
                    "gateway draining for restart/stop (SIGTERM)",
                )
                .await;
        }
        let grace = shared.config.shutdown_timeout();
        let drained = tokio::time::timeout(grace, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        shared.spent.flush();
        if let Some(mut tor) = tor_child {
            if outcome.is_ok() {
                tor.stop().await;
                tokio::time::sleep(TOR_STOP_SETTLE).await;
            }
        }
        if let Some(status) = status_file {
            status.set_pid("tor", None);
            status.set_pid("gateway", None);
            status.set_pid("heartbeat", None);
            status.stopped();
        }
        outcome?;
        if drained.is_err() {
            let open = connections.len();
            connections.abort_all();
            return Err(Error::DrainTimeout { open, grace });
        }
        Ok(())
    }
}

/// The record is read once at start. When its source moves on this node keeps serving the old
/// one and clients route around it, so look again every 15 minutes and say so until restarted.
async fn watch_record(source: String, started: serde_json::Value, status: Arc<Status>) {
    let mut last = String::new();
    loop {
        tokio::time::sleep(record::RECHECK_INTERVAL).await;
        let src = source.clone();
        let fetched = tokio::task::spawn_blocking(move || {
            record::read_source(&src).and_then(|text| record::parse(&text))
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        let current = match fetched {
            Ok(record) => record.value,
            Err(e) if e.contains("not joinable") => {
                let mut retired = started.clone();
                retired["status"] = serde_json::Value::String("not joinable (retired?)".into());
                retired
            }
            Err(_) => continue,
        };
        let changes = record::drift(&started, &current);
        status.set_drift(&changes);
        let key = changes.join("; ");
        if !changes.is_empty() && key != last {
            tracing::warn!(
                "warning: the record at {source} changed since this node started ({key}); this node still serves the old one. Restart it to follow the record (docker restart shadenet-node), or pin a record you control"
            );
        }
        last = key;
    }
}

/// The startup tree the JavaScript node printed on a terminal (`printOperatorBanner`).
/// The listening socket systemd hands over (`LISTEN_FDS=1` addressed to this pid, fd 3): the
/// node serves it instead of binding, so the socket outlives a restart and Tor's local connects
/// queue in the kernel backlog instead of being refused (docs/OPERATOR.md "Restart without
/// dropping a connection"). A socket addressed to another pid is never taken.
fn inherited_listener() -> Option<std::net::TcpListener> {
    let fds: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if fds < 1 || pid != std::process::id() {
        return None;
    }
    // SAFETY: systemd opened fd 3 as a listening socket for this process alone (LISTEN_PID is
    // ours), and nothing else in the node refers to that descriptor.
    Some(unsafe { std::net::TcpListener::from_raw_fd(3) })
}

fn banner(
    shared: &Shared,
    bound: &std::net::SocketAddr,
    activated: bool,
    drain_flag: &drain::Flag,
    alerts: bool,
) {
    let summary = shared.config.summary();
    let mode = summary.banner.to_ascii_lowercase();
    let format = summary.log_format.to_ascii_lowercase();
    let terminal = std::io::stdout().is_terminal()
        && std::env::var("TERM").is_ok_and(|t| t != "dumb")
        && std::env::var("CI").is_err();
    let show = match mode.as_str() {
        "never" | "off" | "0" | "false" => false,
        _ if format == "json" || (format == "auto" && !terminal) => false,
        "always" | "on" | "1" | "true" => true,
        _ => terminal,
    };
    if !show {
        return;
    }
    let rows: Vec<(&str, String)> = vec![
        (
            "listen",
            format!(
                "{bound}{}",
                if activated {
                    " (socket activation)"
                } else {
                    ""
                }
            ),
        ),
        ("drain flag", drain_flag.path().display().to_string()),
        (
            "alerts",
            if alerts {
                "webhook".into()
            } else {
                "off".into()
            },
        ),
        ("admission", summary.admits.join(",")),
        ("egress", summary.egress_allow.clone()),
        (
            "session tickets",
            match &shared.sessions {
                Some(_) => format!("on ({})", session::CLASSES.map(|c| c.class).join(", ")),
                None => "off".into(),
            },
        ),
        (
            "payload limit",
            match shared.config.max_payload_bytes() {
                0 => "off".into(),
                bytes => format!("{bytes} bytes combined / RLN slot"),
            },
        ),
        (
            "metrics",
            match shared.config.metrics_port() {
                0 => "off".into(),
                port => format!("127.0.0.1:{port}"),
            },
        ),
        (
            "logs",
            format!("{} / {}", summary.log_level, summary.log_format),
        ),
    ];
    let mut text = String::from(
        "              \\ | /\n            --  *  --\n        .---------------.\n     .-'                 '-.\n    /_______________________\\\n              |||\n              |||\n          SHADE TREE\n       NODE | cover ready\n\n",
    );
    for (label, value) in rows {
        text.push_str(&format!("  {label:<11}{value}\n"));
    }
    print!("{text}");
}

/// One nullifier's share of the per-nullifier connection cap, released on drop.
struct NullifierSlot {
    shared: Arc<Shared>,
    nullifier: String,
}

impl NullifierSlot {
    fn acquire(shared: &Arc<Shared>, nullifier: &str) -> Option<Self> {
        if let Some(cap) = shared.config.max_connections_per_nullifier() {
            let mut open = shared
                .per_nullifier
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let count = open.entry(nullifier.to_string()).or_insert(0);
            if *count >= cap {
                return None;
            }
            *count += 1;
        }
        Some(Self {
            shared: Arc::clone(shared),
            nullifier: nullifier.to_string(),
        })
    }
}

impl Drop for NullifierSlot {
    fn drop(&mut self) {
        if self.shared.config.max_connections_per_nullifier().is_none() {
            return;
        }
        let mut open = self
            .shared
            .per_nullifier
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.nullifier) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.nullifier);
            }
        }
    }
}

/// Counts one accepted socket for the `connections` gauge while it is open.
struct Connection(Arc<Shared>);

impl Connection {
    fn open(shared: &Arc<Shared>) -> Self {
        let open = shared.open_connections.fetch_add(1, Ordering::Relaxed) + 1;
        shared
            .registry
            .gauge("shade_tree_gateway_connections", &[], open as f64);
        Self(Arc::clone(shared))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let open = self
            .0
            .open_connections
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        self.0
            .registry
            .gauge("shade_tree_gateway_connections", &[], open as f64);
    }
}

/// Counts one established tunnel for the `active_tunnels` gauge while it relays.
struct ActiveTunnel(Arc<Shared>);

impl ActiveTunnel {
    fn open(shared: &Arc<Shared>) -> Self {
        let open = shared.active_tunnels.fetch_add(1, Ordering::Relaxed) + 1;
        shared
            .registry
            .gauge("shade_tree_gateway_active_tunnels", &[], open as f64);
        Self(Arc::clone(shared))
    }
}

impl Drop for ActiveTunnel {
    fn drop(&mut self) {
        let open = self
            .0
            .active_tunnels
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        self.0
            .registry
            .gauge("shade_tree_gateway_active_tunnels", &[], open as f64);
    }
}

/// Which counter a connection's outcome lands in.
#[derive(Clone, Copy)]
enum Path {
    Tunnel,
    Session,
    Ticket,
}

impl Path {
    fn metric(self) -> &'static str {
        match self {
            Self::Tunnel => "shade_tree_gateway_tunnels_total",
            Self::Session => "shade_tree_gateway_sessions_total",
            Self::Ticket => "shade_tree_gateway_tickets_total",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::Tunnel => "tunnel",
            Self::Session => "session",
            Self::Ticket => "ticket",
        }
    }
}

/// Log and count a refusal, then send it.
async fn drop_with(shared: &Shared, stream: &mut TcpStream, path: Path, reason: &str, line: &str) {
    let label = metrics::drop_label(reason);
    tracing::debug!(reason = label, "{} rejected", path.what());
    shared
        .registry
        .counter(path.metric(), &[("result", "drop"), ("reason", label)]);
    refuse(stream, line).await;
}

fn count_close(shared: &Shared, close: Close) {
    let reason = match close {
        Close::IdleTimeout => "idle-timeout",
        Close::PayloadLimit => "payload-limit",
        Close::UpstreamError => "upstream-error",
        Close::Peer | Close::ClientError | Close::Session => return,
    };
    shared.registry.counter(
        "shade_tree_gateway_tunnel_closes_total",
        &[("reason", reason)],
    );
}

async fn serve(shared: Arc<Shared>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _connection = Connection::open(&shared);
    let _permit = match &shared.connections {
        Some(limit) => match limit.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                drop_with(
                    &shared,
                    &mut stream,
                    Path::Tunnel,
                    REASON_TOO_MANY_CONNECTIONS,
                    &refusal(REASON_TOO_MANY_CONNECTIONS, &[]),
                )
                .await;
                return;
            }
        },
        None => None,
    };
    let (envelope, early) = match read_envelope(&mut stream, shared.config.envelope_timeout()).await
    {
        Ok(read) => read,
        Err(e) => {
            drop_with(
                &shared,
                &mut stream,
                Path::Tunnel,
                e.label(),
                &refusal(&format!("bad-envelope:{e}"), &[]),
            )
            .await;
            return;
        }
    };
    if let Err(e) = accept_envelope_version(&envelope::version(&envelope), (PROTO_MIN, PROTO_MAX)) {
        let reason = e.to_string();
        let proto = format!("{{\"min\":{PROTO_MIN},\"max\":{PROTO_MAX}}}");
        drop_with(
            &shared,
            &mut stream,
            Path::Tunnel,
            &reason,
            &refusal(&reason, &[("proto", proto)]),
        )
        .await;
        return;
    }
    if envelope.get("session").is_some() || envelope.get("ticket").is_some() {
        let Some(sessions) = &shared.sessions else {
            drop_with(
                &shared,
                &mut stream,
                Path::Session,
                REASON_SESSION_UNSUPPORTED,
                &refusal(REASON_SESSION_UNSUPPORTED, &[]),
            )
            .await;
            return;
        };
        if envelope.get("session").is_some() {
            session_init(&shared, sessions, stream, &envelope).await;
        } else {
            ticket_spend(&shared, sessions, stream, &envelope, early).await;
        }
        return;
    }
    let target = match shared.config.egress().check_target(envelope.get("target")) {
        Ok(target) => target,
        Err(reason) => {
            drop_with(
                &shared,
                &mut stream,
                Path::Tunnel,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };

    let started = Instant::now();
    let verified = shared
        .verifier
        .verify(&envelope, &shared.roots.accepted(), Binding::Target)
        .await;
    shared.registry.observe(
        "shade_tree_gateway_verify_seconds",
        started.elapsed().as_secs_f64(),
    );
    let verified = match verified {
        Ok(verified) => verified,
        Err(refusal) => {
            refuse_verification(&shared, &mut stream, Path::Tunnel, refusal).await;
            return;
        }
    };

    let nonce = envelope.get("nonce").and_then(|v| v.as_str());
    if let Err(reason) = admit(&shared, &verified, nonce) {
        drop_with(
            &shared,
            &mut stream,
            Path::Tunnel,
            reason,
            &refusal(reason, &[]),
        )
        .await;
        return;
    }

    let Some(_nullifier_slot) = NullifierSlot::acquire(&shared, &verified.nullifier) else {
        drop_with(
            &shared,
            &mut stream,
            Path::Tunnel,
            REASON_NULLIFIER_CONN_LIMIT,
            &refusal(REASON_NULLIFIER_CONN_LIMIT, &[]),
        )
        .await;
        return;
    };

    let key = Budget::key(&verified.external_nullifier, &verified.nullifier);
    let Some(hold) = shared.budget.acquire(key) else {
        drop_with(
            &shared,
            &mut stream,
            Path::Tunnel,
            shadenet_proto::REASON_PAYLOAD_LIMIT,
            &refusal(shadenet_proto::REASON_PAYLOAD_LIMIT, &[]),
        )
        .await;
        return;
    };

    let candidates = match egress::resolve(
        &target,
        shared.config.allow_private_targets(),
        shared.config.dns_timeout(),
    )
    .await
    {
        Ok(candidates) => candidates,
        Err(reason) => {
            drop_with(
                &shared,
                &mut stream,
                Path::Tunnel,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    let dial_started = Instant::now();
    let dialed = egress::dial(&candidates, shared.config.idle_timeout()).await;
    shared.registry.observe(
        "shade_tree_gateway_upstream_connect_seconds",
        dial_started.elapsed().as_secs_f64(),
    );
    let upstream = match dialed {
        Ok(upstream) => upstream,
        Err(reason) => {
            drop_with(
                &shared,
                &mut stream,
                Path::Tunnel,
                metrics::upstream_drop_label(&reason),
                &refusal(&reason, &[]),
            )
            .await;
            return;
        }
    };
    tracing::debug!(port = target.port, "tunnel established");
    // cross-node replay evidence names a real egress, so it is published only now
    if let Some(tally) = &shared.tally {
        tally.record(&verified.nullifier, &verified.external_nullifier);
    }
    shared
        .registry
        .counter("shade_tree_gateway_tunnels_total", &[("result", "pass")]);
    let _active = ActiveTunnel::open(&shared);
    let ack = match &shared.receipts {
        Some(signer) => signer.ack(shared.verifier.current_epoch()),
        None => "{\"ok\":true}".to_string(),
    };
    if !write_line(&mut stream, &ack).await {
        return;
    }
    let close = tunnel::relay(
        stream,
        upstream,
        early,
        hold,
        shared.config.idle_timeout(),
        None,
        shared.cap.clone(),
        None,
        Arc::clone(&shared.traffic),
    )
    .await;
    count_close(&shared, close);
    tracing::debug!(reason = close.label(), "tunnel closed");
}

/// Every verification refusal's wire form, shared by the tunnel and session paths.
async fn refuse_verification(
    shared: &Shared,
    stream: &mut TcpStream,
    path: Path,
    refusal_: Refusal,
) {
    match refusal_ {
        Refusal::Reason(reason) => {
            drop_with(
                shared,
                stream,
                path,
                &reason,
                &refusal(&format!("gate:{reason}"), &[]),
            )
            .await;
        }
        Refusal::WrongRoot => {
            let extras = shared.roots.advert(ROOT_ADVERT_MAX);
            drop_with(
                shared,
                stream,
                path,
                "wrong-group-root",
                &refusal("gate:wrong-group-root", &extras),
            )
            .await;
        }
        Refusal::Artifact { reason, ids } => {
            let ids = serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into());
            drop_with(
                shared,
                stream,
                path,
                &reason,
                &refusal(&format!("gate:{reason}"), &[("artifacts", ids)]),
            )
            .await;
        }
    }
}

/// The spent set's verdict on a verified proof; an over-spend is slashed here. A nullifier
/// this node has not seen is first checked against the fleet tally (fail-open).
fn admit(shared: &Shared, verified: &Verified, nonce: Option<&str>) -> Result<(), &'static str> {
    if let Some(tally) = &shared.tally {
        if !shared.spent.is_known(&verified.nullifier)
            && tally.has(&verified.nullifier, &verified.external_nullifier)
        {
            tracing::debug!(scope = "fleet", "replayed envelope rejected");
            return Err(REASON_REPLAYED_ENVELOPE);
        }
    }
    let share = Share {
        x: verified.share_x.clone(),
        y: verified.share_y.clone(),
    };
    match shared.spent.admit(&verified.nullifier, share, nonce) {
        Admission::First | Admission::Replay => Ok(()),
        Admission::Refused(reason) => Err(reason),
        Admission::OverSpend { first, second } => {
            shared
                .registry
                .counter("shade_tree_gateway_slashes_total", &[]);
            match slash::reconstruct_secret(&first, &second) {
                Ok(secret) => {
                    let tier = slash::resolve_tier(
                        secret,
                        shared.config.tiers(),
                        shared.config.slots(),
                        |leaf| shared.roots.has_leaf(leaf),
                    );
                    shared.slasher.submit(secret, tier);
                }
                Err(e) => tracing::error!(reason = "slash-submit-failed", "slash failed: {e}"),
            }
            Err(REASON_OVER_SPEND_SLASHED)
        }
    }
}

/// A session initialization: the same cheap-first order as a tunnel, then a book is opened and
/// the ack echoes the policy. The socket is closed after the ack; a book, not a connection, is
/// the session handle.
async fn session_init(
    shared: &Arc<Shared>,
    sessions: &Sessions,
    mut stream: TcpStream,
    envelope: &serde_json::Value,
) {
    let init = match session::validate_init(&envelope["session"]) {
        Ok(init) => init,
        Err(reason) => {
            drop_with(
                shared,
                &mut stream,
                Path::Session,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    if init.gateway != sessions.onion {
        drop_with(
            shared,
            &mut stream,
            Path::Session,
            "session-wrong-gateway",
            &refusal("session-wrong-gateway", &[]),
        )
        .await;
        return;
    }
    let signal = match shadenet_proto::session::session_signal(
        &init.gateway,
        &init.class,
        &init.nonce,
        &init.digest,
    ) {
        Ok(signal) => signal,
        Err(_) => {
            drop_with(
                shared,
                &mut stream,
                Path::Session,
                "session-malformed",
                &refusal("session-malformed", &[]),
            )
            .await;
            return;
        }
    };
    let started = Instant::now();
    let verified = shared
        .verifier
        .verify(envelope, &shared.roots.accepted(), Binding::Signal(signal))
        .await;
    shared.registry.observe(
        "shade_tree_gateway_verify_seconds",
        started.elapsed().as_secs_f64(),
    );
    let verified = match verified {
        Ok(verified) => verified,
        Err(refusal) => {
            refuse_verification(shared, &mut stream, Path::Session, refusal).await;
            return;
        }
    };
    if let Err(reason) = admit(shared, &verified, Some(&init.nonce)) {
        drop_with(
            shared,
            &mut stream,
            Path::Session,
            reason,
            &refusal(reason, &[]),
        )
        .await;
        return;
    }
    let opened = match sessions
        .books
        .open(&init, &verified.nullifier, &verified.external_nullifier)
    {
        Ok(opened) => opened,
        Err(reason) => {
            drop_with(
                shared,
                &mut stream,
                Path::Session,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    // publishing the slot makes the book single-use across the fleet
    if let (Some(tally), session::Opened::New) = (&shared.tally, &opened) {
        tally.record(&verified.nullifier, &verified.external_nullifier);
    }
    shared
        .registry
        .counter("shade_tree_gateway_sessions_total", &[("result", "pass")]);
    tracing::debug!(
        class = init.class,
        replay = matches!(opened, session::Opened::Replay),
        "session opened"
    );
    let ack = format!(
        "{{\"ok\":true,\"session\":{{\"ticketBookDigest\":\"{}\",\"policy\":{}}}}}",
        init.digest,
        session::policy_echo(init.policy, sessions.books.stream_max())
    );
    refuse(&mut stream, &ack).await;
}

/// A ticket spend: grammar, target policy, the synchronous reservation, then the shared DNS,
/// dial and relay path under the book's budget key, shapers and idle clock.
async fn ticket_spend(
    shared: &Arc<Shared>,
    sessions: &Sessions,
    mut stream: TcpStream,
    envelope: &serde_json::Value,
    early: Vec<u8>,
) {
    let ticket = match session::validate_ticket(&envelope["ticket"]) {
        Ok(ticket) => ticket,
        Err(reason) => {
            drop_with(
                shared,
                &mut stream,
                Path::Ticket,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    let target = match shared.config.egress().check_target(envelope.get("target")) {
        Ok(target) => target,
        Err(reason) => {
            drop_with(
                shared,
                &mut stream,
                Path::Ticket,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    let target_text = format!("{}:{}", target.host, target.port);
    let reservation = match sessions.books.reserve(&ticket, &target_text) {
        Ok(reservation) => reservation,
        Err(reason) => {
            drop_with(
                shared,
                &mut stream,
                Path::Ticket,
                reason,
                &refusal(reason, &[]),
            )
            .await;
            return;
        }
    };
    shared
        .registry
        .counter("shade_tree_gateway_tickets_total", &[("result", "pass")]);
    let books = Arc::clone(&sessions.books);
    let (epoch, nullifier) = &reservation.slot_key;
    let Some(hold) = shared.budget.acquire(Budget::key(epoch, nullifier)) else {
        books.stream_closed(&reservation);
        drop_with(
            shared,
            &mut stream,
            Path::Ticket,
            shadenet_proto::REASON_PAYLOAD_LIMIT,
            &refusal(shadenet_proto::REASON_PAYLOAD_LIMIT, &[]),
        )
        .await;
        return;
    };
    let cancel = Arc::clone(&reservation.cancel);
    let dial_started = Instant::now();
    let dialed = tokio::select! {
        dialed = async {
            let candidates = egress::resolve(
                &target,
                shared.config.allow_private_targets(),
                shared.config.dns_timeout(),
            )
            .await
            .map_err(|reason| (reason.to_string(), true))?;
            egress::dial(&candidates, shared.config.idle_timeout())
                .await
                .map_err(|reason| {
                    let definite = reason != "upstream:ETIMEDOUT";
                    (reason, definite)
                })
        } => dialed,
        () = cancel.notified() => {
            books.stream_closed(&reservation);
            return;
        }
    };
    shared.registry.observe(
        "shade_tree_gateway_upstream_connect_seconds",
        dial_started.elapsed().as_secs_f64(),
    );
    let upstream = match dialed {
        Ok(upstream) => upstream,
        Err((reason, definite)) => {
            if definite {
                books.release(&reservation);
            } else {
                books.stream_closed(&reservation);
            }
            let label = if reason.starts_with("upstream:") {
                metrics::upstream_drop_label(&reason)
            } else {
                reason.as_str()
            };
            drop_with(
                shared,
                &mut stream,
                Path::Ticket,
                label,
                &refusal(&reason, &[]),
            )
            .await;
            return;
        }
    };
    if !books.spend(&reservation) {
        books.stream_closed(&reservation);
        return;
    }
    tracing::debug!(port = target.port, "tunnel established");
    shared
        .registry
        .counter("shade_tree_gateway_tunnels_total", &[("result", "pass")]);
    let _active = ActiveTunnel::open(shared);
    if !write_line(&mut stream, "{\"ok\":true}").await {
        books.stream_closed(&reservation);
        return;
    }
    let close = tunnel::relay(
        stream,
        upstream,
        early,
        hold,
        shared.config.idle_timeout(),
        Some(Arc::clone(&reservation.shaping)),
        shared.cap.clone(),
        Some(cancel),
        Arc::clone(&shared.traffic),
    )
    .await;
    count_close(shared, close);
    tracing::debug!(reason = close.label(), "tunnel closed");
    if close == Close::PayloadLimit {
        books.close_book(&reservation.book, "payload-limit");
    }
    books.stream_closed(&reservation);
}

enum Signal {
    Terminate(&'static str),
    /// SIGUSR1: `shadenet-node retire` asks the heartbeat to stop.
    Retire,
}

struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    retire: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn install() -> Result<Self, Error> {
        #[cfg(unix)]
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|source| Error::Signal {
            signal: "SIGTERM",
            source,
        })?;
        #[cfg(unix)]
        let retire = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            .map_err(|source| Error::Signal {
                signal: "SIGUSR1",
                source,
            })?;
        Ok(Self {
            #[cfg(unix)]
            terminate,
            #[cfg(unix)]
            retire,
        })
    }

    async fn recv(&mut self) -> Signal {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => Signal::Terminate("SIGINT"),
                _ = self.terminate.recv() => Signal::Terminate("SIGTERM"),
                _ = self.retire.recv() => Signal::Retire,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            Signal::Terminate("SIGINT")
        }
    }
}
