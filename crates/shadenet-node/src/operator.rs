//! The operator front door's commands other than `run` (`packages/node/bin/shadenet-node.mjs`):
//! validate everything and print the plan, mint or show the onion identity, authorize an onion
//! with the staked operator key where that key lives, read a running node's state, and stop
//! announcing. None of them starts a node.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::clock;
use crate::config::{self, Config};
use crate::error::Error;
use crate::knobs::{self, Knobs, GATEWAY_PORT, TOR_SOCKS_PORT};
use crate::onion;
use crate::receipt::Signer;
use crate::record::{self, Record};
use crate::status;
use crate::tor;
use crate::torhttp::{self, Request, Socks};
use crate::verify;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(180);
const STATUS_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_FREE_GIB: f64 = 1.0;

/// The front-door commands. Each prints what the JavaScript command printed.
pub struct Operator;

/// One line of `check`: `ok`, `warn` or `fail`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    level: &'static str,
    what: String,
}

struct Findings(Vec<Finding>);

impl Findings {
    fn ok(&mut self, what: impl Into<String>) {
        self.0.push(Finding {
            level: "ok",
            what: what.into(),
        });
    }

    fn warn(&mut self, what: impl Into<String>) {
        self.0.push(Finding {
            level: "warn",
            what: what.into(),
        });
    }

    fn fail(&mut self, what: impl Into<String>) {
        self.0.push(Finding {
            level: "fail",
            what: what.into(),
        });
    }

    fn failed(&self) -> bool {
        self.0.iter().any(|f| f.level == "fail")
    }
}

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn log(message: &str) {
    eprintln!("[shadenet-node] {message}");
}

/// Load the identity, minting one when none exists yet.
pub(crate) fn ensure_identity(hs_dir: &Path) -> Result<Signer, String> {
    let path = hs_dir.join(onion::IDENTITY_FILE);
    if !path.exists() {
        let minted = onion::mint(hs_dir, "shadenet-node", false)?;
        log(&format!("minted onion identity {}", minted.onion));
    }
    onion::make_private_dir(hs_dir)?;
    Signer::load(&path)
}

/// Add this node's onion to the user's avoid-nodes file, so a ShadeNet client run by the same
/// user on this machine never exits through it. Idempotent; `Ok(None)` when it was there.
pub(crate) fn register_own_node(onion: &str) -> Result<Option<PathBuf>, String> {
    let Some(normalized) = shadenet_proto::normalize_own_node(onion) else {
        return Ok(None);
    };
    let Some(file) = shadenet::own_nodes::avoid_nodes_path() else {
        return Ok(None);
    };
    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    let (known, _) = shadenet_proto::parse_own_node_list(&existing);
    if known.contains(&normalized) {
        return Ok(None);
    }
    if let Some(parent) = file.parent() {
        onion::make_private_dir(parent)?;
    }
    let separator = if !existing.is_empty() && !existing.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    options
        .open(&file)
        .and_then(|mut f| {
            f.write_all(
                format!(
                    "{separator}# added by shadenet-node run, {}\n{normalized}\n",
                    clock::iso_date(clock::now_ms())
                )
                .as_bytes(),
            )
        })
        .map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(Some(file))
}

fn rpc_call(url: &str, method: &str) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut last = String::new();
    for attempt in 0..3_u64 {
        let outcome = client
            .post(url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}))
            .send()
            .map_err(|e| e.to_string())
            .and_then(|response| {
                if !response.status().is_success() {
                    return Err(format!("HTTP {}", response.status().as_u16()));
                }
                response.json::<Value>().map_err(|e| e.to_string())
            })
            .and_then(|body| match body.get("error") {
                Some(error) => Err(error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("rpc error")
                    .to_string()),
                None => Ok(body.get("result").cloned().unwrap_or(Value::Null)),
            });
        match outcome {
            Ok(result) => return Ok(result),
            Err(e) => {
                last = e;
                std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
            }
        }
    }
    Err(last)
}

fn hex_to_u64(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()
}

fn port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

#[cfg(unix)]
fn free_gib(path: &Path) -> Result<f64, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs(2) writes into the struct we own; the path is a valid C string.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stats) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((stats.f_bavail as f64) * (stats.f_frsize as f64) / 2_f64.powi(30))
}

#[cfg(not(unix))]
fn free_gib(_path: &Path) -> Result<f64, String> {
    Err("free space is not checked on this platform".into())
}

fn commit_matches(commit: &str, pin: &str) -> bool {
    pin.is_empty() || pin.starts_with(commit) || commit.starts_with(pin)
}

fn short(text: &str) -> String {
    text.chars().take(7).collect()
}

/// `check [--probe] [--json]`: validate the record, RPCs, Tor, disk and ports; print the plan.
/// Returns whether the node is ready to run.
fn check(probe: bool, as_json: bool) -> Result<bool, Error> {
    let mut findings = Findings(Vec::new());
    let resolved = knobs::load(&process_env).map_err(Error::Operator)?;
    for error in &resolved.errors {
        findings.fail(format!("config: {error}"));
    }
    let knobs = &resolved.knobs;
    if let Some(path) = &resolved.toml_path {
        findings.ok(format!("node.toml read from {}", path.display()));
    }
    let hs_dir = knobs.hs_dir();
    let mut record: Option<Record> = None;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    if resolved.errors.is_empty() {
        match record::fetch(
            knobs.record.as_deref().unwrap_or_default(),
            &knobs.state,
            true,
        ) {
            Ok(fetched) => {
                findings.ok(format!(
                    "record {} ({}), set {}, {} Elder Tree(s)",
                    fetched.network,
                    fetched.status,
                    fetched.contract,
                    fetched.elders.len()
                ));
                record = Some(fetched);
            }
            Err(e) => findings.fail(e),
        }
    }
    if let Some(record) = &record {
        let commit = config::build_commit();
        let pin = record.node_commit.clone().unwrap_or_default();
        if commit == "unknown" {
            findings.warn(format!(
                "build commit unknown (not a release image or git checkout); the record pins {}",
                short(&pin)
            ));
        } else if !commit_matches(&commit, &pin) {
            findings.warn(format!(
                "this build is {}; the record pins {}. Run the release the record names unless you know why not",
                short(&commit),
                short(&pin)
            ));
        } else {
            findings.ok(format!("build {} matches the record's pin", short(&commit)));
        }
        let mut good = 0;
        for url in &record.rpc_urls {
            match rpc_call(url, "eth_chainId")
                .and_then(|chain| rpc_call(url, "eth_blockNumber").map(|head| (chain, head)))
            {
                Ok((chain, head)) => {
                    let chain = hex_to_u64(&chain).unwrap_or(0);
                    let head = hex_to_u64(&head).unwrap_or(0);
                    match record.chain_id {
                        Some(expected) if expected != chain => findings.fail(format!(
                            "rpc {url}: chain {chain}, record expects {expected}"
                        )),
                        _ => {
                            good += 1;
                            findings.ok(format!("rpc {url}: chain {chain}, head {head}"));
                        }
                    }
                }
                Err(e) => findings.warn(format!(
                    "rpc {url}: {e} (the node fails over to the next one)"
                )),
            }
        }
        if good == 0 {
            findings.fail("no RPC in the record answers; the node cannot read the member set");
        }
        let builtin = verify::builtin_artifact_id();
        for artifact in &record.artifacts {
            if artifact.id == builtin {
                findings.ok(format!(
                    "proof artifact {} present (built into this binary)",
                    artifact.id
                ));
            } else if knobs::absolute(Path::new(&artifact.vkey_path)).exists() {
                findings.ok(format!("proof artifact {} present", artifact.id));
            } else {
                findings.fail(format!(
                    "proof artifact {}: {} missing in this build (built in: {builtin})",
                    artifact.id, artifact.vkey_path
                ));
            }
        }
        env = record::derive_env(knobs, record, &explicit_vars(), &hs_dir);
    }
    let tor_info = tor::info();
    match &tor_info {
        None => findings
            .fail("tor: not on PATH (the container image bundles it; on a host, apt install tor)"),
        Some(info) => {
            findings.ok(format!(
                "tor: {}{}",
                info.version,
                if info.pow {
                    ", pow module"
                } else {
                    ", no pow module"
                }
            ));
            if knobs.pow && !info.pow {
                findings.fail("pow: enabled but this Tor has no pow module; set SHADENET_POW=0 or use a Tor built with it");
            }
            let torrc = knobs.state.join("torrc.check");
            let written = onion::make_private_dir(&knobs.state.join("tor")).and_then(|()| {
                std::fs::write(
                    &torrc,
                    tor::render_torrc(&tor::TorrcSettings {
                        state_dir: &knobs.state,
                        hs_dir: &hs_dir,
                        gateway_port: GATEWAY_PORT,
                        socks_port: TOR_SOCKS_PORT,
                        pow: knobs.pow && info.pow,
                        fleet_tally_port: None,
                        log_level: "notice",
                    }),
                )
                .map_err(|e| format!("write {}: {e}", torrc.display()))
            });
            match written.and_then(|()| tor::verify_config(&torrc)) {
                Ok(()) => findings.ok("torrc verifies"),
                Err(e) => findings.fail(format!("torrc does not verify: {e}")),
            }
            let _ = std::fs::remove_file(&torrc);
        }
    }
    match std::fs::create_dir_all(&knobs.state)
        .map_err(|e| e.to_string())
        .and_then(|()| free_gib(&knobs.state))
    {
        Ok(free) if free < MIN_FREE_GIB => findings.fail(format!(
            "state {}: {free:.2} GiB free; keep at least 1 GiB for Tor state and logs",
            knobs.state.display()
        )),
        Ok(free) => findings.ok(format!(
            "state {}: {free:.1} GiB free",
            knobs.state.display()
        )),
        Err(e) => findings.fail(format!("state {}: {e}", knobs.state.display())),
    }
    for (name, port) in [("node", GATEWAY_PORT), ("tor socks", TOR_SOCKS_PORT)] {
        if port_free(port) {
            findings.ok(format!("{name} port {port} free on loopback"));
        } else {
            findings.fail(format!(
                "{name} port {port} already in use on loopback (another node here? stop it or set SHADE_TREE_GATEWAY_PORT / SHADE_TREE_TOR_PORT)"
            ));
        }
    }
    if let Some(file) = &knobs.operator_key_file {
        match knobs::read_operator_key_file(Path::new(file)) {
            Ok(_) => findings.ok("operator key file readable, owner-only, well-formed"),
            Err(e) => findings.fail(format!("operator_key_file: {e}")),
        }
    } else if let (Some(operator), Some(sig)) = (&knobs.operator, &knobs.operator_sig) {
        match Signer::load(&config::identity_path(knobs)) {
            Ok(signer) => {
                if shadenet_proto::verify_operator_sig(&signer.onion(), operator, sig) {
                    findings.ok(format!("operator {operator} authorised this onion"));
                } else {
                    findings.fail("operator_sig does not recover operator for this node's onion (sign operatorAuthMessage(onion, operator) again)");
                }
            }
            Err(_) => findings.warn("operator_sig: cannot verify before the onion identity exists; run `shadenet-node identity` first, then sign"),
        }
    } else if record
        .as_ref()
        .is_some_and(|r| !r.elders.is_empty() && r.elder_admission.as_deref() == Some("stake"))
    {
        findings.warn("this canopy admits staked operators only (elder.admission = stake): set operator_key_file, or operator + operator_sig, or your announces will be refused not-staked");
    }
    if probe && !findings.failed() {
        if let (Some(record), Some(info)) = (&record, &tor_info) {
            log("probe: bootstrapping a temporary Tor to reach each Elder Tree (up to 3 minutes)…");
            probe_elders(knobs, &hs_dir, info, record, &mut findings);
        }
    }
    let failed = findings.failed();
    if as_json {
        let report = json!({
            "ok": !failed,
            "findings": findings.0.iter().map(|f| json!({"level": f.level, "what": f.what})).collect::<Vec<_>>(),
            "knobs": knobs.display_rows().into_iter().collect::<BTreeMap<_, _>>(),
            "env": record::redact(&env),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        for finding in &findings.0 {
            let tag = match finding.level {
                "ok" => "  ok  ",
                "warn" => " warn ",
                _ => " FAIL ",
            };
            println!("{tag} {}", finding.what);
        }
        println!("\nknobs:");
        for (key, value) in knobs.display_rows() {
            println!(
                "  {key:<18} {value}   ({})",
                resolved
                    .sources
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| "default".into())
            );
        }
        if record.is_some() {
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            println!(
                "\nwould run (cwd {cwd}):\n  tor -f {}\n  shadenet-node (the node and its heartbeat, one process)\nwith:",
                knobs.state.join("torrc").display()
            );
            for (key, value) in record::redact(&env) {
                println!("  {key}={value}");
            }
        }
        println!(
            "{}",
            if failed {
                "\nresult: not ready (fix the FAIL lines above)"
            } else {
                "\nresult: ready to run"
            }
        );
    }
    Ok(!failed)
}

fn explicit_vars() -> BTreeMap<String, String> {
    let knob_names: Vec<&str> = knobs::KNOBS.iter().map(|k| k.env).collect();
    std::env::vars()
        .filter(|(key, value)| {
            !value.trim().is_empty()
                && (key.starts_with("SHADE_TREE_")
                    || (key.starts_with("SHADENET_") && !knob_names.contains(&key.as_str())))
        })
        .collect()
}

/// `check --probe`: a temporary Tor, then `/health` of every Elder Tree over it.
fn probe_elders(
    knobs: &Knobs,
    hs_dir: &Path,
    info: &tor::Info,
    record: &Record,
    findings: &mut Findings,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            findings.fail(format!("probe: {e}"));
            return;
        }
    };
    runtime.block_on(async {
        let settings = tor::TorrcSettings {
            state_dir: &knobs.state,
            hs_dir,
            gateway_port: GATEWAY_PORT,
            socks_port: TOR_SOCKS_PORT,
            pow: knobs.pow && info.pow,
            fleet_tally_port: None,
            log_level: "notice",
        };
        let mut tor = match tor::start(&settings, PROBE_TIMEOUT).await {
            Ok(tor) => tor,
            Err(e) => {
                findings.fail(format!("probe: {e}"));
                return;
            }
        };
        let socks = Socks {
            host: "127.0.0.1".into(),
            port: TOR_SOCKS_PORT,
        };
        for elder in &record.elders {
            let tag = format!(
                "Elder {}…",
                elder.onion.chars().take(16).collect::<String>()
            );
            let request = Request {
                timeout: Duration::from_secs(30),
                ..Request::get("/health")
            };
            match torhttp::request_over_tor(&socks, &elder.onion, 80, &request, 2).await {
                Ok(health) if health.get("ok") == Some(&Value::Bool(true)) => findings.ok(format!(
                    "{tag}: {} live node(s), admission {}, commit {}",
                    health.get("count").and_then(Value::as_u64).unwrap_or(0),
                    health
                        .get("admission")
                        .and_then(Value::as_str)
                        .unwrap_or("?"),
                    short(health.get("commit").and_then(Value::as_str).unwrap_or(""))
                )),
                Ok(_) => findings.warn(format!("{tag}: unexpected /health reply")),
                Err(e) => findings.warn(format!("{tag}: {e}")),
            }
        }
        tor.stop().await;
    });
}

/// `identity`: mint (or show) the onion identity without starting.
fn identity() -> Result<(), Error> {
    let resolved = knobs::load(&process_env).map_err(Error::Operator)?;
    let hs_dir = resolved.knobs.hs_dir();
    let signer = ensure_identity(&hs_dir).map_err(Error::Operator)?;
    let out = json!({
        "onion": signer.onion(),
        "identity": hs_dir.join(onion::IDENTITY_FILE).display().to_string(),
        "note": "keep identity.local.json private; it is the node's name. To authorise it offline: sign operatorAuthMessage(onion, operator) with the staked operator key and pass SHADENET_OPERATOR + SHADENET_OPERATOR_SIG.",
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    Ok(())
}

/// `authorize --onion <onion> --key-file <file>`: sign the onion where the key lives.
fn authorize(onion: &str, key_file: &Path) -> Result<(), Error> {
    let key = knobs::read_operator_key_file(&knobs::absolute(key_file)).map_err(Error::Operator)?;
    let wallet = shadenet::eth::Wallet::from_hex(&key).map_err(Error::Operator)?;
    let onion = if onion.ends_with(".onion") {
        onion.to_string()
    } else {
        format!("{onion}.onion")
    };
    let operator = wallet.address.to_string();
    let sig = wallet.sign_message(&shadenet_proto::operator_auth_message(&onion, &operator));
    let out = json!({
        "SHADENET_OPERATOR": operator,
        "SHADENET_OPERATOR_SIG": sig,
        "onion": onion,
        "note": "durable: reusable across restarts; re-run only when the onion or the operator changes",
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    Ok(())
}

fn fetch_local(port: u64, path: &str) -> Option<(bool, String)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(STATUS_TIMEOUT)
        .build()
        .ok()?;
    let response = client
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .ok()?;
    let ok = response.status().is_success();
    Some((ok, response.text().unwrap_or_default()))
}

/// `status [--quiet]`: what a running node is doing. Returns whether it is running.
fn status(quiet: bool) -> Result<bool, Error> {
    let resolved = knobs::load(&process_env).map_err(Error::Operator)?;
    let state = &resolved.knobs.state;
    let Some(saved) = status::read(state) else {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"running": false, "state": state.display().to_string()})
                )
                .unwrap_or_default()
            );
        }
        return Ok(false);
    };
    let metrics_port = saved
        .get("metricsPort")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ready =
        (metrics_port > 0).then(|| fetch_local(metrics_port, "/readyz").is_some_and(|(ok, _)| ok));
    let pids = saved.get("pids").cloned().unwrap_or(Value::Null);
    let has_pid = |name: &str| pids.get(name).and_then(Value::as_u64).is_some();
    let running = saved.get("stoppedAt").is_none_or(Value::is_null)
        && has_pid("gateway")
        && has_pid("heartbeat")
        && has_pid("tor")
        && ready != Some(false);
    let heartbeat_port = saved
        .get("heartbeatMetricsPort")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let listed = (running && heartbeat_port > 0)
        .then(|| fetch_local(heartbeat_port, "/metrics"))
        .flatten()
        .filter(|(ok, _)| *ok)
        .and_then(|(_, text)| status::heartbeat_listing(&text));
    if !quiet {
        let mut out = json!({
            "running": running,
            "ready": ready,
            "listed": listed.as_ref().map(|l| json!(l)).unwrap_or(Value::Null),
        });
        if let (Some(object), Some(fields)) = (out.as_object_mut(), saved.as_object()) {
            for (key, value) in fields {
                object.insert(key.clone(), value.clone());
            }
        }
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        if let Some(listing) = &listed {
            if listing.get("eldersAccepted") == Some(&json!(0.0)) {
                log(&format!(
                    "no Elder Tree lists this node yet (0 of {} accepted the last announce); `docker logs` shows each Elder's answer on the `heartbeat rejected` lines",
                    listing.get("eldersTotal").and_then(Value::as_f64).unwrap_or(0.0)
                ));
            }
        }
    }
    Ok(running)
}

/// `retire`: stop announcing; the node leaves every Elder's directory within the TTL.
fn retire() -> Result<(), Error> {
    let resolved = knobs::load(&process_env).map_err(Error::Operator)?;
    let state = &resolved.knobs.state;
    let saved = status::read(state);
    let heartbeat_pid = saved
        .as_ref()
        .filter(|s| s.get("stoppedAt").is_none_or(Value::is_null))
        .and_then(|s| s.pointer("/pids/heartbeat"))
        .and_then(Value::as_u64);
    let Some(pid) = heartbeat_pid else {
        return Err(Error::Operator(
            "no running node in this state directory; nothing to retire".into(),
        ));
    };
    #[cfg(unix)]
    {
        // SAFETY: kill(2) only sends a signal; the pid comes from the node's own status file.
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) };
        if rc != 0 {
            return Err(Error::Operator(format!(
                "could not signal the node (pid {pid}): {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        return Err(Error::Operator(
            "retire needs a unix signal; stop the node instead".into(),
        ));
    }
    log(&format!(
        "heartbeat stopped. {} leaves every Elder Tree's directory within the TTL (15 minutes); open tunnels finish. Stop the node itself with SIGTERM (docker stop). To forget the identity for good, delete {}.",
        saved
            .as_ref()
            .and_then(|s| s.get("onion"))
            .and_then(Value::as_str)
            .unwrap_or("this node"),
        resolved.knobs.hs_dir().display()
    ));
    Ok(())
}

impl Operator {
    /// The `help` text of the front door.
    pub fn usage() -> String {
        format!(
            "shadenet-node: run a Shade Tree node from a deployment record\n\n  \
shadenet-node run              start (default)\n  \
shadenet-node check [--probe]  validate everything and print what would run; --probe reaches each Elder over Tor\n  \
shadenet-node identity         mint or show the onion identity\n  \
shadenet-node authorize --onion <onion> --key-file <file>\n                                 \
sign the onion with the staked operator key, where the key lives\n  \
shadenet-node status           running node's state\n  \
shadenet-node retire           stop announcing (leaves every Elder's directory within the TTL)\n\n\
Knobs (SHADENET_* env, or keys in <state>/node.toml):\n{}\n\
Everything else comes from the record. Any SHADE_TREE_* you set yourself wins (see docs/CONFIG.md).\n",
            knobs::usage_lines()
        )
    }

    /// `check`: returns whether the node is ready to run.
    pub fn check(probe: bool, json: bool) -> Result<bool, Error> {
        check(probe, json)
    }

    /// `identity`: mint or show the onion identity.
    pub fn identity() -> Result<(), Error> {
        identity()
    }

    /// `authorize`: the operator pair for an onion, signed where the key lives.
    pub fn authorize(onion: &str, key_file: &Path) -> Result<(), Error> {
        authorize(onion, key_file)
    }

    /// `status`: returns whether a node is running.
    pub fn status(quiet: bool) -> Result<bool, Error> {
        status(quiet)
    }

    /// `retire`: stop the running node's heartbeat.
    pub fn retire() -> Result<(), Error> {
        retire()
    }

    /// `run`'s front door, for the binary: resolve the configuration and serve.
    pub async fn run(config: Config) -> Result<(), Error> {
        crate::node::ShadeNode::new(config).run().await
    }
}

/// The settings `run` needs from the operator section, shared with `node.rs`.
pub(crate) struct Prepared {
    pub(crate) signer: Arc<Signer>,
    pub(crate) tor_info: tor::Info,
}

/// Before the node serves: the identity, the own-node registration and Tor's presence.
pub(crate) fn prepare(operator: &config::Operator) -> Result<Prepared, Error> {
    let signer = ensure_identity(&operator.hs_dir).map_err(Error::Operator)?;
    if operator.register_own_node {
        match register_own_node(&signer.onion()) {
            Ok(Some(file)) => log(&format!(
                "added {} to {}: ShadeNet clients on this machine will not exit through this node",
                signer.onion(),
                file.display()
            )),
            Ok(None) => {}
            Err(e) => log(&format!(
                "warning: could not record this node in the clients' avoid-nodes file ({e}); clients here may exit through it"
            )),
        }
    }
    let tor_info = tor::info().ok_or_else(|| Error::Operator("tor is not on PATH".into()))?;
    Ok(Prepared {
        signer: Arc::new(signer),
        tor_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_match_by_prefix_either_way() {
        assert!(commit_matches("abc123", "abc123def"));
        assert!(commit_matches("abc123def", "abc123"));
        assert!(commit_matches("abc", ""));
        assert!(!commit_matches("abc", "abd"));
        assert_eq!(short("114065db4d878a465e0c1d3d901a34b55cb8c193"), "114065d");
    }

    #[test]
    fn usage_lists_every_knob() {
        let usage = Operator::usage();
        for needle in [
            "SHADENET_RECORD",
            "SHADENET_SETS",
            "SHADENET_OPERATOR_SIG",
            "SHADENET_POW",
        ] {
            assert!(usage.contains(needle), "{needle}");
        }
    }
}
