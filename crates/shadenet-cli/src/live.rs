//! Commands that need the `live` build: the SDK client, the prover and on-chain membership.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use shadenet::{Client, Error};
use zeroize::Zeroizing;

use crate::config_file;
use crate::net::Context;
use crate::{
    Command, DoctorArgs, EgressArgs, FetchArgs, IdentityArgs, InitArgs, LeavesArgs, ProxyArgs,
    ServiceKind, StatusArgs, EXIT_USAGE,
};

// ------------------------------------------------------------------ compat
//
// `enroll`, `register-member` and the `member-*` commands predate the SDK and read the selected
// network through these functions.

static SELECTED_NETWORK: OnceLock<shadenet::Network> = OnceLock::new();

fn selected_network() -> Result<&'static shadenet::Network, String> {
    if let Some(network) = SELECTED_NETWORK.get() {
        return Ok(network);
    }
    let network = shadenet::Network::bundled(shadenet::profile::DEFAULT_NETWORK)
        .map_err(|e| e.to_string())?;
    Ok(SELECTED_NETWORK.get_or_init(|| network))
}

pub(crate) mod compat {
    #[cfg(test)]
    pub type BundledDeployment = shadenet::profile::Deployment;
    #[cfg(test)]
    pub const DEFAULT_DEPLOYMENT: &str = shadenet::profile::SEPOLIA_DEPLOYMENT;

    #[cfg(test)]
    pub fn parse_bundled_deployment(raw: &str) -> Result<BundledDeployment, String> {
        shadenet::profile::parse_deployment("bundled", raw)
    }

    #[cfg(test)]
    pub fn staked_default_limit_from(deployment: &BundledDeployment) -> Result<u64, String> {
        shadenet::Network {
            name: "bundled".into(),
            deployment: deployment.clone(),
        }
        .staked_default_limit()
        .map_err(|e| e.to_string())
    }

    pub fn default_staked_limit() -> Result<u64, String> {
        super::selected_network()?
            .staked_default_limit()
            .map_err(|e| e.to_string())
    }

    pub fn default_public_profile() -> Result<shadenet::PublicProfile, String> {
        super::selected_network()?
            .public_profile()
            .map_err(|e| e.to_string())
    }

    pub fn identity_creation_limit_setting(
        flag: Option<&str>,
        env: Option<&str>,
        bundled_default: u64,
    ) -> Result<u64, String> {
        let limit = match flag.or(env) {
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
}

// ---------------------------------------------------------------- dispatch

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))
}

fn fail(prefix: &str, error: &Error) -> ExitCode {
    eprintln!("{prefix}: {error}");
    ExitCode::from(error.exit_code())
}

fn usage(prefix: &str, message: impl std::fmt::Display) -> ExitCode {
    eprintln!("{prefix}: {message}");
    ExitCode::from(EXIT_USAGE)
}

pub fn dispatch(command: Command, ctx: &Context) -> ExitCode {
    match ctx.network() {
        Ok(network) => {
            let _ = SELECTED_NETWORK.set(network);
        }
        Err(message) => return usage("shadenet", message),
    }
    match command {
        Command::Init(args) => init(args, ctx),
        Command::Status(args) => status(args, ctx),
        Command::Plan(args) => plan(args, ctx),
        Command::Doctor(args) => doctor(args, ctx),
        Command::Proxy(args) => proxy(args, ctx),
        Command::Mcp(args) => crate::mcp::serve(args, ctx),
        Command::Fetch(args) => fetch(args, ctx),
        Command::Egress(args) => egress(args, ctx),
        Command::ProxyToken => crate::enroll::cmd_proxy_token(&[]),
        Command::Enroll(pass) => crate::enroll::cmd_enroll(&pass.args),
        Command::Identity(args) => identity(args),
        Command::IdentityLock(args) => match lock_or_unlock(args, true, ctx) {
            Ok(message) => {
                eprintln!("{message}");
                ExitCode::SUCCESS
            }
            Err(e) => usage("identity-lock", e),
        },
        Command::IdentityUnlock(args) => match lock_or_unlock(args, false, ctx) {
            Ok(message) => {
                eprintln!("{message}");
                ExitCode::SUCCESS
            }
            Err(e) => usage("identity-unlock", e),
        },
        Command::RegisterMember(pass) => crate::register::cmd_register_member(&pass.args),
        Command::MemberStatus(pass) => {
            crate::member::cmd_member(crate::member::Action::Status, &pass.args)
        }
        Command::ExitMember(pass) => {
            crate::member::cmd_member(crate::member::Action::Exit, &pass.args)
        }
        Command::WithdrawMember(pass) => {
            crate::member::cmd_member(crate::member::Action::Withdraw, &pass.args)
        }
        Command::Leaves(args) => leaves(args),
        Command::Version
        | Command::VerifyDirectory(_)
        | Command::FetchDirectory(_)
        | Command::Select(_)
        | Command::VerifyReceipt(_)
        | Command::Run(_) => unreachable!("handled by the offline dispatcher"),
    }
}

pub(crate) fn build_client(
    net: &crate::NetArgs,
    ctx: &Context,
    need_identity: bool,
) -> Result<Client, String> {
    let config = net.to_config(ctx, need_identity)?;
    Client::new(config).map_err(|e| e.to_string())
}

/// The longest a queued tunnel waits: flag, then `SHADENET_QUEUE_MAX_WAIT_SECS`, then the config
/// file, then two epochs (ADR 0013). `--no-queue` or a value of 0 refuses at once.
pub(crate) fn queue_max_wait(
    queue: &crate::QueueArgs,
    ctx: &Context,
    epoch_seconds: u64,
) -> Result<Option<Duration>, String> {
    if queue.no_queue {
        return Ok(None);
    }
    let seconds = match queue.max_wait {
        Some(seconds) => seconds,
        None => match shadenet::env::var("QUEUE_MAX_WAIT_SECS")?.filter(|v| !v.trim().is_empty()) {
            Some(raw) => raw.trim().parse::<u64>().map_err(|_| {
                format!("SHADENET_QUEUE_MAX_WAIT_SECS must be an integer (got {raw:?})")
            })?,
            None => ctx
                .file
                .queue_max_wait_secs
                .unwrap_or_else(|| shadenet::scheduler::default_max_wait_seconds(epoch_seconds)),
        },
    };
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

/// [`build_client`] with the budget queue configured for `proxy`, `mcp` and `fetch`.
pub(crate) fn build_client_queued(
    net: &crate::NetArgs,
    queue: &crate::QueueArgs,
    ctx: &Context,
    need_identity: bool,
) -> Result<Client, String> {
    let mut config = net.to_config(ctx, need_identity)?;
    let epoch_seconds = config.effective_epoch_seconds();
    config.queue_max_wait = queue_max_wait(queue, ctx, epoch_seconds)?;
    Client::new(config).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ running proxy

/// A `shadenet proxy` already listening on the configured address (flag, `SHADENET_LISTEN`,
/// `config.toml`, else the default), reachable with this machine's proxy token. One-shot
/// commands prefer it to starting their own client (ADR 0013, #236): no Tor bootstrap, no
/// canopy fetch, and the proxy's own books, queue and node latencies.
pub(crate) struct RunningProxy {
    pub url: String,
    pub token: Zeroizing<String>,
}

pub(crate) fn running_proxy(ctx: &Context) -> Option<RunningProxy> {
    let token = proxy_token(None, ctx).ok()?;
    let listen = shadenet::env::var_lenient("LISTEN")
        .or_else(|| ctx.file.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:8118".into());
    let url = format!("http://{listen}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .no_proxy()
        .build()
        .ok()?;
    let response = client
        .get(format!("{url}/_shadenet/health"))
        .bearer_auth(token.as_str())
        .send()
        .ok()?;
    (response.status().as_u16() == 204).then_some(RunningProxy { url, token })
}

impl RunningProxy {
    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;
        client
            .get(format!("{}{path}", self.url))
            .bearer_auth(self.token.as_str())
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<T>())
            .map_err(|e| format!("{path} via the running proxy: {e}"))
    }

    fn status(&self) -> Result<shadenet::Status, String> {
        self.get_json("/_shadenet/status")
    }

    fn plan(&self, count: u64) -> Result<shadenet::Plan, String> {
        self.get_json(&format!("/_shadenet/plan?count={count}"))
    }

    /// Fetch through the proxy's CONNECT path: the proxy spends the ticket or slot, queues the
    /// request if the budget is spent, and keeps its session books.
    fn fetch(&self, request: &shadenet::FetchRequest) -> Result<shadenet::FetchResponse, String> {
        let proxy = reqwest::Proxy::all(&self.url)
            .map_err(|e| e.to_string())?
            .basic_auth("shadenet", self.token.as_str());
        let client = reqwest::blocking::Client::builder()
            .proxy(proxy)
            .timeout(request.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| format!("bad method: {e}"))?;
        let mut builder = client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        let response = builder
            .send()
            .map_err(|e| format!("fetch via the running proxy: {e}"))?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let mut body = response.bytes().map_err(|e| e.to_string())?.to_vec();
        let truncated = body.len() > request.max_bytes;
        body.truncate(request.max_bytes);
        Ok(shadenet::FetchResponse {
            status,
            headers,
            body,
            truncated,
            gateway: "(running proxy)".into(),
            epoch: 0,
        })
    }
}

// ------------------------------------------------------------------ status

fn state_exit(state: &str) -> ExitCode {
    match state {
        "ready" => ExitCode::SUCCESS,
        "budget_exhausted" => ExitCode::from(4),
        "degraded" => ExitCode::from(3),
        _ => ExitCode::from(EXIT_USAGE),
    }
}

/// What one unit of the per-epoch budget opens: a session of several tunnels with session
/// tickets, otherwise one tunnel. Human output names the budget this way instead of "tier N".
fn budget_unit(network: &shadenet::Network) -> &'static str {
    if network.deployment.session_tickets {
        "sessions"
    } else {
        "tunnels"
    }
}

/// Nodes named on the human `status` line; the rest are counted (`--json` lists all of them).
const NODE_LINE_MAX: usize = 6;

fn print_status(status: &shadenet::Status) {
    println!("state: {}", status.state);
    println!("network: {} (shadenet {})", status.network, status.version);
    if let Some(leaf) = &status.leaf {
        println!("leaf: {leaf}");
    }
    match (status.admitted, status.finalized) {
        (Some(true), _) => println!(
            "admitted: yes, finalized, in {}",
            status.admission_set.as_deref().unwrap_or("?")
        ),
        (Some(false), Some(false)) => println!(
            "admitted: registered but not finalized yet in {} (about 13 minutes on Sepolia)",
            status.admission_set.as_deref().unwrap_or("?")
        ),
        (Some(false), _) => println!(
            "admitted: no; register with `shadenet register-member --identity <file> --key-file <funded key>`"
        ),
        (None, _) => {}
    }
    match (status.slots_used, status.slots_left) {
        (Some(used), Some(left)) => {
            // The per-epoch budget counts proofs. With session tickets each proof opens a session
            // of several tunnels, so the queue line's "tunnels per epoch" is a multiple of this.
            let limit = status.tier.unwrap_or_default();
            let per_proof = status
                .queue
                .capacity_per_epoch
                .checked_div(limit)
                .unwrap_or(0);
            let unit = if per_proof > 1 {
                format!("sessions ({per_proof} tunnels each)")
            } else {
                "tunnels".to_string()
            };
            println!(
                "epoch: {} ({}s window, resets in {}s); {unit} used {used} of {limit}, left {left}",
                status.epoch, status.epoch_seconds, status.epoch_resets_in_seconds
            )
        }
        _ => println!(
            "epoch: {} ({}s window, resets in {}s)",
            status.epoch, status.epoch_seconds, status.epoch_resets_in_seconds
        ),
    }
    let canopy = &status.canopy;
    match canopy.issued {
        Some(issued) => println!(
            "canopy: {} node(s), {} eligible, issued {issued} ({}s ago){}",
            canopy.nodes,
            canopy.eligible,
            canopy.age_seconds.unwrap_or_default(),
            if canopy.from_last_known_good {
                ", from last-known-good copy"
            } else {
                ""
            }
        ),
        None => println!("canopy: unavailable"),
    }
    if let Some(error) = &canopy.error {
        println!("canopy note: {error}");
    }
    println!(
        "tor: {}",
        if status.tor_ready {
            "bootstrapped"
        } else {
            "not bootstrapped yet"
        }
    );
    if status.queue.enabled || status.queue.depth > 0 {
        println!(
            "queue: {} waiting, next tunnel in {}s, {} tunnel(s) per epoch, max wait {}s",
            status.queue.depth,
            status.queue.next_slot_in_seconds,
            status.queue.capacity_per_epoch,
            status.queue.max_wait_seconds
        );
    }
    if !status.nodes.is_empty() {
        let line: Vec<String> = status
            .nodes
            .iter()
            .take(NODE_LINE_MAX)
            .map(|node| {
                format!(
                    "{}{} {}{}",
                    &node.onion[..node.onion.len().min(8)],
                    if node.preferred { "*" } else { "" },
                    node.health,
                    match node.latency_ms {
                        Some(ms) => format!(" {}ms", ms as u64),
                        None => String::new(),
                    }
                )
            })
            .collect();
        // `--json` carries every node; the human line names the first few and counts the rest.
        let more = status.nodes.len().saturating_sub(NODE_LINE_MAX);
        if more > 0 {
            println!("nodes: {}, +{more} more", line.join(", "));
        } else {
            println!("nodes: {}", line.join(", "));
        }
    }
    if let Some(error) = &status.last_error {
        println!(
            "last error: {} ({})",
            error["message"].as_str().unwrap_or(""),
            error["code"].as_str().unwrap_or("")
        );
    }
}

// ------------------------------------------------------------------ plan

fn plan(args: crate::PlanArgs, ctx: &Context) -> ExitCode {
    let listed: Vec<String> = args
        .urls
        .iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let requests = if listed.is_empty() {
        args.count.unwrap_or(1)
    } else {
        listed.len() as u64
    };
    let hosts: std::collections::BTreeSet<String> = listed
        .iter()
        .map(|item| {
            let rest = item
                .strip_prefix("https://")
                .or_else(|| item.strip_prefix("http://"))
                .unwrap_or(item);
            rest.split('/').next().unwrap_or(rest).to_ascii_lowercase()
        })
        .collect();
    let plan = match (args.direct, running_proxy(ctx)) {
        (false, Some(proxy)) => match proxy.plan(requests) {
            Ok(plan) => plan,
            Err(message) => return usage("plan", message),
        },
        _ => match build_client(&args.net, ctx, false) {
            Ok(client) => client.plan(requests),
            Err(message) => return usage("plan", message),
        },
    };
    if args.json {
        let mut value = serde_json::to_value(&plan).unwrap_or_default();
        value["distinctHosts"] = (hosts.len() as u64).into();
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        println!(
            "plan: {} fetch(es){} with {} {} per {}s epoch{}",
            plan.requests,
            if hosts.is_empty() {
                String::new()
            } else {
                format!(" to {} host(s)", hosts.len())
            },
            plan.tier,
            if plan.session_tickets {
                "sessions"
            } else {
                "tunnels"
            },
            plan.epoch_seconds,
            if plan.session_tickets {
                format!(
                    ", session tickets: {} tunnels per proof",
                    plan.tickets_per_book
                )
            } else {
                String::new()
            }
        );
        println!(
            "now: {} tunnel(s) available, {} queued ahead; {} per epoch",
            plan.available_now, plan.queue_depth, plan.capacity_per_epoch
        );
        println!("{}", plan.advice);
        if !hosts.is_empty() && (hosts.len() as u64) < plan.requests {
            println!(
                "tip: {} of these share a host; a keep-alive connection serves them on one tunnel",
                plan.requests - hosts.len() as u64
            );
        }
    }
    ExitCode::SUCCESS
}

fn status(args: StatusArgs, ctx: &Context) -> ExitCode {
    if !args.direct && !args.wait {
        if let Some(proxy) = running_proxy(ctx) {
            return match proxy.status() {
                Ok(status) => {
                    if args.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&status).unwrap_or_default()
                        );
                    } else {
                        print_status(&status);
                        println!("via: running proxy at {}", proxy.url);
                    }
                    state_exit(&status.state)
                }
                Err(message) => usage("status", message),
            };
        }
    }
    let client = match build_client_queued(&args.net, &args.queue, ctx, false) {
        Ok(client) => client,
        Err(message) => return usage("status", message),
    };
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(message) => return usage("status", message),
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(args.wait_timeout);
    let status = rt.block_on(async {
        loop {
            let status = client.status().await;
            if !args.wait || status.state == "ready" || std::time::Instant::now() >= deadline {
                return status;
            }
            tracing::info!(state = %status.state, "waiting for ready");
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).unwrap_or_default()
        );
    } else {
        print_status(&status);
    }
    state_exit(&status.state)
}

// ------------------------------------------------------------------ proxy

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let raw = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?,
    );
    Ok(Zeroizing::new(raw.trim().to_string()))
}

/// Token from --token-file, SHADENET_PROXY_TOKEN_FILE, SHADENET_PROXY_TOKEN, or the config file.
pub(crate) fn proxy_token(
    flag: Option<&PathBuf>,
    ctx: &Context,
) -> Result<Zeroizing<String>, String> {
    if let Some(path) = flag {
        return read_secret_file(path);
    }
    if let Some(path) = shadenet::env::var("PROXY_TOKEN_FILE")? {
        return read_secret_file(Path::new(&path));
    }
    if let Some(token) = shadenet::env::var("PROXY_TOKEN")? {
        return Ok(Zeroizing::new(token));
    }
    if let Some(path) = &ctx.file.proxy_token_file {
        return read_secret_file(path);
    }
    Err(
        "missing proxy token; set SHADENET_PROXY_TOKEN, pass --token-file, or run `shadenet init`"
            .into(),
    )
}

fn proxy(args: ProxyArgs, ctx: &Context) -> ExitCode {
    let token = match proxy_token(args.token_file.as_ref(), ctx) {
        Ok(token) => token,
        Err(message) => return usage("proxy", message),
    };
    let client = match build_client_queued(&args.net, &args.queue, ctx, true) {
        Ok(client) => Arc::new(client),
        Err(message) => return usage("proxy", message),
    };
    let warm = if args.no_warm {
        0
    } else {
        args.warm
            .or_else(|| shadenet::env::parse("WARM_NODES"))
            .or(ctx.file.warm_nodes)
            .unwrap_or(2)
    };
    let listen = args
        .listen
        .clone()
        .or_else(|| shadenet::env::var_lenient("LISTEN"))
        .or_else(|| ctx.file.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:8118".into());
    let mut config = shadenet::ProxyConfig::new(listen, token.as_str());
    config.allow_non_loopback =
        args.allow_non_loopback || ctx.file.allow_non_loopback.unwrap_or(false);
    config.max_tunnels = args
        .max_tunnels
        .or_else(|| shadenet::env::parse("MAX_TUNNELS"))
        .or(ctx.file.max_tunnels)
        .unwrap_or(64);
    config.max_setups = args
        .max_setups
        .or_else(|| shadenet::env::parse("MAX_SETUPS"))
        .or(ctx.file.max_setups)
        .unwrap_or(16);
    config.once = args.once;
    config.targets = {
        let mut list: Vec<String> = args
            .targets
            .iter()
            .flat_map(|raw| raw.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if list.is_empty() {
            if let Some(raw) = shadenet::env::var_lenient("TARGETS") {
                list = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
        }
        if list.is_empty() {
            list = ctx.file.targets.clone().unwrap_or_default();
        }
        list
    };
    if !config.targets.is_empty() {
        tracing::info!(targets = ?config.targets, "destination allow-list on; other hosts get 403 target_not_allowed");
    }
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(message) => return usage("proxy", message),
    };
    let result = rt.block_on(async move {
        let listener = shadenet::proxy::bind(&config).await?;
        let bound = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| config.listen.clone());
        // Harnesses and service managers wait for this exact line.
        eprintln!("{} proxy listening on http://{bound}", invoked_name());
        client.spawn_canopy_refresh();
        client.spawn_warmer(warm, Duration::from_secs(60));
        if args.preopen
            || shadenet::env::flag("PREOPEN").unwrap_or(false)
            || ctx.file.preopen_books.unwrap_or(false)
        {
            // Task 71: a first request otherwise pays for proving and initializing a book.
            client.spawn_preopener(Duration::from_secs(600));
        }
        let preflight = Arc::clone(&client);
        tokio::spawn(async move {
            let status = preflight.status().await;
            match status.state.as_str() {
                "ready" => tracing::info!(
                    slots_left = status.slots_left.unwrap_or_default(),
                    nodes = status.canopy.eligible,
                    "ready"
                ),
                "not_admitted" => tracing::warn!("this identity is not admitted yet; tunnels will answer 403 not_admitted until it is registered and finalized"),
                "not_finalized" => tracing::warn!("this identity is registered but not finalized yet; tunnels will answer 403 not_finalized for a few more minutes"),
                other => tracing::warn!(state = other, "proxy started in a degraded state; see GET /_shadenet/status"),
            }
        });
        shadenet::proxy::serve(client, listener, config).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail("proxy", &error),
    }
}

/// The name this binary was started as (`shadenet` or the `shade-tree` alias).
pub(crate) fn invoked_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|arg| {
            Path::new(&arg)
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .filter(|name| name == "shade-tree")
        .unwrap_or_else(|| "shadenet".into())
}

// ------------------------------------------------------------------- fetch

pub(crate) fn parse_header(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("header {raw:?} must be `Name: value`"))?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(format!("bad header name {name:?}"));
    }
    Ok((name.to_string(), value.trim().to_string()))
}

fn fetch(args: FetchArgs, ctx: &Context) -> ExitCode {
    let headers = match args
        .headers
        .iter()
        .map(|h| parse_header(h))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(headers) => headers,
        Err(message) => return usage("fetch", message),
    };
    let request = shadenet::FetchRequest {
        url: args.url.clone(),
        method: args.method.to_ascii_uppercase(),
        headers,
        body: args.data.clone().map(String::into_bytes),
        max_bytes: args.max_bytes,
        timeout: Duration::from_secs(180),
    };
    let outcome = match (args.direct, running_proxy(ctx)) {
        (false, Some(proxy)) => proxy.fetch(&request).map_err(shadenet::Error::Transport),
        _ => {
            let client = match build_client_queued(&args.net, &args.queue, ctx, true) {
                Ok(client) => client,
                Err(message) => return usage("fetch", message),
            };
            let rt = match runtime() {
                Ok(rt) => rt,
                Err(message) => return usage("fetch", message),
            };
            rt.block_on(client.fetch(request))
        }
    };
    match outcome {
        Ok(response) => {
            use std::io::Write;
            if args.json {
                let mut value = serde_json::to_value(&response).unwrap_or_default();
                value["body"] = match std::str::from_utf8(&response.body) {
                    Ok(text) => text.into(),
                    Err(_) => {
                        use base64::Engine as _;
                        value["bodyEncoding"] = "base64".into();
                        base64::engine::general_purpose::STANDARD
                            .encode(&response.body)
                            .into()
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else {
                let mut out = std::io::stdout().lock();
                if args.include {
                    let _ = writeln!(out, "HTTP/1.1 {}", response.status);
                    for (name, value) in &response.headers {
                        let _ = writeln!(out, "{name}: {value}");
                    }
                    let _ = writeln!(out);
                }
                let _ = out.write_all(&response.body);
                let _ = out.flush();
            }
            eprintln!(
                "fetch: HTTP {} via {} (epoch {}){}",
                response.status,
                response.gateway,
                response.epoch,
                if response.truncated {
                    ", body truncated"
                } else {
                    ""
                }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            if args.json {
                println!("{}", error.to_json());
            }
            fail("fetch", &error)
        }
    }
}

// ------------------------------------------------------------------ egress

async fn relay_stdio(
    stream: shadenet::transport::BoxStream,
    proxy_response: bool,
) -> Result<(), String> {
    use tokio::io::{copy, split, AsyncWriteExt};
    let (mut reader, mut writer) = split(stream);
    let mut stdout = tokio::io::stdout();
    if proxy_response {
        stdout
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: shadenet-rust\r\n\r\n")
            .await
            .map_err(|e| format!("write proxy response: {e}"))?;
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
        // The gateway treats a client FIN as a full close, so a finite `printf | --stdio` keeps the
        // write half open to receive the reply. CONNECT helpers propagate EOF so children exit.
        if proxy_response {
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

fn egress(args: EgressArgs, ctx: &Context) -> ExitCode {
    let client = match build_client(&args.net, ctx, true) {
        Ok(client) => client,
        Err(message) => return usage("egress", message),
    };
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(message) => return usage("egress", message),
    };
    let relay = args.stdio || args.proxy_response;
    let result = rt.block_on(async {
        let tunnel = client.connect(&args.target).await?;
        if !relay {
            return Ok::<_, Error>((
                tunnel.gateway.clone(),
                tunnel.target.clone(),
                tunnel.nullifier.clone(),
                tunnel.receipt.clone(),
                tunnel.epoch,
                None,
            ));
        }
        let gateway = tunnel.gateway.clone();
        let outcome = relay_stdio(tunnel.into_stream(), args.proxy_response).await;
        Ok((
            gateway,
            String::new(),
            String::new(),
            None,
            0,
            Some(outcome),
        ))
    });
    // A bounded shutdown: Tokio's stdin is a blocking read that must not hold the process open
    // once the destination has closed.
    rt.shutdown_timeout(Duration::from_millis(100));
    match result {
        Ok((gateway, _, _, _, _, Some(outcome))) => {
            if let Err(error) = outcome {
                eprintln!("egress: accepted tunnel relay ended with error: {error}");
            }
            eprintln!("egress: tunnel via {gateway} closed");
            ExitCode::SUCCESS
        }
        Ok((gateway, target, nullifier, receipt, epoch, None)) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "gateway": gateway,
                        "target": target,
                        "nullifier": nullifier,
                        "epoch": epoch,
                        "receipt": receipt,
                    })
                );
            } else {
                println!("ok");
                println!("gateway: {gateway}");
                println!("target: {target}");
                println!("nullifier: {nullifier}");
                if let Some(receipt) = receipt {
                    println!("receipt: {receipt}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if args.json {
                println!("{}", error.to_json());
            } else if let Error::NodeRefused { reason, ack, .. } = &error {
                println!("not-ok: gate-refused: {reason}");
                if let Some(list) = ack.get("artifacts").and_then(serde_json::Value::as_array) {
                    let ids: Vec<&str> =
                        list.iter().filter_map(serde_json::Value::as_str).collect();
                    println!("gateway accepts artifacts: {}", ids.join(","));
                }
            }
            fail("egress", &error)
        }
    }
}

// ---------------------------------------------------------------- identity

fn identity(args: IdentityArgs) -> ExitCode {
    use serde::Serialize;
    use std::io::{Read, Write};

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output<'a> {
        identity_secret: &'a str,
        leaf: &'a str,
        limit: u64,
    }

    let (secret, source) = if let Some(path) = &args.secret_file {
        match read_secret_file(path) {
            Ok(secret) => (secret, format!("--secret-file {}", path.display())),
            Err(e) => return usage("identity", e),
        }
    } else if args.secret_stdin {
        let mut raw = Zeroizing::new(String::new());
        if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
            return usage("identity", format!("read stdin: {e}"));
        }
        (Zeroizing::new(raw.trim().to_string()), "stdin".to_string())
    } else {
        match shadenet::env::var("SECRET") {
            Ok(Some(secret)) => (Zeroizing::new(secret), "SHADENET_SECRET".to_string()),
            Ok(None) => {
                return usage(
                    "identity",
                    "no secret; pass --secret-file or --secret-stdin, or set SHADENET_SECRET (secrets are never taken from argv)",
                )
            }
            Err(e) => return usage("identity", e),
        }
    };
    let bundled = match compat::default_staked_limit() {
        Ok(limit) => limit,
        Err(e) => return usage("identity", e),
    };
    let limit_env = shadenet::env::var_lenient("LIMIT");
    let limit_flag = args.limit.map(|l| l.to_string());
    let limit = match compat::identity_creation_limit_setting(
        limit_flag.as_deref(),
        limit_env.as_deref(),
        bundled,
    ) {
        Ok(limit) => limit,
        Err(e) => return usage("identity", e),
    };
    let material = match shadenet_rln::identity::derive_identity(&secret, limit) {
        Ok(material) => material,
        Err(e) => return usage("identity", e),
    };
    let body = Zeroizing::new(
        serde_json::to_string_pretty(&Output {
            identity_secret: &material.identity_secret,
            leaf: &material.leaf,
            limit,
        })
        .unwrap_or_default()
            + "\n",
    );
    match &args.out {
        Some(path) => {
            if let Err(e) = write_private(path, body.as_bytes()) {
                return usage("identity", e);
            }
            eprintln!(
                "shadenet identity: {source}; public leaf {}; wrote {}",
                material.leaf,
                path.display()
            );
        }
        None => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(body.as_bytes());
            eprintln!("shadenet identity: {source}; public leaf {}", material.leaf);
        }
    }
    ExitCode::SUCCESS
}

/// Write owner-only (0600 on Unix), creating parent directories owner-only too.
pub(crate) fn write_private(path: &Path, body: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.write_all(body)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

// ---------------------------------------------------------- identity lock

fn lock_identity(path: &Path) -> Result<(), String> {
    let material = shadenet::identity::load(path, || {
        Err(shadenet::Error::Config(format!(
            "{} is already passphrase-protected",
            path.display()
        )))
    })
    .map_err(|e| e.to_string())?;
    let passphrase = crate::passphrase::choose()?;
    let body = shadenet::identity::serialize(
        &material,
        Some(&passphrase),
        shadenet::identity::DEFAULT_LOG_N,
    )
    .map_err(|e| e.to_string())?;
    shadenet::identity::replace_file(path, &body).map_err(|e| e.to_string())
}

fn lock_or_unlock(
    args: crate::IdentityFileArgs,
    lock: bool,
    ctx: &Context,
) -> Result<String, String> {
    let path = ctx
        .identity_path(args.identity.as_ref())?
        .ok_or("no identity: pass --identity or set SHADENET_IDENTITY")?;
    let public = shadenet::identity::read_public(&path).map_err(|e| e.to_string())?;
    if lock {
        if public.encrypted {
            return Ok(format!(
                "{} is already passphrase-protected",
                path.display()
            ));
        }
        lock_identity(&path)?;
        Ok(format!(
            "{} is now passphrase-protected. Services read it with SHADENET_PASSPHRASE_FILE.",
            path.display()
        ))
    } else {
        if !public.encrypted {
            return Ok(format!("{} has no passphrase", path.display()));
        }
        let material = shadenet::identity::load(&path, || {
            crate::passphrase::unlock(&path).map_err(shadenet::Error::Config)
        })
        .map_err(|e| e.to_string())?;
        let body = shadenet::identity::serialize(&material, None, 0).map_err(|e| e.to_string())?;
        shadenet::identity::replace_file(&path, &body).map_err(|e| e.to_string())?;
        Ok(format!("{} no longer has a passphrase", path.display()))
    }
}

// ------------------------------------------------------------------ leaves

fn leaves(args: LeavesArgs) -> ExitCode {
    let contract = args
        .contract
        .clone()
        .or_else(|| shadenet::env::var_lenient("PAID_ACCESS_CONTRACT"))
        .or_else(|| {
            shadenet::env::var_lenient("GROUP_CONTRACT")
                .and_then(|v| v.split(',').next().map(str::trim).map(str::to_string))
        })
        .filter(|s| !s.is_empty());
    let Some(contract) = contract else {
        return usage("leaves", "no contract; pass --contract or set SHADENET_GROUP_CONTRACT / SHADENET_PAID_ACCESS_CONTRACT");
    };
    let rpc_url = args
        .rpc_url
        .clone()
        .or_else(|| shadenet::env::var_lenient("RPC_URL"))
        .unwrap_or_else(|| "http://127.0.0.1:8545".into());
    let from = args
        .from_block
        .clone()
        .or_else(|| shadenet::env::var_lenient("FROM_BLOCK"))
        .unwrap_or_else(|| "0".into());
    let from_block = match from.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => from.parse::<u64>(),
    };
    let Ok(from_block) = from_block else {
        return usage("leaves", format!("invalid --from-block {from:?}"));
    };
    let rln_identifier = args
        .rln_identifier
        .or_else(|| shadenet::env::parse("RLN_IDENTIFIER"))
        .unwrap_or(1);
    let discovered = match shadenet::leaves::fetch_members(
        &rpc_url,
        &contract,
        from_block,
        &args.block_tag,
        rln_identifier,
    ) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("leaves: {e}");
            return ExitCode::from(1);
        }
    };
    let body = serde_json::to_string_pretty(&discovered.document).unwrap_or_default() + "\n";
    let summary = format!(
        "shadenet leaves: {contract}: {} live leaves in {} slots; root {}",
        discovered.live_count,
        discovered.document.members.len(),
        discovered.root
    );
    match &args.out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &body) {
                return usage("leaves", format!("write {}: {e}", path.display()));
            }
            eprintln!("{summary}; wrote {}", path.display());
        }
        None => {
            print!("{body}");
            eprintln!("{summary}");
        }
    }
    ExitCode::SUCCESS
}

// -------------------------------------------------------------------- init

fn init(args: InitArgs, ctx: &Context) -> ExitCode {
    let Some(dir) = args.dir.clone().or_else(config_file::default_dir) else {
        return usage("init", "no config directory; pass --dir");
    };
    let network = match ctx.network() {
        Ok(network) => network,
        Err(message) => return usage("init", message),
    };
    let identity_path = dir.join("identity.json");
    let token_path = dir.join("proxy-token");
    let config_path = dir.join("config.toml");
    if let Some(kind) = args.service {
        print!("{}", service_unit(kind, &config_path));
        return ExitCode::SUCCESS;
    }
    if let Err(e) = create_private_dir(&dir) {
        return usage("init", e);
    }
    let mut created = Vec::new();
    // Identity: never overwritten.
    let freshly_created = !identity_path.exists();
    if freshly_created {
        let limit = match args
            .limit
            .map(Ok)
            .unwrap_or_else(|| network.staked_default_limit())
        {
            Ok(limit) => limit,
            Err(e) => return usage("init", e),
        };
        if let Err(e) = crate::enroll::create_identity(&identity_path, limit) {
            return usage("init", e);
        }
        created.push(identity_path.display().to_string());
    }
    // Derive the public identity commitment `Poseidon1(identitySecret)`, the leaf
    // `Poseidon2(commitment, tier)` and the tier, so init can print what `registerIdentity`
    // actually takes and a stake link that carries it. A plaintext identity (always the case
    // for one freshly created here, before any passphrase lock below) loads without a
    // passphrase; an already-encrypted file is read for its public leaf/tier only — the
    // commitment needs an unlock, which `register-member --identity` performs at stake time.
    let (identity_commitment, leaf, tier): (Option<String>, String, Option<u64>) =
        match shadenet::identity::load(&identity_path, || {
            Err(Error::Config("identity is passphrase-protected".into()))
        }) {
            Ok(material) => match shadenet::member::verify_identity(&material, args.limit) {
                Ok(v) => (
                    Some(v.identity_commitment.to_string()),
                    v.leaf.to_string(),
                    Some(v.limit),
                ),
                Err(e) => return usage("init", e),
            },
            Err(_) => match shadenet::identity::read_public(&identity_path) {
                Ok(public) => (None, public.leaf, public.limit),
                Err(_) => {
                    return usage(
                        "init",
                        format!(
                            "{} exists but is not an identity file",
                            identity_path.display()
                        ),
                    )
                }
            },
        };
    // Lock a freshly-created identity only after the commitment has been derived above.
    if freshly_created && args.passphrase {
        if let Err(e) = lock_identity(&identity_path) {
            return usage("init", e);
        }
    }
    // The stake link fragment is never sent to a server; the page verifies Poseidon2(c, tier)
    // == leaf. Present only when the commitment is known (not for an encrypted re-init).
    let stake_link = match (&identity_commitment, tier) {
        (Some(idc), Some(tier)) => Some(format!(
            "https://shadenet.xyz/stake/#c={idc}&limit={tier}&leaf={leaf}"
        )),
        _ => None,
    };
    if !token_path.exists() {
        let token = match crate::enroll::fresh_token() {
            Ok(token) => Zeroizing::new(token),
            Err(e) => return usage("init", e),
        };
        if let Err(e) = write_private(&token_path, format!("{}\n", token.as_str()).as_bytes()) {
            return usage("init", e);
        }
        created.push(token_path.display().to_string());
    }
    if !config_path.exists() {
        let network_value = if network.name == shadenet::profile::DEFAULT_NETWORK {
            network.name.clone()
        } else {
            ctx.network.clone().unwrap_or_else(|| network.name.clone())
        };
        let body = format!(
            "# ShadeNet client configuration. Flags and SHADENET_* variables override these.\n\
             network = {network_value:?}\n\
             identity = {:?}\n\
             proxy_token_file = {:?}\n\
             listen = \"127.0.0.1:8118\"\n",
            identity_path.display().to_string(),
            token_path.display().to_string()
        );
        if let Err(e) = write_private(&config_path, body.as_bytes()) {
            return usage("init", e);
        }
        created.push(config_path.display().to_string());
    }

    let profile = network.public_profile().ok();
    let mut summary = serde_json::json!({
        "network": network.name,
        "dir": dir.display().to_string(),
        "identity": identity_path.display().to_string(),
        "leaf": leaf,
        "proxyTokenFile": token_path.display().to_string(),
        "config": config_path.display().to_string(),
        "created": created,
    });
    if let Some(idc) = &identity_commitment {
        summary["identityCommitment"] = idc.clone().into();
    }
    if let Some(tier) = tier {
        summary["tier"] = tier.into();
    }
    if let Some(link) = &stake_link {
        summary["stakeLink"] = link.clone().into();
    }
    if let Some(profile) = &profile {
        summary["staking"] = serde_json::json!({
            "contract": profile.contract,
            "chainId": profile.chain_id,
            "tiers": profile.tiers.iter().map(|t| serde_json::json!({"limit": t.limit, "bondWei": t.bond_wei})).collect::<Vec<_>>(),
            "unbondingSeconds": profile.unbonding_seconds,
        });
    }
    let mut state = "unknown".to_string();
    if !args.offline {
        let config_ctx = Context {
            network: ctx.network.clone(),
            file: config_file::load(Some(&config_path)).unwrap_or_default(),
        };
        let net = crate::NetArgs {
            identity: Some(identity_path.clone()),
            ..crate::NetArgs::default()
        };
        if let (Ok(client), Ok(rt)) = (build_client(&net, &config_ctx, true), runtime()) {
            let deadline = std::time::Instant::now() + Duration::from_secs(args.wait_timeout);
            let status = rt.block_on(async {
                loop {
                    let status = client.status().await;
                    if !args.wait
                        || status.state == "ready"
                        || std::time::Instant::now() >= deadline
                    {
                        return status;
                    }
                    eprintln!("init: {} ... checking again in 30s", status.state);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
            state = status.state.clone();
            summary["status"] = serde_json::to_value(&status).unwrap_or_default();
        }
    }
    summary["state"] = state.clone().into();
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
        return if state == "ready" || args.offline {
            ExitCode::SUCCESS
        } else {
            state_exit(&state)
        };
    }
    let bin = invoked_name();
    println!("ShadeNet is set up in {}", dir.display());
    for path in &created {
        println!("  created {path}");
    }
    // The stake page takes the identity commitment. Staking the leaf instead locks a bond
    // nobody can withdraw, and the page cannot tell the two apart, so when the commitment is
    // known the leaf is shortened the way `status` shows it: impossible to paste whole.
    if let Some(idc) = &identity_commitment {
        println!("  identity commitment {idc}");
        println!(
            "  leaf {}.., derived from it; not for staking",
            &leaf[..leaf.len().min(12)]
        );
    } else {
        println!("  leaf {leaf}");
    }
    println!();
    match state.as_str() {
        "ready" => println!("This identity is admitted. Start the proxy:"),
        _ => {
            if let Some(profile) = &profile {
                let tier_info = tier
                    .and_then(|committed| profile.tiers.iter().find(|t| t.limit == committed))
                    .or_else(|| {
                        profile
                            .tiers
                            .iter()
                            .find(|t| t.limit == profile.default_limit)
                    })
                    .or(profile.tiers.first());
                if let Some(tier_info) = tier_info {
                    // Human units (dogfood #239): the page says "0.01 ETH, tier 1"; so do we.
                    let unit = if network.deployment.session_tickets {
                        "session"
                    } else {
                        "tunnel"
                    };
                    // The contract takes the identity commitment and derives the leaf itself;
                    // registering a leaf value where a commitment is expected burns the bond
                    // (task 66), so this says "register this identity commitment", never "leaf".
                    println!(
                        "Next, register this identity commitment ({} {}{} per {}s epoch) for a bond of {} on {}:",
                        tier_info.limit,
                        unit,
                        if tier_info.limit == 1 { "" } else { "s" },
                        profile.rate_policy.epoch_seconds,
                        format_bond(&tier_info.bond_wei, profile.chain_id),
                        chain_name(profile.chain_id, &network.name),
                    );
                }
                println!("  {bin} register-member --identity {} --key-file <owner-only file with a funded key>", identity_path.display());
                if let Some(link) = &stake_link {
                    println!("Or open the stake page in a browser (the link carries your identity commitment; the secret never leaves this machine):");
                    println!("  {link}");
                }
                println!("Then wait for finality (about 13 minutes on Sepolia):");
                println!("  {bin} status --wait");
            }
            println!("Then start the proxy:");
        }
    }
    println!("  {bin} proxy");
    println!("and run your agent through it (keep your model API off ShadeNet):");
    println!("  {bin} run --no-proxy api.openai.com -- your-agent");
    println!("To run the proxy as a service: {bin} init --service systemd (or launchd)");
    ExitCode::SUCCESS
}

fn service_unit(kind: ServiceKind, config: &Path) -> String {
    let bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "shadenet".into());
    match kind {
        ServiceKind::Systemd => format!(
            "# ~/.config/systemd/user/shadenet-proxy.service\n\
             # systemctl --user daemon-reload && systemctl --user enable --now shadenet-proxy\n\
             [Unit]\n\
             Description=ShadeNet proxy\n\
             After=network-online.target\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             ExecStart={bin} proxy --config {config}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             NoNewPrivileges=yes\n\
             Environment=SHADENET_LOG_FORMAT=json\n\n\
             [Install]\n\
             WantedBy=default.target\n",
            config = config.display()
        ),
        ServiceKind::Launchd => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!-- ~/Library/LaunchAgents/xyz.shadenet.proxy.plist; launchctl load -w <this file> -->\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n\
             \t<key>Label</key><string>xyz.shadenet.proxy</string>\n\
             \t<key>ProgramArguments</key>\n\t<array>\n\
             \t\t<string>{bin}</string>\n\t\t<string>proxy</string>\n\t\t<string>--config</string>\n\t\t<string>{config}</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key><true/>\n\
             \t<key>KeepAlive</key><true/>\n\
             \t<key>StandardErrorPath</key><string>/tmp/shadenet-proxy.log</string>\n\
             </dict>\n</plist>\n",
            config = config.display()
        ),
    }
}

// ------------------------------------------------------------------ doctor

use shadenet::doctor::{Check, Level};

#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_path: &Path) -> Option<u32> {
    None
}

fn print_check(c: &Check) {
    println!("{:<4}  {:<22} {}", c.level.as_str(), c.name, c.detail);
    if c.level != Level::Ok {
        if let Some(cause) = &c.cause {
            println!("      cause: {cause}");
        }
        if let Some(fix) = &c.fix {
            println!("      fix:   {fix}");
        }
    }
}

/// Records the doctor looks for the identity in besides the active one: the bundled network,
/// `--records`, and the repo-style `network/*/deployment.json` next to the current directory.
fn other_records(args: &DoctorArgs) -> Vec<shadenet::Network> {
    let mut out = Vec::new();
    if let Ok(bundled) = shadenet::Network::bundled(shadenet::profile::DEFAULT_NETWORK) {
        out.push(bundled);
    }
    let mut paths = args.records.clone();
    if let Ok(entries) = std::fs::read_dir("network") {
        for entry in entries.flatten() {
            let candidate = entry.path().join("deployment.json");
            if candidate.is_file() {
                paths.push(candidate);
            }
        }
    }
    for path in paths {
        match shadenet::Network::from_file(&path) {
            Ok(network) if !out.iter().any(|n| n.name == network.name) => out.push(network),
            Ok(_) => {}
            Err(error) => tracing::warn!(path = %path.display(), %error, "record skipped"),
        }
    }
    out
}

fn doctor(args: DoctorArgs, ctx: &Context) -> ExitCode {
    let mut checks: Vec<Check> = Vec::new();
    let network = ctx.network();
    let config = args.net.to_config(ctx, false);
    let rln_identifier = config
        .as_ref()
        .ok()
        .and_then(|c| c.rln_identifier.parse::<u64>().ok())
        .unwrap_or(1);

    if !args.rpc {
        match &network {
            Ok(network) => checks.push(shadenet::doctor::check_version(
                crate::VERSION,
                (crate::COMMIT != "unknown").then_some(crate::COMMIT),
                network,
            )),
            Err(e) => checks.push(Check::fail(
                "network",
                e.clone(),
                "the deployment record could not be loaded",
                "pass --network sepolia or the path to a deployment.json",
            )),
        }
        checks.push(match &ctx.file.path {
            Some(path) => Check::ok("config", path.display().to_string()),
            None => Check::warn(
                "config",
                "no config file",
                "nothing persists between commands, so every flag must be repeated",
                "run `shadenet init` once; it writes ~/.config/shadenet/config.toml",
            ),
        });
        let legacy: Vec<String> = std::env::vars()
            .map(|(k, _)| k)
            .filter(|k| k.starts_with(shadenet::env::LEGACY_PREFIX))
            .filter(|k| {
                std::env::var(format!(
                    "{}{}",
                    shadenet::env::PREFIX,
                    &k[shadenet::env::LEGACY_PREFIX.len()..]
                ))
                .is_err()
            })
            .collect();
        if !legacy.is_empty() {
            checks.push(Check::warn(
                "environment",
                legacy.join(", "),
                "deprecated SHADE_TREE_* names are set; they still work this release but are read after SHADENET_*",
                "rename them to SHADENET_*",
            ));
        }
        if let Ok(network) = &network {
            checks.push(Check::ok(
                "network",
                format!(
                    "{} ({} Elder Tree{}, first {})",
                    network.name,
                    network.deployment.elders.len(),
                    if network.deployment.elders.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    &network.deployment.elder_onion[..network.deployment.elder_onion.len().min(12)]
                ),
            ));
            if network.deployment.default_path.as_deref() == Some("staked") {
                checks.push(match network.public_profile() {
                    Ok(p) => Check::ok(
                        "staking profile",
                        format!(
                            "contract {} on chain {}, {}, {} RPC endpoint(s)",
                            p.contract,
                            p.chain_id,
                            if p.tiers.len() == 1 {
                                format!("{} {} per epoch", p.default_limit, budget_unit(network))
                            } else {
                                format!(
                                    "{} tiers, default {} {} per epoch",
                                    p.tiers.len(),
                                    p.default_limit,
                                    budget_unit(network)
                                )
                            },
                            p.rpc_urls.len()
                        ),
                    ),
                    Err(e) => Check::fail(
                        "staking profile",
                        e.to_string(),
                        "the record's staked admission root is incomplete",
                        "use the record the release ships (`--network sepolia`)",
                    ),
                });
            }
        }
    }

    // Identity file.
    let identity_path = ctx.identity_path(args.net.identity.as_ref()).ok().flatten();
    let mut leaf = None;
    if !args.rpc {
        match &identity_path {
            None => checks.push(Check::fail(
                "identity",
                "none configured",
                "no identity file is configured, so there is nothing to prove with",
                "run `shadenet init`, or pass --identity <file> to the identity a sponsor gave you",
            )),
            Some(path) => {
                let parsed = std::fs::read_to_string(path)
                    .map_err(|e| format!("read {}: {e}", path.display()))
                    .and_then(|raw| {
                        serde_json::from_str::<serde_json::Value>(&raw)
                            .map_err(|e| format!("{}: {e}", path.display()))
                    });
                match parsed {
                    Ok(value) => {
                        leaf = value["leaf"].as_str().map(str::to_string);
                        let secret = value["identitySecret"].is_string();
                        let encrypted = value["encrypted"].is_object();
                        checks.push(match (&leaf, secret || encrypted) {
                            (Some(l), true) => Check::ok(
                                "identity",
                                format!(
                                    "{} (leaf {}.., {} {} per epoch, {})",
                                    path.display(),
                                    &l[..l.len().min(12)],
                                    value["limit"],
                                    network.as_ref().map(budget_unit).unwrap_or("sessions"),
                                    if encrypted {
                                        "passphrase-protected"
                                    } else {
                                        "no passphrase; `shadenet identity-lock` adds one"
                                    }
                                ),
                            ),
                            _ => Check::fail(
                                "identity",
                                format!("{} is missing identitySecret or leaf", path.display()),
                                "the file is not an identity file (or is a public commitment only)",
                                "use the identity.json that `shadenet init` or the Get access page wrote; a sponsor gets only the commitment, never this file",
                            ),
                        });
                        if let Some(mode) = mode_of(path) {
                            if mode & 0o077 != 0 {
                                checks.push(Check::fail(
                                    "identity permissions",
                                    format!("{} is mode {mode:o}", path.display()),
                                    "the identity secret is readable by other users on this machine",
                                    format!("chmod 600 {}", path.display()),
                                ));
                            }
                        }
                    }
                    Err(e) => checks.push(Check::fail(
                        "identity",
                        e,
                        "the identity file could not be read or parsed",
                        "check the path in config.toml (`shadenet doctor` prints it) or re-create it with `shadenet init`",
                    )),
                }
            }
        }
        // Proxy token.
        checks.push(match proxy_token(None, ctx).and_then(|t| {
            shadenet::proxy::validate_token(&t).map_err(|e| e.to_string())
        }) {
            Ok(()) => Check::ok("proxy token", "set and well-formed"),
            Err(e) => Check::fail(
                "proxy token",
                e,
                "the local proxy refuses every CONNECT without a valid token, so agents get 407",
                "run `shadenet init` to mint one, or set SHADENET_PROXY_TOKEN_FILE",
            ),
        });
        // Slot state.
        if let Some(leaf) = &leaf {
            checks.push(
                match shadenet::slot::default_path(leaf)
                    .map_err(|e| e.to_string())
                    .and_then(|path| {
                        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
                        std::fs::create_dir_all(&parent)
                            .map_err(|e| format!("{}: {e}", parent.display()))?;
                        let probe = parent.join(format!(".doctor-{}", std::process::id()));
                        std::fs::write(&probe, b"")
                            .map_err(|e| format!("{} is not writable: {e}", parent.display()))?;
                        let _ = std::fs::remove_file(probe);
                        Ok(path)
                    }) {
                    Ok(path) => Check::ok(
                        "slot state",
                        format!("{} (shared with the JavaScript client; never delete mid-epoch)", path.display()),
                    ),
                    Err(e) => Check::fail(
                        "slot state",
                        e,
                        "the per-epoch slot file cannot be written, so the client refuses to spend (reusing a slot would get the identity slashed)",
                        "make the directory writable by this user, or set SHADENET_SLOTS_DIR to one that is",
                    ),
                },
            );
        }
        checks.push(match shadenet_rln::artifacts::verify_embedded() {
            Ok(c) => Check::ok(
                "zk artifacts",
                format!("{} (trust {}, provenance {})", c.artifact_id, c.trust, c.provenance),
            ),
            Err(e) => Check::fail(
                "zk artifacts",
                e.to_string(),
                "the embedded circuit artifacts do not match their lock, so no node will accept a proof from this binary",
                "reinstall the release (`curl … install.sh | sh`); a modified binary is never accepted",
            ),
        });
        // Directories Arti and the cache use.
        if let Ok(config) = &config {
            checks.extend(shadenet::doctor::check_state_dirs(
                config.tor_directories.as_ref(),
                config.cache_dir.as_deref(),
            ));
        }
    }

    // Network checks.
    let mut rpc_verdicts = Vec::new();
    let mut elder_verdicts = Vec::new();
    let mut code_state = None;
    let mut node_roots: Option<(Vec<String>, Option<u64>, Option<u64>)> = None;
    if !args.offline {
        if let (Ok(network), Ok(config)) = (&network, &config) {
            if let Ok(profile) = network.public_profile() {
                let overrides: Option<Vec<String>> = config.rpc_url.as_deref().map(|list| {
                    list.split(',')
                        .map(str::trim)
                        .filter(|u| !u.is_empty())
                        .map(str::to_string)
                        .collect()
                });
                let deploy_tx = network
                    .deployment
                    .staked
                    .as_ref()
                    .and_then(|s| s.deploy_tx.clone());
                // `--rpc` rates the endpoints for operators (deploys and preflights read
                // receipts); the default run is a client checking that it can prove.
                let audience = if args.rpc {
                    shadenet::doctor::RpcAudience::Operator
                } else {
                    shadenet::doctor::RpcAudience::Client
                };
                let (rpc_checks, verdicts) = shadenet::doctor::check_rpcs(
                    &profile,
                    deploy_tx.as_deref(),
                    overrides.as_deref(),
                    rln_identifier,
                    audience,
                );
                checks.extend(rpc_checks);
                rpc_verdicts = verdicts;
            }
        }
        if !args.rpc {
            match build_client(&args.net, ctx, false) {
                Ok(client) => match runtime() {
                    Ok(rt) => {
                        let status = rt.block_on(client.status());
                        checks.push(if status.tor_ready {
                            Check::ok("tor", "embedded Tor bootstrapped")
                        } else {
                            Check::warn(
                                "tor",
                                "not bootstrapped",
                                "embedded Tor (Arti) has not reached the Tor network yet",
                                "wait a few seconds and retry; persistent failure means Tor is blocked from this machine",
                            )
                        });
                        // Each Elder on its own: reachability, directory age, incidents.
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or_default();
                        let our_set = network.as_ref().ok().and_then(|n| {
                            n.deployment
                                .staked
                                .as_ref()
                                .map(|s| s.contract.to_ascii_lowercase())
                        });
                        if let Ok(network) = &network {
                            for elder in &network.deployment.elders {
                                let directory =
                                    rt.block_on(client.fetch_elder(&elder.onion, "/directory"));
                                let incidents = directory.is_ok().then(|| {
                                    rt.block_on(client.fetch_elder(&elder.onion, "/incidents"))
                                });
                                let (check, verdict) = shadenet::doctor::judge_elder_for_set(
                                    &elder.onion,
                                    &elder.canopy_signer,
                                    directory,
                                    incidents,
                                    now,
                                    our_set.as_deref(),
                                );
                                checks.push(check);
                                elder_verdicts.push(verdict);
                            }
                        }
                        checks.push(match status.canopy.issued {
                            Some(_) => Check::ok(
                                "canopy",
                                format!(
                                    "{} node(s), {} eligible{}",
                                    status.canopy.nodes,
                                    status.canopy.eligible,
                                    if status.canopy.from_last_known_good { " (last-known-good copy)" } else { "" }
                                ),
                            ),
                            None => Check::fail(
                                "canopy",
                                status.canopy.error.clone().unwrap_or_else(|| "unavailable".into()),
                                "no Elder Tree served a verifiable canopy and no last-known-good copy exists",
                                "check the elder lines above and the `tor` line; nothing else can work until a canopy verifies",
                            ),
                        });
                        // Admission set (dogfood #234): do the listed nodes read the set this
                        // record names? Judged from the freshest Elder that answered.
                        if let Some(ours) = our_set.as_deref() {
                            let best = elder_verdicts
                                .iter()
                                .filter(|v| v.reachable && v.gateways.is_some())
                                .max_by_key(|v| v.issued.unwrap_or_default());
                            if let Some(v) = best {
                                let nodes = v.gateways.unwrap_or_default();
                                let sets = &v.sets;
                                checks.push(if sets.advertising == 0 {
                                    Check::ok(
                                        "admission set",
                                        format!("{nodes} node(s), none advertises the set it reads (pre-0.7.1 fleet); {ours} assumed"),
                                    )
                                } else if sets.admitting > 0 {
                                    Check::ok(
                                        "admission set",
                                        format!("{} of {} advertising node(s) read {ours}", sets.admitting, sets.advertising),
                                    )
                                } else {
                                    Check::fail(
                                        "admission set",
                                        format!("0 of {} advertising node(s) read {ours}; they read {}", sets.advertising, sets.advertised.join(", ")),
                                        "every proof would be refused `wrong-group-root`: the nodes serve another network's set (the fleet moved, or this binary carries an older record)",
                                        "run against the record these nodes serve (`--network <path>` or update the binary), or stake in the set they read",
                                    )
                                });
                            }
                        }
                        if let Some(last) = &status.last_error {
                            if last["reason"].as_str() == Some("gate:wrong-group-root") {
                                // The node told us which roots it accepts; keep them for the root check.
                                node_roots = Some((
                                    last["ack"]["roots"]
                                        .as_array()
                                        .map(|a| {
                                            a.iter()
                                                .filter_map(|v| v.as_str().map(str::to_string))
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                    last["ack"]["rootBlock"].as_u64(),
                                    last["ack"]["rootLeaves"].as_u64(),
                                ));
                            }
                        }
                        for problem in &status.problems {
                            if problem.kind == "state" || problem.kind == "last_error" {
                                checks.push(Check::warn(
                                    format!("{} {}", problem.kind, problem.code),
                                    status.state.clone(),
                                    problem.cause.clone(),
                                    problem.fix.clone(),
                                ));
                            }
                        }
                        if status.state == "ready" {
                            checks.push(Check::ok(
                                "admission",
                                format!(
                                    "ready in {} ({} of {} {} left this epoch)",
                                    status.admission_set.clone().unwrap_or_default(),
                                    status.slots_left.unwrap_or_default(),
                                    status.tier.unwrap_or_default(),
                                    network.as_ref().map(budget_unit).unwrap_or("sessions")
                                ),
                            ));
                        }
                        code_state = Some(status.state.clone());
                        // Not admitted here: look for the leaf in the other records.
                        if status.state == "not_admitted" {
                            if let (Some(leaf), Ok(network)) = (&leaf, &network) {
                                checks.extend(shadenet::doctor::check_identity_elsewhere(
                                    leaf,
                                    network,
                                    &other_records(&args),
                                    rln_identifier,
                                ));
                            }
                        }
                    }
                    Err(e) => checks.push(Check::fail(
                        "runtime",
                        e,
                        "the async runtime could not start",
                        "report it with `shadenet doctor --json`",
                    )),
                },
                Err(e) => checks.push(Check::fail(
                    "client",
                    e,
                    "the client could not be built from this configuration",
                    "fix the config lines above first",
                )),
            }
        }
    }

    // Root comparison: our replay against what a node advertised in its last refusal.
    if let Some((roots, block, leaves)) = &node_roots {
        let ours: Option<&shadenet::doctor::RpcVerdict> =
            rpc_verdicts.iter().find(|v| v.members == "complete");
        let where_ = match (block, leaves) {
            (Some(b), Some(n)) => format!(" ({n} leaves at block {b})"),
            (Some(b), None) => format!(" (block {b})"),
            _ => String::new(),
        };
        checks.push(match ours {
            Some(v) if roots.iter().any(|r| Some(r) == v.root.as_ref()) => Check::ok(
                "root",
                format!("our replay root matches a root the node accepts{where_}; the last refusal was transient"),
            ),
            Some(v) => Check::fail(
                "root",
                format!(
                    "ours {}… ({} live / {} slots) vs node's {} root(s){where_}",
                    v.root.as_deref().unwrap_or("?").chars().take(12).collect::<String>(),
                    v.live.unwrap_or_default(),
                    v.slots.unwrap_or_default(),
                    roots.len()
                ),
                "the member set this client replays is not one the node accepts: if the node's leaf count is higher, our RPC is behind or dropped logs; if ours is higher, the node's root source is stale",
                "ours behind: use another RPC (see the rpc lines). Node behind: wait one root refresh (60 s) or report the node to the operator with this output",
            ),
            None => Check::fail(
                "root",
                format!("the node accepts {} root(s){where_}, and no RPC gave us a complete member set", roots.len()),
                "we cannot build the tree the node expects because every RPC failed the replay",
                "fix the rpc lines above first",
            ),
        });
    }

    let failed = checks.iter().any(|c| c.level == Level::Fail);
    if args.json {
        let value = serde_json::json!({
            "ok": !failed,
            "state": code_state,
            "checks": checks,
            "rpc": rpc_verdicts,
            "elders": elder_verdicts,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        for c in &checks {
            print_check(c);
        }
        if failed {
            println!("\nfix the first `fail` line, then run `shadenet doctor` again");
        }
    }
    if failed {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

/// A bond in wei, printed the way the Get access page prints it: `0.01 ETH` (trailing zeros
/// trimmed, at most 18 decimals), falling back to the raw figure when the string is not an
/// integer. Sepolia's ether is named so nobody reads it as mainnet ETH.
fn format_bond(wei: &str, chain_id: u64) -> String {
    let digits = wei.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return format!("{wei} wei");
    }
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let (whole, frac) = if digits.len() > 18 {
        digits.split_at(digits.len() - 18)
    } else {
        ("0", digits)
    };
    let frac = format!("{frac:0>18}");
    let frac = frac.trim_end_matches('0');
    let amount = if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    };
    let unit = match chain_id {
        11155111 => "Sepolia ETH",
        1 => "ETH",
        _ => "ETH",
    };
    format!("{amount} {unit}")
}

/// The network a chain id belongs to, for prose; the record's own name wins when it says more.
fn chain_name(chain_id: u64, record_name: &str) -> String {
    let chain = match chain_id {
        1 => "Ethereum mainnet".to_string(),
        11155111 => "Sepolia".to_string(),
        17000 => "Holesky".to_string(),
        other => format!("chain {other}"),
    };
    if record_name.is_empty() || record_name.eq_ignore_ascii_case(&chain) {
        chain
    } else {
        format!("{chain} (record {record_name})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bonds_print_in_ether_not_wei() {
        assert_eq!(
            format_bond("10000000000000000", 11155111),
            "0.01 Sepolia ETH"
        );
        assert_eq!(
            format_bond("80000000000000000", 11155111),
            "0.08 Sepolia ETH"
        );
        assert_eq!(
            format_bond("1000000000000000", 11155111),
            "0.001 Sepolia ETH"
        );
        assert_eq!(format_bond("1000000000000000000", 1), "1 ETH");
        assert_eq!(format_bond("1500000000000000000000", 1), "1500 ETH");
        assert_eq!(format_bond("1", 1), "0.000000000000000001 ETH");
        assert_eq!(format_bond("0", 1), "0 ETH");
        assert_eq!(format_bond("not-a-number", 1), "not-a-number wei");
    }

    #[test]
    fn chain_names_read_as_prose() {
        assert_eq!(chain_name(11155111, "sepolia"), "Sepolia");
        assert_eq!(
            chain_name(11155111, "sepolia-staging"),
            "Sepolia (record sepolia-staging)"
        );
        assert_eq!(chain_name(1, ""), "Ethereum mainnet");
        assert_eq!(chain_name(424242, "x"), "chain 424242 (record x)");
    }

    #[test]
    fn headers_parse_strictly() {
        assert_eq!(
            parse_header("Accept: text/html").unwrap(),
            ("Accept".into(), "text/html".into())
        );
        assert!(parse_header("no colon").is_err());
        assert!(parse_header("Bad Name: x").is_err());
    }

    #[test]
    fn service_units_run_the_proxy_with_the_config() {
        let unit = service_unit(
            ServiceKind::Systemd,
            Path::new("/home/u/.config/shadenet/config.toml"),
        );
        assert!(unit.contains("proxy --config /home/u/.config/shadenet/config.toml"));
        assert!(unit.contains("Restart=on-failure"));
        let plist = service_unit(ServiceKind::Launchd, Path::new("/c.toml"));
        assert!(plist.contains("<string>proxy</string>"));
    }

    #[test]
    fn private_files_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("shadenet-cli-private-{}", std::process::id()));
        let path = dir.join("nested").join("token");
        write_private(&path, b"x").unwrap();
        if let Some(mode) = mode_of(&path) {
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
