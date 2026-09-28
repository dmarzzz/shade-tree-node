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

// ------------------------------------------------------------------ status

fn state_exit(state: &str) -> ExitCode {
    match state {
        "ready" => ExitCode::SUCCESS,
        "budget_exhausted" => ExitCode::from(4),
        "degraded" => ExitCode::from(3),
        _ => ExitCode::from(EXIT_USAGE),
    }
}

fn print_status(status: &shadenet::Status) {
    println!("state: {}", status.state);
    println!("network: {} (shadenet {})", status.network, status.version);
    if let Some(leaf) = &status.leaf {
        println!("leaf: {leaf} (tier {})", status.tier.unwrap_or_default());
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
        (Some(used), Some(left)) => println!(
            "epoch: {} ({}s window, resets in {}s); tunnels used {used}, left {left}",
            status.epoch, status.epoch_seconds, status.epoch_resets_in_seconds
        ),
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
    if let Some(error) = &status.last_error {
        println!(
            "last error: {} ({})",
            error["message"].as_str().unwrap_or(""),
            error["code"].as_str().unwrap_or("")
        );
    }
}

fn status(args: StatusArgs, ctx: &Context) -> ExitCode {
    let client = match build_client(&args.net, ctx, false) {
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
    let client = match build_client(&args.net, ctx, true) {
        Ok(client) => Arc::new(client),
        Err(message) => return usage("proxy", message),
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
    let client = match build_client(&args.net, ctx, true) {
        Ok(client) => client,
        Err(message) => return usage("fetch", message),
    };
    let rt = match runtime() {
        Ok(rt) => rt,
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
    match rt.block_on(client.fetch(request)) {
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
    let leaf = if identity_path.exists() {
        match std::fs::read_to_string(&identity_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|v| v["leaf"].as_str().map(str::to_string))
        {
            Some(leaf) => leaf,
            None => {
                return usage(
                    "init",
                    format!(
                        "{} exists but is not an identity file",
                        identity_path.display()
                    ),
                )
            }
        }
    } else {
        let limit = match args
            .limit
            .map(Ok)
            .unwrap_or_else(|| network.staked_default_limit())
        {
            Ok(limit) => limit,
            Err(e) => return usage("init", e),
        };
        match crate::enroll::create_identity(&identity_path, limit) {
            Ok(leaf) => {
                created.push(identity_path.display().to_string());
                if args.passphrase {
                    if let Err(e) = lock_identity(&identity_path) {
                        return usage("init", e);
                    }
                }
                leaf
            }
            Err(e) => return usage("init", e),
        }
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
    println!("  leaf {leaf}");
    println!();
    match state.as_str() {
        "ready" => println!("This identity is admitted. Start the proxy:"),
        _ => {
            if let Some(profile) = &profile {
                let tier = profile
                    .tiers
                    .iter()
                    .find(|t| t.limit == profile.default_limit)
                    .or(profile.tiers.first());
                if let Some(tier) = tier {
                    println!(
                        "Next, stake this leaf ({} tunnel(s) per {}s epoch for a bond of {} wei on chain {}):",
                        tier.limit, profile.rate_policy.epoch_seconds, tier.bond_wei, profile.chain_id
                    );
                }
                println!("  {bin} register-member --identity {} --key-file <owner-only file with a funded key>", identity_path.display());
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

struct Check {
    name: &'static str,
    level: &'static str,
    detail: String,
}

fn check(name: &'static str, result: Result<String, String>) -> Check {
    match result {
        Ok(detail) => Check {
            name,
            level: "ok",
            detail,
        },
        Err(detail) => Check {
            name,
            level: "fail",
            detail,
        },
    }
}

fn warn(name: &'static str, detail: String) -> Check {
    Check {
        name,
        level: "warn",
        detail,
    }
}

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

fn doctor(args: DoctorArgs, ctx: &Context) -> ExitCode {
    let mut checks = Vec::new();
    checks.push(Check {
        name: "version",
        level: "ok",
        detail: format!(
            "shadenet {} (invoked as {})",
            crate::VERSION,
            invoked_name()
        ),
    });
    checks.push(match &ctx.file.path {
        Some(path) => Check {
            name: "config",
            level: "ok",
            detail: path.display().to_string(),
        },
        None => warn(
            "config",
            "no config file; run `shadenet init` or pass flags".into(),
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
        checks.push(warn(
            "environment",
            format!(
                "deprecated names in use (rename to SHADENET_*): {}",
                legacy.join(", ")
            ),
        ));
    }
    let network = ctx.network();
    checks.push(check(
        "network",
        network
            .as_ref()
            .map(|n| format!("{} (Elder Tree {})", n.name, n.deployment.elder_onion))
            .map_err(Clone::clone),
    ));
    if let Ok(network) = &network {
        if network.deployment.default_path.as_deref() == Some("staked") {
            checks.push(check(
                "staking profile",
                network
                    .public_profile()
                    .map(|p| {
                        format!(
                            "contract {} on chain {}, {} tier(s), default tier {}",
                            p.contract,
                            p.chain_id,
                            p.tiers.len(),
                            p.default_limit
                        )
                    })
                    .map_err(|e| e.to_string()),
            ));
        }
    }
    // Identity.
    let identity_path = ctx.identity_path(args.net.identity.as_ref()).ok().flatten();
    let mut leaf = None;
    match &identity_path {
        None => checks.push(Check {
            name: "identity",
            level: "fail",
            detail: "none configured; run `shadenet init`".into(),
        }),
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
                    checks.push(check(
                        "identity",
                        match (
                            &leaf,
                            value["identitySecret"].is_string(),
                            value["encrypted"].is_object(),
                        ) {
                            (Some(l), secret, encrypted) if secret || encrypted => Ok(format!(
                                "{} (leaf {}.., tier {}, {})",
                                path.display(),
                                &l[..l.len().min(12)],
                                value["limit"],
                                if encrypted {
                                    "passphrase-protected"
                                } else {
                                    "no passphrase; `shadenet identity-lock` adds one"
                                }
                            )),
                            _ => Err(format!(
                                "{} is missing identitySecret or leaf",
                                path.display()
                            )),
                        },
                    ));
                    if let Some(mode) = mode_of(path) {
                        if mode & 0o077 != 0 {
                            checks.push(Check {
                                name: "identity permissions",
                                level: "fail",
                                detail: format!(
                                    "{} is mode {mode:o}; run chmod 600",
                                    path.display()
                                ),
                            });
                        }
                    }
                }
                Err(e) => checks.push(Check {
                    name: "identity",
                    level: "fail",
                    detail: e,
                }),
            }
        }
    }
    // Proxy token.
    checks.push(check(
        "proxy token",
        proxy_token(None, ctx).and_then(|t| {
            shadenet::proxy::validate_token(&t)
                .map(|()| "set and well-formed".to_string())
                .map_err(|e| e.to_string())
        }),
    ));
    // Slot state.
    if let Some(leaf) = &leaf {
        checks.push(check(
            "slot state",
            shadenet::slot::default_path(leaf)
                .map_err(|e| e.to_string())
                .and_then(|path| {
                    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
                    std::fs::create_dir_all(&parent)
                        .map_err(|e| format!("{}: {e}", parent.display()))?;
                    let probe = parent.join(format!(".doctor-{}", std::process::id()));
                    std::fs::write(&probe, b"")
                        .map_err(|e| format!("{} is not writable: {e}", parent.display()))?;
                    let _ = std::fs::remove_file(probe);
                    Ok(format!(
                        "{} (shared with the JavaScript client; never delete mid-epoch)",
                        path.display()
                    ))
                }),
        ));
    }
    checks.push(check(
        "zk artifacts",
        shadenet_rln::artifacts::verify_embedded()
            .map(|c| {
                format!(
                    "{} (trust {}, provenance {})",
                    c.artifact_id, c.trust, c.provenance
                )
            })
            .map_err(|e| e.to_string()),
    ));
    let mut code_state = None;
    if !args.offline {
        match build_client(&args.net, ctx, false) {
            Ok(client) => match runtime() {
                Ok(rt) => {
                    let status = rt.block_on(client.status());
                    checks.push(check(
                        "canopy over Tor",
                        match status.canopy.issued {
                            Some(_) => Ok(format!(
                                "{} node(s), {} eligible",
                                status.canopy.nodes, status.canopy.eligible
                            )),
                            None => Err(status
                                .canopy
                                .error
                                .clone()
                                .unwrap_or_else(|| "unavailable".into())),
                        },
                    ));
                    if status.admitted.is_some() {
                        let level = if status.admitted == Some(true) {
                            "ok"
                        } else {
                            "warn"
                        };
                        checks.push(Check {
                            name: "admission",
                            level,
                            detail: format!(
                                "{} ({})",
                                status.state,
                                status.admission_set.clone().unwrap_or_default()
                            ),
                        });
                    }
                    code_state = Some(status.state);
                }
                Err(e) => checks.push(Check {
                    name: "runtime",
                    level: "fail",
                    detail: e,
                }),
            },
            Err(e) => checks.push(Check {
                name: "client",
                level: "fail",
                detail: e,
            }),
        }
    }
    let failed = checks.iter().any(|c| c.level == "fail");
    if args.json {
        let value = serde_json::json!({
            "ok": !failed,
            "state": code_state,
            "checks": checks.iter().map(|c| serde_json::json!({"name": c.name, "level": c.level, "detail": c.detail})).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        for c in &checks {
            println!("{:<4}  {:<20} {}", c.level, c.name, c.detail);
        }
    }
    if failed {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
