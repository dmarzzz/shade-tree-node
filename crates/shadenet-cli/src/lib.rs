//! `shadenet`: the ShadeNet command line, a thin shell over the `shadenet` SDK.
//!
//! The binary is also installed as `shade-tree` for one minor release. Both names behave the same.
//!
//! Exit codes (stable): 0 ok, 1 a node refused, 2 usage/config/not admitted, 3 local or transport
//! failure (fails closed), 4 epoch budget exhausted.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub mod config_file;
#[cfg(feature = "live")]
mod enroll;
#[cfg(feature = "live")]
mod live;
#[cfg(feature = "live")]
mod mcp;
#[cfg(feature = "live")]
mod member;
mod net;
mod offline;
#[cfg(feature = "live")]
mod register;
mod run;

#[cfg(feature = "live")]
pub(crate) use live::compat::*;
pub(crate) use net::NetArgs;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for usage and configuration errors.
pub(crate) const EXIT_USAGE: u8 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "shadenet",
    version,
    about = "ShadeNet: proof-gated anonymous egress for agents (research preview)",
    long_about = "ShadeNet: proof-gated anonymous egress for agents (research preview).\n\n\
        A local proxy proves RLN membership in zero knowledge and a Shade Tree node, a Tor onion \
        service, opens the connection to the destination. Start with `shadenet init`.\n\n\
        Exit codes: 0 ok, 1 node refused, 2 usage/config/not admitted, 3 local or transport \
        failure, 4 epoch budget exhausted.",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Network: a bundled name (sepolia) or a path to a deployment.json record [env: SHADENET_NETWORK]
    #[arg(long, global = true, value_name = "NAME|PATH")]
    pub network: Option<String>,
    /// Config file [env: SHADENET_CONFIG] [default: ~/.config/shadenet/config.toml]
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Log level for ShadeNet messages [env: SHADENET_LOG_LEVEL]
    #[arg(long, global = true, value_enum)]
    pub log_level: Option<LogLevel>,
    /// Log format on stderr [env: SHADENET_LOG_FORMAT]
    #[arg(long, global = true, value_enum)]
    pub log_format: Option<LogFormat>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

/// Raw arguments handed to a command with its own parser and `--help`.
#[derive(Args, Debug)]
pub struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    pub args: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Set up this machine: identity, proxy token, config file, then show what is left to do
    Init(InitArgs),
    /// Show admission, budget and canopy state
    Status(StatusArgs),
    /// Check the local setup and report every problem found
    Doctor(DoctorArgs),
    /// Run the local HTTP CONNECT proxy for agents and SearXNG
    Proxy(ProxyArgs),
    /// Run a command with its HTTP(S) traffic routed through the local proxy
    #[command(disable_help_flag = true)]
    Run(Passthrough),
    /// Serve the MCP tools shadenet_fetch, shadenet_status and shadenet_search over stdio
    Mcp(McpArgs),
    /// Fetch one https URL through ShadeNet
    Fetch(FetchArgs),
    /// Open one proof-gated tunnel (debugging and scripts)
    Egress(EgressArgs),
    /// Print a fresh proxy token
    ProxyToken,
    /// Create a new member identity
    #[command(disable_help_flag = true)]
    Enroll(Passthrough),
    /// Derive an identity file from an existing member secret
    Identity(IdentityArgs),
    /// Stake a member leaf on chain
    #[command(disable_help_flag = true)]
    RegisterMember(Passthrough),
    /// Show a staked leaf's on-chain state
    #[command(disable_help_flag = true)]
    MemberStatus(Passthrough),
    /// Leave the staked set and start unbonding
    #[command(disable_help_flag = true)]
    ExitMember(Passthrough),
    /// Reclaim a bond after unbonding
    #[command(disable_help_flag = true)]
    WithdrawMember(Passthrough),
    /// Reconstruct a member set from contract events
    Leaves(LeavesArgs),
    /// Verify a signed canopy file
    VerifyDirectory(offline::VerifyDirectoryArgs),
    /// Fetch and verify a canopy with last-known-good caching (no Tor)
    FetchDirectory(offline::FetchDirectoryArgs),
    /// Show the node selection for a canopy file
    Select(offline::SelectArgs),
    /// Verify a node's signed egress receipt
    VerifyReceipt(offline::VerifyReceiptArgs),
    /// Print the version
    Version,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Directory for identity.json, proxy-token and config.toml [default: ~/.config/shadenet]
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Tier for a new identity [default: the network's default tier]
    #[arg(long)]
    pub limit: Option<u64>,
    /// Skip the network status check
    #[arg(long)]
    pub offline: bool,
    /// After setup, wait until the identity is admitted (poll every 30 s)
    #[arg(long)]
    pub wait: bool,
    /// Give up waiting after this many seconds
    #[arg(long, default_value_t = 3600)]
    pub wait_timeout: u64,
    /// Print a service unit for the proxy instead of the summary
    #[arg(long, value_enum)]
    pub service: Option<ServiceKind>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ServiceKind {
    Systemd,
    Launchd,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    pub net: NetArgs,
    #[arg(long)]
    pub json: bool,
    /// Poll until the state is `ready`
    #[arg(long)]
    pub wait: bool,
    #[arg(long, default_value_t = 3600)]
    pub wait_timeout: u64,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub net: NetArgs,
    /// Skip checks that need the network (RPC, Tor)
    #[arg(long)]
    pub offline: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ProxyArgs {
    #[command(flatten)]
    pub net: NetArgs,
    /// Listen address [env: SHADENET_LISTEN] [default: 127.0.0.1:8118]
    #[arg(long)]
    pub listen: Option<String>,
    /// File holding the proxy token [env: SHADENET_PROXY_TOKEN_FILE]; or set SHADENET_PROXY_TOKEN
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Allow a non-loopback listen address (the token is still required)
    #[arg(long)]
    pub allow_non_loopback: bool,
    /// Most tunnels open at once [env: SHADENET_MAX_TUNNELS] [default: 64]
    #[arg(long)]
    pub max_tunnels: Option<usize>,
    /// Most tunnels being set up at once [env: SHADENET_MAX_SETUPS] [default: 16]
    #[arg(long)]
    pub max_setups: Option<usize>,
    /// Serve one CONNECT, then exit
    #[arg(long)]
    pub once: bool,
}

#[derive(Args, Debug)]
pub struct McpArgs {
    #[command(flatten)]
    pub net: NetArgs,
    /// SearXNG base URL for shadenet_search [env: SHADENET_SEARXNG_URL]
    #[arg(long)]
    pub searxng_url: Option<String>,
}

#[derive(Args, Debug)]
pub struct FetchArgs {
    #[command(flatten)]
    pub net: NetArgs,
    /// https URL
    pub url: String,
    /// HTTP method
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,
    /// Request header, `Name: value` (repeatable)
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    /// Request body
    #[arg(long)]
    pub data: Option<String>,
    /// Truncate the response body after this many bytes
    #[arg(long, default_value_t = shadenet_max_bytes())]
    pub max_bytes: usize,
    /// Print the status line and headers before the body
    #[arg(short = 'i', long)]
    pub include: bool,
    /// Print a JSON object instead of the raw body
    #[arg(long)]
    pub json: bool,
}

const fn shadenet_max_bytes() -> usize {
    2_000_000
}

#[derive(Args, Debug)]
pub struct EgressArgs {
    #[command(flatten)]
    pub net: NetArgs,
    /// host:port bound into the proof
    #[arg(long)]
    pub target: String,
    /// Relay the accepted tunnel to stdin/stdout
    #[arg(long)]
    pub stdio: bool,
    /// Like --stdio, first writing an HTTP 200 Connection Established line (CONNECT helpers)
    #[arg(long)]
    pub proxy_response: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct IdentityArgs {
    /// File holding the member secret (decimal or 0x hex) [or env SHADENET_SECRET]
    #[arg(long, value_name = "PATH")]
    pub secret_file: Option<PathBuf>,
    /// Read the member secret from stdin
    #[arg(long)]
    pub secret_stdin: bool,
    /// Tier [env: SHADENET_LIMIT] [default: the network's default tier]
    #[arg(long)]
    pub limit: Option<u64>,
    /// Write the identity owner-only here instead of stdout
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct LeavesArgs {
    /// Contract [env: SHADENET_PAID_ACCESS_CONTRACT / SHADENET_GROUP_CONTRACT]
    #[arg(long)]
    pub contract: Option<String>,
    /// JSON-RPC URL [env: SHADENET_RPC_URL]
    #[arg(long)]
    pub rpc_url: Option<String>,
    /// First block (decimal or 0x hex) [env: SHADENET_FROM_BLOCK]
    #[arg(long)]
    pub from_block: Option<String>,
    /// latest, safe or finalized
    #[arg(long, default_value = "latest")]
    pub block_tag: String,
    #[arg(long)]
    pub rln_identifier: Option<u64>,
    /// Write members.json here instead of stdout
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Copy each `SHADENET_*` variable to its `SHADE_TREE_*` twin so every reader sees one value, and
/// refuse to start when the two disagree. Runs before any thread exists.
fn normalize_environment() -> Result<(), String> {
    use shadenet::env::{LEGACY_PREFIX, PREFIX};
    let vars: Vec<(String, String)> = std::env::vars().collect();
    for (key, value) in &vars {
        let Some(name) = key.strip_prefix(PREFIX) else {
            continue;
        };
        let legacy = format!("{LEGACY_PREFIX}{name}");
        match std::env::var(&legacy) {
            Ok(existing) if existing != *value => {
                return Err(format!(
                    "{key} and {legacy} are both set to different values; unset one"
                ));
            }
            Ok(_) => {}
            Err(_) => std::env::set_var(&legacy, value),
        }
    }
    Ok(())
}

fn init_logging(level: Option<LogLevel>, format: Option<LogFormat>) {
    use tracing_subscriber::EnvFilter;
    let level = level
        .or_else(|| {
            shadenet::env::var_lenient("LOG_LEVEL").and_then(|v| LogLevel::from_str(&v, true).ok())
        })
        .unwrap_or(LogLevel::Info);
    let format = format
        .or_else(|| {
            shadenet::env::var_lenient("LOG_FORMAT")
                .and_then(|v| LogFormat::from_str(&v, true).ok())
        })
        .unwrap_or(LogFormat::Text);
    let ours = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };
    // Third-party crates stay at warn unless SHADENET_LOG asks for more. Arti's directory manager
    // warns about every malformed document a relay serves and then retries on its own; that is
    // noise for a client, so it is kept at error.
    let filter = shadenet::env::var_lenient("LOG")
        .and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| {
            EnvFilter::new(format!(
                "warn,tor_dirmgr=error,shadenet={ours},shadenet_cli={ours}"
            ))
        });
    use std::io::IsTerminal;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Json => builder.json().with_current_span(false).try_init(),
        LogFormat::Text => builder.with_target(false).try_init(),
    };
}

/// Entry point shared by the `shadenet` and `shade-tree` binaries.
pub fn main() -> ExitCode {
    if let Err(message) = normalize_environment() {
        eprintln!("shadenet: {message}");
        return ExitCode::from(EXIT_USAGE);
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    init_logging(cli.log_level, cli.log_format);
    let file = match config_file::load(cli.config.as_deref()) {
        Ok(file) => file,
        Err(message) => {
            eprintln!("shadenet: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let ctx = net::Context {
        network: cli.network.clone(),
        file,
    };
    dispatch(cli.command, &ctx)
}

#[cfg(not(feature = "live"))]
fn not_live(name: &str) -> ExitCode {
    eprintln!("{name}: requires a build with the `live` feature (the release `-live` binary)");
    ExitCode::from(3)
}

fn dispatch(command: Command, ctx: &net::Context) -> ExitCode {
    match command {
        Command::Version => {
            println!("shadenet {VERSION}");
            ExitCode::SUCCESS
        }
        Command::VerifyDirectory(args) => offline::verify_directory(args),
        Command::FetchDirectory(args) => offline::fetch_directory(args),
        Command::Select(args) => offline::select(args, ctx),
        Command::VerifyReceipt(args) => offline::verify_receipt(args),
        Command::Run(pass) => run::run(
            &pass.args,
            &run::RunDefaults {
                listen: ctx.file.listen.clone(),
                proxy_token_file: ctx.file.proxy_token_file.clone(),
            },
        ),
        #[cfg(feature = "live")]
        command => live::dispatch(command, ctx),
        #[cfg(not(feature = "live"))]
        command => not_live(command_name(&command)),
    }
}

#[cfg(not(feature = "live"))]
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Init(_) => "init",
        Command::Status(_) => "status",
        Command::Doctor(_) => "doctor",
        Command::Proxy(_) => "proxy",
        Command::Mcp(_) => "mcp",
        Command::Fetch(_) => "fetch",
        Command::Egress(_) => "egress",
        Command::ProxyToken => "proxy-token",
        Command::Enroll(_) => "enroll",
        Command::Identity(_) => "identity",
        Command::RegisterMember(_) => "register-member",
        Command::MemberStatus(_) => "member-status",
        Command::ExitMember(_) => "exit-member",
        Command::WithdrawMember(_) => "withdraw-member",
        Command::Leaves(_) => "leaves",
        _ => "command",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn legacy_egress_flags_still_parse() {
        let cli = Cli::try_parse_from([
            "shade-tree",
            "egress",
            "--plain-tcp",
            "127.0.0.1:1,127.0.0.1:2",
            "--identity",
            "id.json",
            "--members",
            "m.json",
            "--target",
            "example.com:443",
            "--circuits",
            "c",
            "--stdio",
            "--rotation-spread",
            "0",
            "--signers",
            "aa",
        ])
        .unwrap();
        let Command::Egress(args) = cli.command else {
            panic!("egress")
        };
        assert!(args.stdio);
        assert_eq!(args.net.rotation_spread.as_deref(), Some("0"));
        assert_eq!(args.net.signer.as_deref(), Some("aa"));
    }

    #[test]
    fn passthrough_commands_keep_their_own_flags_and_help() {
        let cli = Cli::try_parse_from(["shadenet", "enroll", "--help"]).unwrap();
        let Command::Enroll(pass) = cli.command else {
            panic!("enroll")
        };
        assert_eq!(pass.args, vec!["--help".to_string()]);
        let cli = Cli::try_parse_from(["shadenet", "member-status", "--identity", "x", "--json"])
            .unwrap();
        let Command::MemberStatus(pass) = cli.command else {
            panic!("member-status")
        };
        assert_eq!(pass.args, vec!["--identity", "x", "--json"]);
    }

    #[test]
    fn unknown_flags_are_rejected() {
        assert!(Cli::try_parse_from(["shadenet", "status", "--bogus"]).is_err());
        assert!(Cli::try_parse_from(["shadenet", "select", "d.json", "--bogus"]).is_err());
    }
}
