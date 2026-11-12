//! `shadenet-node`: the one-command front door for running a Shade Tree node.
//!
//! `run` resolves the configuration (the deployment record and the knobs, or the advanced
//! `SHADE_TREE_*` layer) and hands the process to `ShadeNode`; the other commands never start
//! a node and go through `Operator`.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use shadenet_node::{Config, Operator, ShadeNode};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("SHADENET_COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "shadenet-node",
    version = LONG_VERSION,
    about = "Run a Shade Tree node from a deployment record",
    disable_help_subcommand = true,
    after_help = "Knobs: `shadenet-node help` lists the SHADENET_* variables and node.toml keys."
)]
struct Cli {
    /// Log level [env: SHADENET_LOG_LEVEL]
    #[arg(long, global = true, value_enum)]
    log_level: Option<LogLevel>,
    /// Log format [env: SHADENET_LOG_FORMAT]
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Tor + node + heartbeat from the record alone (the default)
    Run,
    /// Validate the record, RPCs, Tor, disk and ports; print the plan
    Check {
        /// Reach each Elder Tree over a temporary Tor
        #[arg(long)]
        probe: bool,
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Mint (or show) this node's onion identity without starting
    Identity,
    /// Sign the onion with the staked operator key, where the key lives
    Authorize {
        /// The onion to authorize (56 chars, `.onion` optional)
        #[arg(long)]
        onion: Option<String>,
        /// Owner-only file holding the operator key
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// What a running node is doing (reads <state>/status.json)
    Status {
        /// Print nothing; the exit code says whether the node runs
        #[arg(long)]
        quiet: bool,
    },
    /// Stop announcing; the node leaves every Elder Tree within the TTL
    Retire,
    /// The knobs and commands
    Help,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Auto,
    Json,
    Text,
    Pretty,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // an unknown command is a usage error with the front door's exit code
            if e.kind() == clap::error::ErrorKind::InvalidSubcommand
                || e.kind() == clap::error::ErrorKind::UnknownArgument
            {
                eprintln!(
                    "[shadenet-node] {}",
                    e.to_string().lines().next().unwrap_or("unknown command")
                );
                eprint!("{}", Operator::usage());
                return ExitCode::from(2);
            }
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let command = cli.command.unwrap_or(Command::Run);
    if matches!(command, Command::Help) {
        print!("{}", Operator::usage());
        return ExitCode::SUCCESS;
    }
    let hint = Config::log_hint();
    init_logging(cli.log_level, cli.log_format, hint);
    match command {
        Command::Run => run(),
        Command::Check { probe, json } => report(Operator::check(probe, json).map(|ready| !ready)),
        Command::Identity => report(Operator::identity().map(|()| false)),
        Command::Authorize { onion, key_file } => {
            let onion = onion
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty());
            match (onion, key_file) {
                (Some(onion), Some(key_file)) => {
                    report(Operator::authorize(&onion, &key_file).map(|()| false))
                }
                _ => {
                    eprintln!("[shadenet-node] usage: shadenet-node authorize --onion <56-char>.onion --key-file <owner-only file with the operator key>");
                    ExitCode::from(2)
                }
            }
        }
        Command::Status { quiet } => report(Operator::status(quiet).map(|running| !running)),
        Command::Retire => report(Operator::retire().map(|()| false)),
        Command::Help => ExitCode::SUCCESS,
    }
}

/// `Ok(false)` exits 0, `Ok(true)` exits 1, an error prints and exits with its code.
fn report(outcome: Result<bool, shadenet_node::Error>) -> ExitCode {
    match outcome {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("[shadenet-node] {}", chain(&e));
            ExitCode::from(e.exit_code())
        }
    }
}

fn run() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("shadenet-node: {}", chain(&e));
            return ExitCode::from(e.exit_code());
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("shadenet-node: failed to start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(ShadeNode::new(config).run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{}", chain(&e));
            ExitCode::from(e.exit_code())
        }
    }
}

fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Flags win, then `SHADENET_LOG_*` / `SHADE_TREE_LOG_*`, then the front door's `log` knob.
fn init_logging(
    level: Option<LogLevel>,
    format: Option<LogFormat>,
    hint: Option<(String, String)>,
) {
    use tracing_subscriber::EnvFilter;
    let level = level
        .or_else(|| {
            shadenet::env::var_lenient("LOG_LEVEL").and_then(|v| LogLevel::from_str(&v, true).ok())
        })
        .or_else(|| {
            hint.as_ref()
                .and_then(|(_, level)| LogLevel::from_str(level, true).ok())
        })
        .unwrap_or(LogLevel::Info);
    let format = format
        .or_else(|| {
            shadenet::env::var_lenient("LOG_FORMAT")
                .and_then(|v| LogFormat::from_str(&v, true).ok())
        })
        .or_else(|| {
            hint.as_ref()
                .and_then(|(format, _)| LogFormat::from_str(format, true).ok())
        })
        .unwrap_or(LogFormat::Auto);
    let ours = match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    // through the front door SHADENET_LOG is the `format:level` knob, not a filter directive
    let filter = hint
        .is_none()
        .then(|| shadenet::env::var_lenient("LOG"))
        .flatten()
        .and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| EnvFilter::new(format!("warn,shadenet_node={ours}")));
    let terminal = std::io::stderr().is_terminal();
    let interactive = terminal
        && std::env::var("TERM").is_ok_and(|t| t != "dumb")
        && std::env::var("CI").is_err();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Json => builder.json().with_current_span(false).try_init(),
        LogFormat::Auto if !interactive => builder.json().with_current_span(false).try_init(),
        LogFormat::Auto | LogFormat::Pretty => {
            builder.with_ansi(terminal).with_target(false).try_init()
        }
        LogFormat::Text => builder.with_ansi(false).with_target(false).try_init(),
    };
}
