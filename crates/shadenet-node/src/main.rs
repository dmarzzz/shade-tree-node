//! `shadenet-node`: the one-command front door for running a Shade Tree node.
//!
//! `run` resolves the configuration (the deployment record and the knobs, or the advanced
//! `SHADE_TREE_*` layer) and hands the process to `ShadeNode`; the other commands never start
//! a node and go through `Operator`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use shadenet_node::{Config, Operator, ShadeNode};
use shadenet_service::logging::{self, Format, Level};

/// `<version> (commit <sha>)`, what `--version` prints.
fn long_version() -> String {
    format!(
        "{} (commit {})",
        env!("CARGO_PKG_VERSION"),
        shadenet_service::version::COMMIT
    )
}

#[derive(Parser)]
#[command(
    name = "shadenet-node",
    version = long_version(),
    about = "Run a Shade Tree node from a deployment record",
    disable_help_subcommand = true,
    after_help = "Knobs: `shadenet-node help` lists the SHADENET_* variables and node.toml keys."
)]
struct Cli {
    /// Log level [env: SHADENET_LOG_LEVEL]
    #[arg(long, global = true, value_enum)]
    log_level: Option<Level>,
    /// Log format [env: SHADENET_LOG_FORMAT]
    #[arg(long, global = true, value_enum)]
    log_format: Option<Format>,
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
    logging::init(logging::Settings {
        level: cli.log_level,
        format: cli.log_format,
        env_level: shadenet::env::var_lenient("LOG_LEVEL"),
        env_format: shadenet::env::var_lenient("LOG_FORMAT"),
        env_filter: shadenet::env::var_lenient("LOG"),
        hint,
        target: "shadenet_node",
    });
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
