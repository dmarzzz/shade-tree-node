//! `shadenet-elder`: the Elder Tree binary. `run` resolves the configuration and hands the
//! process to `Elder`; the other commands never start a service and go through `Operator`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use shadenet_elder::{Config, Elder, Operator};
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
    name = "shadenet-elder",
    version = long_version(),
    about = "Run an Elder Tree: the live node directory behind an onion",
    disable_help_subcommand = true,
    after_help = "Settings: `shadenet-elder help` lists the commands; docs/CONFIG.md the SHADE_TREE_BOOTNODE_* variables."
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
    /// Serve the directory (the default)
    Run,
    /// Validate the settings, the ports and the signer; print the plan
    Check,
    /// Mint the Elder's own onion identity for Tor's HiddenServiceDir
    Identity {
        /// The hidden-service directory to write
        hs_dir: PathBuf,
        /// A label kept in identity.local.json
        #[arg(long, default_value = "")]
        label: String,
        /// Overwrite an existing identity (an intentional rotation)
        #[arg(long)]
        force: bool,
    },
    /// Print the commands and where the settings are documented
    Help,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            if e.kind() == clap::error::ErrorKind::InvalidSubcommand
                || e.kind() == clap::error::ErrorKind::UnknownArgument
            {
                eprintln!(
                    "[shadenet-elder] {}",
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
    logging::init(logging::Settings {
        level: cli.log_level,
        format: cli.log_format,
        env_level: None,
        env_format: None,
        env_filter: std::env::var("SHADENET_LOG").ok(),
        hint: Config::log_hint(),
        target: "shadenet_elder",
    });
    match command {
        Command::Run => run(),
        Command::Check => report(Operator::check().map(|ready| !ready)),
        Command::Identity {
            hs_dir,
            label,
            force,
        } => report(Operator::identity(&hs_dir, &label, force).map(|()| false)),
        Command::Help => ExitCode::SUCCESS,
    }
}

/// `Ok(false)` is success, `Ok(true)` a reported problem, an error its own exit code.
fn report(outcome: Result<bool, shadenet_elder::Error>) -> ExitCode {
    match outcome {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("[shadenet-elder] {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn run() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("[shadenet-elder] {e}");
            return ExitCode::from(e.exit_code());
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("[shadenet-elder] failed to start the async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(Elder::new(config).run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(event = "service.failed", "Elder Tree failed: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
