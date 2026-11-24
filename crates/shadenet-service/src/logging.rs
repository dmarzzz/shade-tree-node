//! Logging as the JavaScript services shaped it (`packages/node/lib/log.mjs`): a level and a
//! format, JSON unless stderr is an interactive terminal, resolved from the command line first,
//! then `SHADENET_LOG_*`, then a front door's `log` knob.

use std::io::IsTerminal as _;

use clap::ValueEnum;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, ValueEnum)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn directive(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Auto,
    Json,
    Text,
    Pretty,
}

/// Where the level and format come from, in order of precedence.
pub struct Settings<'a> {
    /// The `--log-level` flag.
    pub level: Option<Level>,
    /// The `--log-format` flag.
    pub format: Option<Format>,
    /// `SHADENET_LOG_LEVEL` (or its `SHADE_TREE_` twin), already read.
    pub env_level: Option<String>,
    /// `SHADENET_LOG_FORMAT`, already read.
    pub env_format: Option<String>,
    /// `SHADENET_LOG`, a tracing filter directive, honoured only without a front-door hint.
    pub env_filter: Option<String>,
    /// A front door's `log` knob as `(format, level)`.
    pub hint: Option<(String, String)>,
    /// The crate whose events the default filter admits at the chosen level.
    pub target: &'a str,
}

/// Install the global subscriber. A second call is a no-op.
pub fn init(settings: Settings<'_>) {
    let level = settings
        .level
        .or_else(|| {
            settings
                .env_level
                .as_deref()
                .and_then(|v| Level::from_str(v, true).ok())
        })
        .or_else(|| {
            settings
                .hint
                .as_ref()
                .and_then(|(_, level)| Level::from_str(level, true).ok())
        })
        .unwrap_or(Level::Info);
    let format = settings
        .format
        .or_else(|| {
            settings
                .env_format
                .as_deref()
                .and_then(|v| Format::from_str(v, true).ok())
        })
        .or_else(|| {
            settings
                .hint
                .as_ref()
                .and_then(|(format, _)| Format::from_str(format, true).ok())
        })
        .unwrap_or(Format::Auto);
    // through the front door SHADENET_LOG is the `format:level` knob, not a filter directive
    let filter = settings
        .hint
        .is_none()
        .then_some(settings.env_filter)
        .flatten()
        .and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| {
            EnvFilter::new(format!("warn,{}={}", settings.target, level.directive()))
        });
    let terminal = std::io::stderr().is_terminal();
    let interactive = terminal
        && std::env::var("TERM").is_ok_and(|t| t != "dumb")
        && std::env::var("CI").is_err();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let _ = match format {
        Format::Json => builder.json().with_current_span(false).try_init(),
        Format::Auto if !interactive => builder.json().with_current_span(false).try_init(),
        Format::Auto | Format::Pretty => builder.with_ansi(terminal).with_target(false).try_init(),
        Format::Text => builder.with_ansi(false).with_target(false).try_init(),
    };
}
