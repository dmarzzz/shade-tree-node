use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Environment(String),
    #[error("{name}: {message}")]
    Setting { name: &'static str, message: String },
    /// The front door knobs, every problem at once.
    #[error("{}\nrun `shadenet-node check` for the full picture", .0.iter().map(|e| format!("config: {e}")).collect::<Vec<_>>().join("\n"))]
    Knobs(Vec<String>),
    #[error("{0}")]
    Record(String),
    #[error("{0}")]
    Operator(String),
    #[error("failed to read {path}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid JSON")]
    ParseJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: {message}")]
    FileContent { path: PathBuf, message: String },
    #[error("no admission root available: {0}")]
    NoAdmissionRoot(String),
    #[error("slash: {0}")]
    Slash(String),
    #[error("failed to bind {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the address bound for {addr}")]
    LocalAddr {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to install the {signal} handler")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{open} connections were still open {grace:?} after shutdown began and were closed")]
    DrainTimeout { open: usize, grace: Duration },
}

impl Error {
    /// Process exit code: 2 for configuration, 1 for a runtime failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Environment(_)
            | Self::Setting { .. }
            | Self::Knobs(_)
            | Self::Record(_)
            | Self::ReadFile { .. }
            | Self::ParseJson { .. }
            | Self::FileContent { .. } => 2,
            Self::NoAdmissionRoot(_)
            | Self::Operator(_)
            | Self::Slash(_)
            | Self::Bind { .. }
            | Self::LocalAddr { .. }
            | Self::Signal { .. }
            | Self::DrainTimeout { .. } => 1,
        }
    }
}
