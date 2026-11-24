use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Every configuration problem at once.
    #[error("{}", .0.iter().map(|e| format!("config: {e}")).collect::<Vec<_>>().join("\n"))]
    Config(Vec<String>),
    #[error("signer key {path}: {message}")]
    Signer { path: PathBuf, message: String },
    #[error("onion identity: {0}")]
    Identity(String),
    /// A private state file the Elder refuses to start over.
    #[error("{path}: {message}")]
    State { path: PathBuf, message: String },
    #[error("failed to bind {addr}")]
    Bind {
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
            Self::Config(_) | Self::Signer { .. } | Self::Identity(_) | Self::State { .. } => 2,
            Self::Bind { .. } | Self::Signal { .. } | Self::DrainTimeout { .. } => 1,
        }
    }
}
