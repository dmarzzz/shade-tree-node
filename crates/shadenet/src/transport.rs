//! Proof-gated transport: prove once, dial candidates in order, exchange the envelope and ack.
//!
//! [`Client`] owns the service-lifetime transport and proving state. Its Arti
//! dialer stores exactly one successfully bootstrapped `Arc<TorClient>` in an
//! async once-cell, so concurrent tunnels and failover candidates share the
//! same Tor network view. Groth16 work is admitted by a bounded semaphore and
//! runs on Tokio's blocking pool, never on an async network worker.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use shadenet_rln::prover::{BuiltEnvelope, EnvelopeInput};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OnceCell, Semaphore};
use tor_rtcompat::PreferredRuntime;

use crate::slot;

/// A bidirectional stream returned after a gateway accepts the RLN envelope.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxStream = Pin<Box<dyn AsyncStream>>;

/// One ordered candidate in a connect request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gateway {
    PlainTcp { address: String },
    Onion { onion: String, port: u16 },
}

impl Gateway {
    pub fn label(&self) -> String {
        match self {
            Self::PlainTcp { address } => address.clone(),
            Self::Onion { onion, port } => {
                format!("{}.onion:{port}", onion.trim_end_matches(".onion"))
            }
        }
    }
}

/// Result of one candidate dial. A gateway reply (accept or refusal) counts as
/// a successful dial; only transport/framing failures rotate to another entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub gateway: Gateway,
    pub dial_succeeded: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMetadata {
    pub target: String,
    pub nullifier: String,
}

/// Inputs for one proof-gated connection. The proof is built exactly once and
/// its framed bytes are reused for every failover candidate.
pub struct ConnectRequest {
    pub gateways: Vec<Gateway>,
    pub proof: ProofRequest,
    pub slots: SlotPolicy,
    pub artifact: String,
}

/// Proof inputs with no caller-controlled `message_id`. [`Client::connect`]
/// allocates that value durably immediately before dispatching the proof job.
pub struct ProofRequest {
    pub identity_secret: String,
    pub member_leaf: String,
    pub members: Vec<String>,
    pub target: String,
    pub nonce: String,
    pub epoch: u64,
    pub rln_identifier: String,
    pub user_message_limit: u64,
    pub circuits_dir: Option<String>,
}

/// Production callers use `CrashSafe`. The deliberately loud unsafe variant is
/// available only when an operator explicitly ports a slashing test; the CLI
/// requires its corresponding unsafe flag before constructing it.
pub enum SlotPolicy {
    CrashSafe { cursor: std::path::PathBuf },
    UnsafeForSlashingTest { message_id: u64 },
}

/// An accepted tunnel plus the bytes received after the ack's newline.
pub struct Connected {
    /// Opaque application stream. Once accepted, a gateway-enforced payload boundary appears as
    /// ordinary EOF because an in-band JSON error would corrupt the end-to-end TLS connection.
    pub stream: BoxStream,
    pub gateway: Gateway,
    pub ack: serde_json::Value,
    pub early_data: Vec<u8>,
    pub proof: ProofMetadata,
    pub attempts: Vec<Attempt>,
}

/// Stable classification for gateway refusals that need client-specific handling.
///
/// The full acknowledgement remains attached to [`Error::GatewayRefused`]. Only reasons with
/// protocol-defined client behavior belong here; unknown reasons stay terminal as [`Self::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRefusalKind {
    /// This gateway has no payload allowance left for the proof's RLN epoch slot.
    PayloadLimit,
    /// Any refusal not explicitly classified by this client version.
    Other,
}

impl GatewayRefusalKind {
    pub fn from_ack(ack: &serde_json::Value) -> Self {
        match ack.get("err").and_then(serde_json::Value::as_str) {
            Some(shadenet_proto::REASON_PAYLOAD_LIMIT) => Self::PayloadLimit,
            _ => Self::Other,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    NoGateways,
    Prove(String),
    Join(String),
    Slot(slot::Error),
    UnsafeSlotOutOfRange {
        message_id: u64,
        limit: u64,
    },
    GatewayRefused {
        gateway: Gateway,
        kind: GatewayRefusalKind,
        ack: Box<serde_json::Value>,
        proof: ProofMetadata,
        attempts: Vec<Attempt>,
    },
    AllCandidatesFailed {
        attempts: Vec<Attempt>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoGateways => f.write_str("no gateways"),
            Self::Prove(e) => write!(f, "build envelope: {e}"),
            Self::Join(e) => write!(f, "prover worker: {e}"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::UnsafeSlotOutOfRange { message_id, limit } => {
                write!(f, "unsafe message slot {message_id} is outside 0..{limit}")
            }
            Self::GatewayRefused { gateway, ack, .. } => write!(
                f,
                "gateway {} refused: {}",
                gateway.label(),
                ack.get("err")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(no err field)")
            ),
            Self::AllCandidatesFailed { attempts } => write!(
                f,
                "all {} candidate(s) failed; last error: {}",
                attempts.len(),
                attempts
                    .last()
                    .and_then(|a| a.error.as_deref())
                    .unwrap_or("(none)")
            ),
        }
    }
}

impl std::error::Error for Error {}

pub type DialFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxStream, String>> + Send + 'a>>;

/// Injectable transport boundary. Production uses embedded Arti; tests and
/// applications can provide a deterministic in-memory transport.
pub trait Dialer: Send + Sync {
    fn dial<'a>(&'a self, gateway: &'a Gateway) -> DialFuture<'a>;
    /// Return a per-tunnel isolation group. Failover candidates for one
    /// request share the returned group; separate requests must not.
    fn isolated(&self) -> Arc<dyn Dialer>;
    fn successful_bootstraps(&self) -> usize;
}

struct ArtiDialer {
    shared: Arc<ArtiShared>,
    isolated: Option<OnceCell<Arc<TorClient<PreferredRuntime>>>>,
}

struct ArtiShared {
    tor: OnceCell<Arc<TorClient<PreferredRuntime>>>,
    timeout: Duration,
    successful_bootstraps: AtomicUsize,
    directories: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl ArtiDialer {
    fn new(
        timeout: Duration,
        directories: Option<(std::path::PathBuf, std::path::PathBuf)>,
    ) -> Self {
        Self {
            shared: Arc::new(ArtiShared {
                tor: OnceCell::new(),
                timeout,
                successful_bootstraps: AtomicUsize::new(0),
                directories,
            }),
            isolated: None,
        }
    }

    fn config(&self) -> Result<TorClientConfig, String> {
        match &self.shared.directories {
            // Our own state and cache directories, so ShadeNet never shares guard or directory
            // state with another Arti on the same host.
            Some((state, cache)) => {
                // Arti refuses group- or world-writable state. A first run under umask 002 (the
                // Ubuntu default for users with a private group) leaves lock files mode 664 and
                // every later start fails; these directories are ours, so tighten them.
                for dir in [state, cache] {
                    make_private(dir);
                }
                TorClientConfigBuilder::from_directories(state, cache)
                    .build()
                    .map_err(|e| format!("arti config: {e}"))
            }
            None => Ok(TorClientConfig::default()),
        }
    }

    async fn tor(&self) -> Result<&Arc<TorClient<PreferredRuntime>>, String> {
        let base = self
            .shared
            .tor
            .get_or_try_init(|| async {
                let config = self.config()?;
                let client = tokio::time::timeout(
                    self.shared.timeout,
                    TorClient::create_bootstrapped(config),
                )
                .await
                .map_err(|_| format!("arti bootstrap timed out after {:?}", self.shared.timeout))?
                .map_err(|e| format!("arti bootstrap: {}", error_chain(&e)))?;
                self.shared
                    .successful_bootstraps
                    .fetch_add(1, Ordering::SeqCst);
                tracing::info!("embedded Arti bootstrap complete");
                Ok::<Arc<TorClient<PreferredRuntime>>, String>(client)
            })
            .await?;
        match &self.isolated {
            Some(isolated) => Ok(isolated
                .get_or_init(|| async { base.isolated_client() })
                .await),
            None => Ok(base),
        }
    }
}

/// `outer: inner: innermost`: Arti's top-level messages hide the cause (which path, which mode).
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        let text = inner.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = inner.source();
    }
    out
}

/// Create `dir` if needed and remove group and other access from it and everything below it.
/// Only ever called on ShadeNet's own Arti directories.
fn make_private(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fn walk(path: &std::path::Path, depth: usize) {
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            if meta.file_type().is_symlink() {
                return;
            }
            let mode = meta.permissions().mode() & 0o7777;
            let private = if meta.is_dir() {
                mode & 0o700 | 0o700
            } else {
                mode & 0o600
            };
            if mode != private {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(private));
            }
            if meta.is_dir() && depth < 8 {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        walk(&entry.path(), depth + 1);
                    }
                }
            }
        }
        let _ = std::fs::create_dir_all(dir);
        walk(dir, 0);
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::create_dir_all(dir);
    }
}

impl Dialer for ArtiDialer {
    fn dial<'a>(&'a self, gateway: &'a Gateway) -> DialFuture<'a> {
        Box::pin(async move {
            match gateway {
                Gateway::PlainTcp { address } => {
                    let stream = tokio::time::timeout(
                        self.shared.timeout,
                        tokio::net::TcpStream::connect(address),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "connect {address} timed out after {:?}",
                            self.shared.timeout
                        )
                    })?
                    .map_err(|e| format!("connect {address}: {e}"))?;
                    stream.set_nodelay(true).ok();
                    Ok(Box::pin(stream) as BoxStream)
                }
                Gateway::Onion { onion, port } => {
                    let host = format!("{}.onion", onion.trim_end_matches(".onion"));
                    let tor = Arc::clone(self.tor().await?);
                    let stream = tokio::time::timeout(
                        self.shared.timeout,
                        tor.connect((host.as_str(), *port)),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "onion connect {host}:{port} timed out after {:?}",
                            self.shared.timeout
                        )
                    })?
                    .map_err(|e| format!("connect onion {host}:{port}: {e}"))?;
                    Ok(Box::pin(stream) as BoxStream)
                }
            }
        })
    }

    fn isolated(&self) -> Arc<dyn Dialer> {
        Arc::new(Self {
            shared: Arc::clone(&self.shared),
            isolated: Some(OnceCell::new()),
        })
    }

    fn successful_bootstraps(&self) -> usize {
        self.shared.successful_bootstraps.load(Ordering::SeqCst)
    }
}

pub type ProveFuture = Pin<Box<dyn Future<Output = Result<BuiltEnvelope, Error>> + Send + 'static>>;

/// Injectable proof boundary used to keep transport tests fast and Tor-free.
pub trait Prover: Send + Sync {
    fn prove(&self, input: EnvelopeInput) -> ProveFuture;
}

type ProveFn = dyn Fn(EnvelopeInput) -> Result<BuiltEnvelope, String> + Send + Sync;

/// Groth16 executor with a hard upper bound on simultaneously running jobs.
pub struct BlockingProver {
    permits: Arc<Semaphore>,
    prove: Arc<ProveFn>,
}

impl BlockingProver {
    pub fn new(max_parallel: usize) -> Self {
        Self::with_function(max_parallel, |input| {
            shadenet_rln::prover::build_envelope(&input)
        })
    }

    /// Construct a bounded worker around another blocking prover. This is useful
    /// for deterministic tests and alternate artifact stores.
    pub fn with_function<F>(max_parallel: usize, prove: F) -> Self
    where
        F: Fn(EnvelopeInput) -> Result<BuiltEnvelope, String> + Send + Sync + 'static,
    {
        Self {
            permits: Arc::new(Semaphore::new(max_parallel.max(1))),
            prove: Arc::new(prove),
        }
    }
}

impl Prover for BlockingProver {
    fn prove(&self, input: EnvelopeInput) -> ProveFuture {
        let permits = Arc::clone(&self.permits);
        let prove = Arc::clone(&self.prove);
        Box::pin(async move {
            let permit = permits
                .acquire_owned()
                .await
                .map_err(|e| Error::Join(e.to_string()))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                prove(input).map_err(Error::Prove)
            })
            .await
            .map_err(|e| Error::Join(e.to_string()))?
        })
    }
}

/// Service-lifetime egress state. Clone/share this with every proxy connection.
pub struct Client {
    dialer: Arc<dyn Dialer>,
    prover: Arc<dyn Prover>,
    ack_timeout: Duration,
}

impl Client {
    pub fn new(tor_timeout: Duration, ack_timeout: Duration, max_parallel_proofs: usize) -> Self {
        Self::with_tor_directories(tor_timeout, ack_timeout, max_parallel_proofs, None)
    }

    /// Like [`Client::new`], with Arti state and cache directories owned by ShadeNet.
    pub fn with_tor_directories(
        tor_timeout: Duration,
        ack_timeout: Duration,
        max_parallel_proofs: usize,
        directories: Option<(std::path::PathBuf, std::path::PathBuf)>,
    ) -> Self {
        Self {
            dialer: Arc::new(ArtiDialer::new(tor_timeout, directories)),
            prover: Arc::new(BlockingProver::new(max_parallel_proofs)),
            ack_timeout,
        }
    }

    pub fn with_components(dialer: Arc<dyn Dialer>, prover: Arc<dyn Prover>) -> Self {
        Self::with_components_and_ack_timeout(dialer, prover, Duration::from_secs(15))
    }

    pub fn with_components_and_ack_timeout(
        dialer: Arc<dyn Dialer>,
        prover: Arc<dyn Prover>,
        ack_timeout: Duration,
    ) -> Self {
        Self {
            dialer,
            prover,
            ack_timeout,
        }
    }

    /// Number of successful Arti bootstraps performed by this client. It is
    /// observable for acceptance tests and operational diagnostics.
    pub fn successful_bootstraps(&self) -> usize {
        self.dialer.successful_bootstraps()
    }

    /// Open a raw stream through the same service-lifetime transport. This is
    /// used for authenticated bootnode directory discovery before proof
    /// construction; onion calls share the exact Arti once-cell used by
    /// [`Client::connect`].
    pub async fn open(&self, gateway: &Gateway) -> Result<BoxStream, String> {
        self.dialer.dial(gateway).await
    }

    /// Prove once, then try candidates in order. A gateway refusal is terminal;
    /// only dial/I/O failures advance to the next candidate.
    pub async fn connect(&self, request: ConnectRequest) -> Result<Connected, Error> {
        if request.gateways.is_empty() {
            return Err(Error::NoGateways);
        }
        let message_id = match request.slots {
            SlotPolicy::CrashSafe { cursor } => {
                let epoch = request.proof.epoch;
                let limit = request.proof.user_message_limit;
                tokio::task::spawn_blocking(move || slot::allocate(&cursor, epoch, limit))
                    .await
                    .map_err(|e| Error::Join(e.to_string()))?
                    .map_err(Error::Slot)?
            }
            SlotPolicy::UnsafeForSlashingTest { message_id } => message_id,
        };
        if message_id >= request.proof.user_message_limit {
            return Err(Error::UnsafeSlotOutOfRange {
                message_id,
                limit: request.proof.user_message_limit,
            });
        }
        let proof_input = EnvelopeInput {
            identity_secret: request.proof.identity_secret,
            member_leaf: request.proof.member_leaf,
            members: request.proof.members,
            target: request.proof.target,
            nonce: request.proof.nonce,
            epoch: request.proof.epoch,
            rln_identifier: request.proof.rln_identifier,
            user_message_limit: request.proof.user_message_limit,
            message_id,
            circuits_dir: request.proof.circuits_dir,
        };
        let built = self.prover.prove(proof_input).await?;
        let proof = ProofMetadata {
            target: built.target.clone(),
            nullifier: built.nullifier.clone(),
        };
        let envelope = serde_json::json!({
            "v": shadenet_proto::PROTO_MAX,
            "target": built.target,
            "nonce": built.nonce,
            "artifact": request.artifact,
            "proof": {
                "snarkProof": { "proof": built.proof, "publicSignals": built.public_signals },
                "epoch": built.epoch,
                "rlnIdentifier": built.rln_identifier,
            },
            "nullifier": built.nullifier,
            "externalNullifier": built.external_nullifier,
            "share": { "x": built.share_x, "y": built.share_y },
        });
        let wire = serde_json::to_string(&envelope).expect("serialize envelope") + "\n";
        let mut attempts = Vec::with_capacity(request.gateways.len());
        let dialer = self.dialer.isolated();

        for gateway in request.gateways {
            match dialer.dial(&gateway).await {
                Ok(mut stream) => match tokio::time::timeout(
                    self.ack_timeout,
                    exchange_ack(&mut stream, wire.as_bytes()),
                )
                .await
                .map_err(|_| {
                    format!(
                        "gateway envelope/ack exchange timed out after {:?}",
                        self.ack_timeout
                    )
                })
                .and_then(|result| result)
                {
                    Ok((ack, early_data)) => {
                        attempts.push(Attempt {
                            gateway: gateway.clone(),
                            dial_succeeded: true,
                            error: None,
                        });
                        if ack.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                            return Ok(Connected {
                                stream,
                                gateway,
                                ack,
                                early_data,
                                proof,
                                attempts,
                            });
                        }
                        let kind = GatewayRefusalKind::from_ack(&ack);
                        return Err(Error::GatewayRefused {
                            gateway,
                            kind,
                            ack: Box::new(ack),
                            proof,
                            attempts,
                        });
                    }
                    Err(error) => attempts.push(Attempt {
                        gateway,
                        dial_succeeded: false,
                        error: Some(error),
                    }),
                },
                Err(error) => attempts.push(Attempt {
                    gateway,
                    dial_succeeded: false,
                    error: Some(error),
                }),
            }
        }
        Err(Error::AllCandidatesFailed { attempts })
    }
}

async fn exchange_ack(
    stream: &mut BoxStream,
    wire: &[u8],
) -> Result<(serde_json::Value, Vec<u8>), String> {
    stream
        .write_all(wire)
        .await
        .map_err(|e| format!("write envelope: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush envelope: {e}"))?;
    let mut line = Vec::with_capacity(256);
    let mut early = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read ack: {e}"))?;
        if n == 0 {
            return Err("gateway closed the connection before an ack".into());
        }
        if let Some(newline) = chunk[..n].iter().position(|byte| *byte == b'\n') {
            line.extend_from_slice(&chunk[..newline]);
            early.extend_from_slice(&chunk[newline + 1..n]);
            break;
        }
        line.extend_from_slice(&chunk[..n]);
        if line.len() > 64 * 1024 {
            return Err("ack exceeded 64KiB without a newline".into());
        }
    }
    let text = String::from_utf8_lossy(&line);
    let ack: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        format!(
            "bad ack json ({e}): {}",
            text.chars().take(160).collect::<String>()
        )
    })?;
    if ack.get("ok").and_then(serde_json::Value::as_bool).is_none() {
        return Err("bad ack shape: expected an object with boolean `ok`".into());
    }
    Ok((ack, early))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn arti_directories_are_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("shadenet-private-{}", std::process::id()));
        let nested = root.join("state");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o775)).unwrap();
        let lock = nested.join("state.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o664)).unwrap();
        make_private(&root);
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&lock), 0o600);
        std::fs::remove_dir_all(root).ok();
    }
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn built(target: String) -> BuiltEnvelope {
        BuiltEnvelope {
            target,
            nonce: "00".repeat(16),
            epoch: "1".into(),
            rln_identifier: "1".into(),
            proof: serde_json::json!({}),
            public_signals: serde_json::json!([]),
            nullifier: "2".into(),
            external_nullifier: "3".into(),
            share_x: "4".into(),
            share_y: "5".into(),
        }
    }

    fn input(target: &str) -> EnvelopeInput {
        EnvelopeInput {
            identity_secret: "1".into(),
            member_leaf: "1".into(),
            members: vec!["1".into()],
            target: target.into(),
            nonce: "00".repeat(16),
            epoch: 1,
            rln_identifier: "1".into(),
            user_message_limit: 8,
            message_id: 0,
            circuits_dir: None,
        }
    }

    fn proof_request(target: &str) -> ProofRequest {
        ProofRequest {
            identity_secret: "1".into(),
            member_leaf: "1".into(),
            members: vec!["1".into()],
            target: target.into(),
            nonce: "00".repeat(16),
            epoch: 1,
            rln_identifier: "1".into(),
            user_message_limit: 8,
            circuits_dir: None,
        }
    }

    struct FakeArti {
        bootstrapped: Arc<AtomicBool>,
        bootstraps: Arc<AtomicUsize>,
        isolations: Arc<AtomicUsize>,
    }

    impl Dialer for FakeArti {
        fn dial<'a>(&'a self, _gateway: &'a Gateway) -> DialFuture<'a> {
            Box::pin(async move {
                if !self.bootstrapped.swap(true, Ordering::SeqCst) {
                    self.bootstraps.fetch_add(1, Ordering::SeqCst);
                }
                let (client, mut gateway) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    loop {
                        let mut byte = [0_u8; 1];
                        gateway.read_exact(&mut byte).await.unwrap();
                        request.push(byte[0]);
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let value: serde_json::Value =
                        serde_json::from_slice(&request[..request.len() - 1]).unwrap();
                    assert!(value.get("proof").is_some());
                    gateway.write_all(b"{\"ok\":true}\n").await.unwrap();
                });
                Ok(Box::pin(client) as BoxStream)
            })
        }

        fn successful_bootstraps(&self) -> usize {
            self.bootstraps.load(Ordering::SeqCst)
        }

        fn isolated(&self) -> Arc<dyn Dialer> {
            self.isolations.fetch_add(1, Ordering::SeqCst);
            Arc::new(Self {
                bootstrapped: Arc::clone(&self.bootstrapped),
                bootstraps: Arc::clone(&self.bootstraps),
                isolations: Arc::clone(&self.isolations),
            })
        }
    }

    struct PayloadLimitDialer {
        dials: Arc<AtomicUsize>,
    }

    impl Dialer for PayloadLimitDialer {
        fn dial<'a>(&'a self, _gateway: &'a Gateway) -> DialFuture<'a> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let (client, mut gateway) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    loop {
                        let mut byte = [0_u8; 1];
                        gateway.read_exact(&mut byte).await.unwrap();
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    gateway
                        .write_all(b"{\"ok\":false,\"err\":\"payload-limit\"}\n")
                        .await
                        .unwrap();
                });
                Ok(Box::pin(client) as BoxStream)
            })
        }

        fn successful_bootstraps(&self) -> usize {
            0
        }

        fn isolated(&self) -> Arc<dyn Dialer> {
            Arc::new(Self {
                dials: Arc::clone(&self.dials),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_tunnels_share_one_injected_bootstrap() {
        let dialer = Arc::new(FakeArti {
            bootstrapped: Arc::new(AtomicBool::new(false)),
            bootstraps: Arc::new(AtomicUsize::new(0)),
            isolations: Arc::new(AtomicUsize::new(0)),
        });
        let isolations = Arc::clone(&dialer.isolations);
        let proves = Arc::new(AtomicUsize::new(0));
        let proof_count = Arc::clone(&proves);
        let prover = Arc::new(BlockingProver::with_function(2, move |input| {
            proof_count.fetch_add(1, Ordering::SeqCst);
            Ok(built(input.target))
        }));
        let client = Client::with_components(dialer, prover);
        let cursor = std::env::temp_dir().join(format!(
            "shade-tree-egress-client-test-{}-{}.json",
            std::process::id(),
            proves.load(Ordering::Relaxed)
        ));

        for target in ["one.example:443", "two.example:443"] {
            let connected = client
                .connect(ConnectRequest {
                    gateways: vec![Gateway::Onion {
                        onion: "fake".into(),
                        port: 80,
                    }],
                    proof: proof_request(target),
                    slots: SlotPolicy::CrashSafe {
                        cursor: cursor.clone(),
                    },
                    artifact: "rln-test".into(),
                })
                .await
                .unwrap();
            assert_eq!(connected.proof.target, target);
        }
        assert_eq!(client.successful_bootstraps(), 1);
        assert_eq!(isolations.load(Ordering::SeqCst), 2);
        assert_eq!(proves.load(Ordering::SeqCst), 2);
        let _ = std::fs::remove_file(&cursor);
        let mut lock = cursor.as_os_str().to_os_string();
        lock.push(".lock");
        let _ = std::fs::remove_dir(std::path::PathBuf::from(lock));
    }

    #[tokio::test]
    async fn payload_limit_is_typed_and_terminal_before_gateway_failover() {
        assert_eq!(shadenet_proto::DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES, 41_943_040);
        assert_eq!(
            GatewayRefusalKind::from_ack(&serde_json::json!({
                "ok": false,
                "err": "payload-limit"
            })),
            GatewayRefusalKind::PayloadLimit
        );
        assert_eq!(
            GatewayRefusalKind::from_ack(&serde_json::json!({
                "ok": false,
                "err": "invalid-proof"
            })),
            GatewayRefusalKind::Other
        );

        let dials = Arc::new(AtomicUsize::new(0));
        let dialer = Arc::new(PayloadLimitDialer {
            dials: Arc::clone(&dials),
        });
        let prover = Arc::new(BlockingProver::with_function(1, move |input| {
            Ok(built(input.target))
        }));
        let client = Client::with_components(dialer, prover);
        let outcome = client
            .connect(ConnectRequest {
                gateways: vec![
                    Gateway::PlainTcp {
                        address: "first.invalid:1".into(),
                    },
                    Gateway::PlainTcp {
                        address: "must-not-dial.invalid:2".into(),
                    },
                ],
                proof: proof_request("example.com:443"),
                slots: SlotPolicy::UnsafeForSlashingTest { message_id: 0 },
                artifact: "rln-test".into(),
            })
            .await;

        match outcome {
            Err(Error::GatewayRefused {
                kind,
                ack,
                attempts,
                ..
            }) => {
                assert_eq!(kind, GatewayRefusalKind::PayloadLimit);
                assert_eq!(
                    ack.get("err").and_then(serde_json::Value::as_str),
                    Some(shadenet_proto::REASON_PAYLOAD_LIMIT)
                );
                assert_eq!(attempts.len(), 1);
                assert!(attempts[0].dial_succeeded);
            }
            _ => panic!("payload-limit must remain a terminal typed gateway refusal"),
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_prover_never_exceeds_bound() {
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let running_job = Arc::clone(&running);
        let peak_job = Arc::clone(&peak);
        let prover = Arc::new(BlockingProver::with_function(1, move |input| {
            let now = running_job.fetch_add(1, Ordering::SeqCst) + 1;
            peak_job.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(25));
            running_job.fetch_sub(1, Ordering::SeqCst);
            Ok(built(input.target))
        }));
        let one = prover.prove(input("one:443"));
        let two = prover.prove(input("two:443"));
        let three = prover.prove(input("three:443"));
        let (one, two, three) = tokio::join!(one, two, three);
        one.unwrap();
        two.unwrap();
        three.unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ack_exchange_times_out_and_rejects_missing_ok_shape() {
        let (client, _server) = tokio::io::duplex(128);
        let mut stream = Box::pin(client) as BoxStream;
        let timed_out = tokio::time::timeout(
            Duration::from_millis(10),
            exchange_ack(&mut stream, b"{}\n"),
        )
        .await;
        assert!(timed_out.is_err());

        let (client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let mut request = [0_u8; 3];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(b"{}\n").await.unwrap();
        });
        let mut stream = Box::pin(client) as BoxStream;
        let error = exchange_ack(&mut stream, b"{}\n").await.unwrap_err();
        assert!(error.contains("boolean `ok`"));
    }
}
