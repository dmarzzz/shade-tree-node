//! The long-lived ShadeNet client.
//!
//! One [`Client`] serves many tunnels. It keeps:
//! - the verified canopy in memory, refreshed in the background, with a last-known-good copy on
//!   disk and a rollback floor (a fresh canopy may never be older than the one in use);
//! - the member set, reused for `member_refresh` instead of replaying chain logs per tunnel;
//! - node health, in memory and persisted;
//! - one embedded Arti bootstrap and one bounded prover shared by every tunnel.
//!
//! Every failure is a typed [`Error`] with a stable code.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use shadenet_proto::{selection_order, spread_selection_order, Directory, SmoothWeightedState};
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

use crate::capability::{self, Admission, Requirement};
use crate::config::{Config, Discovery, Identity, Members, Slots};
use crate::dircache::{self, DemoAdvert};
use crate::health::{self, HealthCache};
use crate::leaves::{self, DiscoveredMembers};
use crate::profile::PublicProfile;
use crate::scheduler::{self, Budget, Plan};
use crate::transport::{self, BoxStream, Gateway};
use crate::{slot, Error};

/// Epoch length used by custom canopies that sign no rate policy.
pub const LEGACY_EPOCH_SECONDS: u64 = 120;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

use crate::identity::IdentityMaterial;

fn load_identity(
    identity: &Identity,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<IdentityMaterial, Error> {
    match identity {
        Identity::File(path) => {
            let public = crate::identity::read_public(path)?;
            if public.encrypted && passphrase.is_none() {
                // Status and admission checks need only the public leaf. Tunnels need the secret
                // and fail with a clear message (see `locked_identity`).
                validate_leaf(&public.leaf)?;
                return Ok(IdentityMaterial {
                    secret: Zeroizing::new(String::new()),
                    leaf: public.leaf,
                    limit: public.limit,
                });
            }
            let material = crate::identity::load(path, || {
                passphrase
                    .cloned()
                    .ok_or_else(|| Error::Config("identity passphrase missing".into()))
            })?;
            validate_leaf(&material.leaf)?;
            Ok(material)
        }
        Identity::Material {
            secret,
            leaf,
            limit,
        } => {
            validate_leaf(leaf)?;
            Ok(IdentityMaterial {
                secret: secret.clone(),
                leaf: leaf.clone(),
                limit: *limit,
            })
        }
    }
}

fn validate_leaf(leaf: &str) -> Result<(), Error> {
    if leaf.is_empty() || !leaf.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Config(
            "identity leaf must be a canonical decimal field element".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct MembersFile {
    members: Vec<String>,
}

/// A verified canopy snapshot.
#[derive(Clone)]
struct CanopySnapshot {
    dir: Directory,
    demo: Option<DemoAdvert>,
    fetched_at: Instant,
    from_cache: bool,
    fresh_error: Option<String>,
    /// Operator-declared incidents from every Elder that served a verified feed (advice only).
    incidents: Vec<crate::incidents::Incident>,
}

/// One place a signed canopy comes from.
#[derive(Clone, Debug)]
enum CanopySource {
    Elder { onion: String, signers: String },
    File { path: PathBuf, signers: String },
}

impl CanopySource {
    fn signers(&self) -> &str {
        match self {
            Self::Elder { signers, .. } | Self::File { signers, .. } => signers,
        }
    }
    fn label(&self) -> String {
        match self {
            Self::Elder { onion, .. } => format!("Elder Tree {}", &onion[..onion.len().min(16)]),
            Self::File { path, .. } => path.display().to_string(),
        }
    }
}

/// Union of verified canopies: every node listed by any verified directory, once. When two
/// directories list the same node, the entry from the more recently issued directory wins. The
/// result carries the newest `issued`; it is never re-verified as a whole (each part already was).
fn merge_canopies(mut outcomes: Vec<dircache::LoadOutcome>) -> (Directory, Option<DemoAdvert>) {
    outcomes.sort_by_key(|outcome| std::cmp::Reverse(outcome.dir.issued));
    let mut iter = outcomes.into_iter();
    let first = iter.next().expect("at least one verified canopy");
    let mut dir = first.dir;
    let mut demo = first.demo;
    let mut seen: HashSet<String> = dir.gateways.iter().map(|g| g.onion.clone()).collect();
    for outcome in iter {
        if demo.is_none() {
            demo = outcome.demo;
        }
        for gateway in outcome.dir.gateways {
            if seen.insert(gateway.onion.clone()) {
                dir.gateways.push(gateway);
            }
        }
    }
    (dir, demo)
}

#[derive(Clone)]
struct MemberSnapshot {
    set: Arc<DiscoveredMembers>,
    fetched_at: Instant,
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct MemberKey {
    contract: String,
    /// Failover order (ADR 0012): an explicit rpc_url (comma-separated allowed), else the
    /// profile's list, else the local dev node.
    rpc_urls: Vec<String>,
    from_block: u64,
    block_tag: String,
}

/// Counters exported by [`Client::metrics`] and the proxy's metrics endpoint.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub tunnels_opened: u64,
    pub tunnels_failed: u64,
    pub canopy_refreshes: u64,
    pub canopy_refresh_failures: u64,
    pub member_fetches: u64,
    pub member_fetch_failures: u64,
    /// Failures by error code.
    pub errors: BTreeMap<String, u64>,
}

#[derive(Default)]
struct Counters {
    tunnels_opened: AtomicU64,
    tunnels_failed: AtomicU64,
    canopy_refreshes: AtomicU64,
    canopy_refresh_failures: AtomicU64,
    member_fetches: AtomicU64,
    member_fetch_failures: AtomicU64,
    errors: StdMutex<BTreeMap<String, u64>>,
}

/// An accepted tunnel.
pub struct Tunnel {
    /// The stream to the destination. Bytes the node sent after its ack are in `early_data`; use
    /// [`Tunnel::into_stream`] to read them transparently.
    pub stream: BoxStream,
    pub early_data: Vec<u8>,
    /// The node that accepted, as `<onion>.onion:<port>` (or `host:port` for plain TCP).
    pub gateway: String,
    pub target: String,
    pub nullifier: String,
    pub epoch: u64,
    /// The node's signed receipt, when it sent one.
    pub receipt: Option<serde_json::Value>,
    /// `Some(book digest)` when this tunnel spent a session ticket instead of a proof (ADR 0011).
    pub session: Option<String>,
    /// How long the request was held in the budget queue before it opened (ADR 0013).
    pub waited: Duration,
}

impl Tunnel {
    /// One stream that yields `early_data` first.
    pub fn into_stream(self) -> BoxStream {
        if self.early_data.is_empty() {
            self.stream
        } else {
            Box::pin(crate::stream::Prepend::new(self.early_data, self.stream))
        }
    }
}

/// A point-in-time view for agents and operators. Field names are the public JSON contract of
/// `shadenet status --json` and `GET /_shadenet/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    pub network: String,
    /// `ready`, `not_admitted`, `not_finalized`, `budget_exhausted`, `no_identity`, `degraded`.
    pub state: String,
    pub admitted: Option<bool>,
    pub finalized: Option<bool>,
    pub leaf: Option<String>,
    pub admission_set: Option<String>,
    pub tier: Option<u64>,
    pub epoch: u64,
    pub epoch_seconds: u64,
    pub epoch_resets_in_seconds: u64,
    pub slots_used: Option<u64>,
    pub slots_left: Option<u64>,
    pub canopy: CanopyStatus,
    pub tor_ready: bool,
    pub last_error: Option<serde_json::Value>,
    /// Per-node reachability and measured dial latency, best first (ADR 0013).
    pub nodes: Vec<NodeStatus>,
    /// The budget queue (ADR 0013).
    pub queue: QueueStatus,
    /// What one more tunnel costs right now.
    pub plan: Option<Plan>,
    /// Everything an agent should read before retrying: why the state is not `ready`, which
    /// canopy sources fell back, the last error's cause and fix, and the operators' open
    /// incidents. Empty when nothing is wrong.
    pub problems: Vec<Problem>,
}

/// One thing standing between the agent and a working tunnel, with the cause and the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// `state`, `canopy`, `last_error`, `incident`.
    pub kind: String,
    /// The error code, state name or incident id.
    pub code: String,
    pub cause: String,
    pub fix: String,
    /// For incidents: the component and instance the operator named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// One canopy node as the client sees it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub onion: String,
    /// The canopy's own health word for the node (`up`, `down`, ...).
    pub health: String,
    /// Dial latency EWMA in milliseconds, measured by this client (tunnels and warm-ups).
    pub latency_ms: Option<f64>,
    /// Consecutive dial failures seen by this client.
    pub fails: u64,
    /// This node is the next pick for a tunnel.
    pub preferred: bool,
}

/// The budget queue: requests held for the next epoch instead of refused (ADR 0013).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueStatus {
    pub enabled: bool,
    /// Requests waiting for a slot right now.
    pub depth: u64,
    pub max_wait_seconds: u64,
    /// Seconds until a new request could open: 0 when a slot or ticket is free now.
    pub next_slot_in_seconds: u64,
    pub capacity_per_epoch: u64,
    pub available_now: u64,
    pub queued_total: u64,
    pub waited_seconds_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanopyStatus {
    pub nodes: usize,
    pub eligible: usize,
    pub issued: Option<u64>,
    pub age_seconds: Option<u64>,
    pub from_last_known_good: bool,
    /// `true` when the client is past `Config::canopy_max_stale` on a last-known-good copy
    /// (every Elder Tree unreachable for that long): status is reported, routing fails closed.
    pub stale: bool,
    pub error: Option<String>,
}

/// The ShadeNet client. Share it behind an `Arc`.
pub struct Client {
    config: Config,
    profile: Option<PublicProfile>,
    identity: Option<IdentityMaterial>,
    transport: transport::Client,
    canopy: Mutex<Option<CanopySnapshot>>,
    /// Highest `issued` accepted per canopy source (keyed by its signer set).
    canopy_floors: StdMutex<std::collections::HashMap<String, u64>>,
    members: Mutex<BTreeMap<MemberKey, MemberSnapshot>>,
    health: StdMutex<(HealthCache, HashSet<String>)>,
    rotation: StdMutex<SmoothWeightedState>,
    artifact: OnceCell<String>,
    last_error: StdMutex<Option<serde_json::Value>>,
    counters: Counters,
    /// Live session-ticket books, one per node (ADR 0011); empty unless `session_tickets` is on.
    sessions: crate::session::SessionPool,
    /// Nodes that refused a session initialization as unsupported this process lifetime.
    session_refused: StdMutex<HashSet<String>>,
    /// Serializes session-book initialization so concurrent tunnels to one node share one
    /// proof and one book instead of each opening its own (ADR 0013).
    session_init_gate: Mutex<()>,
    queue: QueueCounters,
    /// The node a transport failure was last attributed to, for the one retry elsewhere.
    last_failed_gateway: StdMutex<Option<String>>,
}

#[derive(Default)]
struct QueueCounters {
    depth: AtomicU64,
    seq: AtomicU64,
    queued_total: AtomicU64,
    waited_ms_total: AtomicU64,
}

impl Client {
    /// Validate the configuration and load the identity. No network I/O happens here.
    pub fn new(config: Config) -> Result<Self, Error> {
        let transport = transport::Client::with_tor_directories(
            config.tor_timeout,
            config.ack_timeout,
            config.prover_workers,
            config.tor_directories.clone(),
        );
        Self::with_transport(config, transport)
    }

    /// Like [`Client::new`] with an injected transport (tests, alternative dialers).
    pub fn with_transport(config: Config, transport: transport::Client) -> Result<Self, Error> {
        let profile = if config.uses_public_profile() {
            Some(config.network.public_profile()?)
        } else {
            None
        };
        if let (Some(profile), Some(seconds)) = (&profile, config.epoch_seconds) {
            if seconds != profile.rate_policy.epoch_seconds {
                return Err(Error::Config(format!(
                    "epoch seconds {seconds} conflicts with the network's signed rate policy ({})",
                    profile.rate_policy.epoch_seconds
                )));
            }
        }
        let identity = config
            .identity
            .as_ref()
            .map(|identity| load_identity(identity, config.passphrase.as_ref()))
            .transpose()?;
        let health_path = health_path(&config);
        let cache = health::load(health_path.as_deref());
        Ok(Self {
            config,
            profile,
            identity,
            transport,
            canopy: Mutex::new(None),
            canopy_floors: StdMutex::new(std::collections::HashMap::new()),
            members: Mutex::new(BTreeMap::new()),
            health: StdMutex::new((cache, HashSet::new())),
            rotation: StdMutex::new(SmoothWeightedState::default()),
            artifact: OnceCell::new(),
            last_error: StdMutex::new(None),
            counters: Counters::default(),
            sessions: crate::session::SessionPool::new(),
            session_refused: StdMutex::new(HashSet::new()),
            session_init_gate: Mutex::new(()),
            queue: QueueCounters::default(),
            last_failed_gateway: StdMutex::new(None),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The public profile in use, if this is the zero-configuration path.
    pub fn public_profile(&self) -> Option<&PublicProfile> {
        self.profile.as_ref()
    }

    /// The member leaf, if an identity is configured.
    pub fn leaf(&self) -> Option<&str> {
        self.identity
            .as_ref()
            .map(|identity| identity.leaf.as_str())
    }

    /// Effective epoch length.
    pub fn epoch_seconds(&self) -> u64 {
        self.config
            .epoch_seconds
            .or_else(|| {
                self.profile
                    .as_ref()
                    .map(|profile| profile.rate_policy.epoch_seconds)
            })
            .unwrap_or(LEGACY_EPOCH_SECONDS)
    }

    fn current_epoch(&self) -> u64 {
        self.config
            .epoch
            .unwrap_or_else(|| now_secs() / self.epoch_seconds())
    }

    fn resets_in(&self) -> Duration {
        let seconds = self.epoch_seconds();
        Duration::from_secs(seconds - (now_secs() % seconds))
    }

    /// Effective tier (`userMessageLimit`).
    pub fn tier(&self) -> u64 {
        self.config
            .limit
            .or_else(|| self.identity.as_ref().and_then(|identity| identity.limit))
            .or_else(|| self.profile.as_ref().map(|profile| profile.default_limit))
            .unwrap_or(crate::profile::LEGACY_DEFAULT_LIMIT)
    }

    fn block_tag(&self) -> String {
        self.config.block_tag.clone().unwrap_or_else(|| {
            if self.profile.is_some() {
                "finalized".into()
            } else {
                "latest".into()
            }
        })
    }

    fn admission(&self) -> Admission {
        Admission {
            leaf_source: self.config.leaf_source.clone().or_else(|| {
                self.profile
                    .as_ref()
                    .map(|profile| profile.default_path.clone())
            }),
            max_anon: self.config.max_anon,
        }
    }

    fn slot_path(&self, leaf: &str) -> Result<Option<PathBuf>, Error> {
        match &self.config.slots {
            Slots::CrashSafe => slot::default_path(leaf)
                .map(Some)
                .map_err(|e| Error::Slot(e.to_string())),
            Slots::Cursor(path) => Ok(Some(path.clone())),
            Slots::UnsafeForSlashingTest(_) => Ok(None),
        }
    }

    fn record_error(&self, error: &Error) {
        self.counters.tunnels_failed.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut errors) = self.counters.errors.lock() {
            *errors.entry(error.code().to_string()).or_default() += 1;
        }
        if let Ok(mut last) = self.last_error.lock() {
            let mut body = error.to_json()["error"].clone();
            body["at"] = now_secs().into();
            *last = Some(body);
        }
    }

    /// Snapshot of the client's counters.
    pub fn metrics(&self) -> Metrics {
        let c = &self.counters;
        Metrics {
            tunnels_opened: c.tunnels_opened.load(Ordering::Relaxed),
            tunnels_failed: c.tunnels_failed.load(Ordering::Relaxed),
            canopy_refreshes: c.canopy_refreshes.load(Ordering::Relaxed),
            canopy_refresh_failures: c.canopy_refresh_failures.load(Ordering::Relaxed),
            member_fetches: c.member_fetches.load(Ordering::Relaxed),
            member_fetch_failures: c.member_fetch_failures.load(Ordering::Relaxed),
            errors: c.errors.lock().map(|e| e.clone()).unwrap_or_default(),
        }
    }

    /// Number of successful embedded Arti bootstraps so far.
    pub fn tor_bootstraps(&self) -> usize {
        self.transport.successful_bootstraps()
    }

    // ---------------------------------------------------------------- canopy

    /// Where canopies come from: every Elder Tree of the network, one named Elder, or a file.
    fn sources(&self) -> Vec<CanopySource> {
        match &self.config.discovery {
            Discovery::Network => self
                .config
                .network
                .deployment
                .elders
                .iter()
                .map(|elder| CanopySource::Elder {
                    onion: elder.onion.clone(),
                    signers: elder.canopy_signer.clone(),
                })
                .collect(),
            Discovery::ElderTree { onion, signers } => vec![CanopySource::Elder {
                onion: onion.clone(),
                signers: signers.clone(),
            }],
            Discovery::CanopyFile { path, signers } => vec![CanopySource::File {
                path: path.clone(),
                signers: signers.clone(),
            }],
            Discovery::Onions(_) | Discovery::PlainTcp(_) => Vec::new(),
        }
    }

    /// Past `canopy_max_stale` on a last-known-good copy: report it and stop routing on it.
    fn canopy_is_stale(&self, from_cache: bool, age_seconds: u64) -> bool {
        from_cache && age_seconds > self.config.canopy_max_stale.as_secs()
    }

    fn signers(&self) -> Option<String> {
        let sources = self.sources();
        (!sources.is_empty()).then(|| {
            sources
                .iter()
                .map(|source| source.signers().to_string())
                .collect::<Vec<_>>()
                .join(";")
        })
    }

    fn canopy_cache_path(&self, source: &CanopySource, only: bool) -> Option<PathBuf> {
        if let Some(path) = &self.config.canopy_cache {
            // An explicit file holds one canopy; with several Elders it holds the first one's.
            return only.then(|| path.clone());
        }
        let dir = self.config.cache_dir.as_ref()?;
        // One file per pinned signer set, so switching networks or Elders never trips a rollback
        // floor that belongs to another directory.
        let digest = <sha2::Sha256 as sha2::Digest>::digest(source.signers().as_bytes());
        Some(dir.join(format!("canopy-{}.json", &hex::encode(digest)[..16])))
    }

    async fn fetch_canopy_raw(&self, source: &CanopySource) -> Result<String, String> {
        match source {
            CanopySource::Elder { onion, .. } => self.fetch_over_tor(onion).await,
            CanopySource::File { path, .. } => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::read_to_string(&path)
                        .map_err(|e| format!("read {}: {e}", path.display()))
                })
                .await
                .map_err(|e| e.to_string())?
            }
        }
    }

    async fn fetch_over_tor(&self, elder: &str) -> Result<String, String> {
        self.fetch_elder(elder, "/directory").await
    }

    /// One HTTP GET of `path` from an Elder Tree over Tor, body as text. Public for `doctor`.
    pub async fn fetch_elder(&self, elder: &str, path: &str) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (onion, port) = parse_onion_addr(elder, 80)?;
        let host = format!("{onion}.onion");
        let timeout = self.config.tor_timeout;
        tokio::time::timeout(timeout, async {
            tracing::debug!(elder = %host, "fetching canopy over Tor");
            let gateway = Gateway::Onion {
                onion: onion.clone(),
                port,
            };
            let mut stream = self
                .transport
                .open(&gateway)
                .await
                .map_err(|e| format!("connect Elder Tree {host}:{port}: {e}"))?;
            stream
                .write_all(dircache::http_get_request(&host, path).as_bytes())
                .await
                .map_err(|e| format!("write request: {e}"))?;
            stream.flush().await.map_err(|e| format!("flush: {e}"))?;
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| format!("read response: {e}"))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > dircache::MAX_HTTP_RESP {
                    return Err(format!(
                        "Elder Tree response exceeded {} bytes",
                        dircache::MAX_HTTP_RESP
                    ));
                }
            }
            dircache::parse_http_body(&buf)
        })
        .await
        .map_err(|_| format!("Elder Tree exchange timed out after {}s", timeout.as_secs()))?
    }

    /// Fetch every canopy source concurrently, verify each against its own signer, and install
    /// the union of the verified directories. A source that fails falls back to its own
    /// last-known-good copy; the refresh fails only when no source yields a verified canopy.
    pub async fn refresh_canopy(&self) -> Result<(), Error> {
        let sources = self.sources();
        if sources.is_empty() {
            return Ok(());
        }
        self.counters
            .canopy_refreshes
            .fetch_add(1, Ordering::Relaxed);
        let only = sources.len() == 1;
        let fetches = sources.iter().map(|source| async move {
            let fresh = self.fetch_canopy_raw(source).await;
            let cache_path = self.canopy_cache_path(source, only);
            let signers = source.signers().to_string();
            let max_age = self.config.max_age;
            let outcome = tokio::task::spawn_blocking(move || {
                dircache::resolve_directory(
                    fresh,
                    cache_path.as_deref(),
                    &signers,
                    max_age,
                    now_ms(),
                )
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|result| result);
            // The incident feed rides behind the directory: advice only, never a reason to fail
            // the refresh, verified under the same pinned signer(s).
            let incidents = match (&outcome, source) {
                (Ok(_), CanopySource::Elder { onion, signers }) => {
                    match self.fetch_elder(onion, "/incidents").await {
                        Ok(raw) => match crate::incidents::parse_and_verify(&raw, signers, now_secs()) {
                            Ok(feed) => feed.active(now_secs()).into_iter().cloned().collect(),
                            Err(error) => {
                                tracing::debug!(elder = %onion, %error, "incident feed ignored");
                                Vec::new()
                            }
                        },
                        Err(error) => {
                            tracing::debug!(elder = %onion, %error, "no incident feed");
                            Vec::new()
                        }
                    }
                }
                _ => Vec::new(),
            };
            (source.label(), source.signers().to_string(), outcome, incidents)
        });
        let results = futures::future::join_all(fetches).await;

        let mut accepted = Vec::new();
        let mut errors = Vec::new();
        let mut incidents: Vec<crate::incidents::Incident> = Vec::new();
        {
            let mut floors = self.canopy_floors.lock().unwrap_or_else(|p| p.into_inner());
            for (label, signers, outcome, feed) in results {
                for incident in feed {
                    if !incidents.iter().any(|known| known.id == incident.id) {
                        incidents.push(incident);
                    }
                }
                match outcome {
                    Ok(outcome) => {
                        // In-memory rollback floor per source, for when no LKG file is configured.
                        let floor = floors.get(&signers).copied().unwrap_or(0);
                        if outcome.dir.issued < floor {
                            errors.push(format!(
                                "{label}: canopy rollback rejected: issued {} < in-use {floor}",
                                outcome.dir.issued
                            ));
                            continue;
                        }
                        floors.insert(signers, outcome.dir.issued);
                        if outcome.source == dircache::Source::Cache {
                            errors.push(format!(
                                "{label}: {}",
                                outcome
                                    .fresh_error
                                    .clone()
                                    .unwrap_or_else(|| "fresh unavailable".into())
                            ));
                        }
                        accepted.push(outcome);
                    }
                    Err(error) => errors.push(format!("{label}: {error}")),
                }
            }
        }
        if accepted.is_empty() {
            self.counters
                .canopy_refresh_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Canopy(errors.join("; ")));
        }
        let from_cache = accepted
            .iter()
            .all(|outcome| outcome.source == dircache::Source::Cache);
        if !errors.is_empty() {
            self.counters
                .canopy_refresh_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(problems = %errors.join("; "), "some canopy sources fell back or failed");
        }
        let (dir, demo) = merge_canopies(accepted);
        if let Ok(mut health) = self.health.lock() {
            health.1 = dir.gateways.iter().map(|g| g.onion.clone()).collect();
        }
        tracing::info!(
            nodes = dir.gateways.len(),
            issued = dir.issued,
            sources = sources.len(),
            from_cache,
            "canopy verified"
        );
        *self.canopy.lock().await = Some(CanopySnapshot {
            dir,
            demo,
            fetched_at: Instant::now(),
            from_cache,
            fresh_error: (!errors.is_empty()).then(|| errors.join("; ")),
            incidents,
        });
        Ok(())
    }

    async fn canopy_snapshot(&self) -> Result<CanopySnapshot, Error> {
        {
            let guard = self.canopy.lock().await;
            if let Some(snapshot) = guard.as_ref() {
                if snapshot.fetched_at.elapsed() < self.config.canopy_refresh * 2 {
                    return Ok(snapshot.clone());
                }
            }
        }
        match self.refresh_canopy().await {
            Ok(()) => {}
            Err(error) => {
                // Keep serving the canopy already in memory; it was verified.
                let guard = self.canopy.lock().await;
                if let Some(snapshot) = guard.as_ref() {
                    tracing::warn!(%error, "canopy refresh failed; keeping the verified canopy in use");
                    return Ok(snapshot.clone());
                }
                return Err(error);
            }
        }
        self.canopy
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::Canopy("no canopy".into()))
    }

    /// Keep the canopy fresh in the background. The task ends when the client is dropped.
    pub fn spawn_canopy_refresh(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.signers()?;
        let weak = Arc::downgrade(self);
        let base = self.config.canopy_refresh;
        Some(tokio::spawn(async move {
            loop {
                // Jitter by up to 20% so a fleet of clients never refreshes in lockstep.
                let jitter = base.mul_f64(0.2 * (now_ms() % 1000) as f64 / 1000.0);
                tokio::time::sleep(base + jitter).await;
                let Some(client) = weak.upgrade() else { return };
                if let Err(error) = client.refresh_canopy().await {
                    tracing::warn!(%error, "background canopy refresh failed");
                }
            }
        }))
    }

    // --------------------------------------------------------------- members

    fn member_key(&self, demo: Option<&DemoAdvert>) -> Result<Option<MemberKey>, Error> {
        let contract = match &self.config.members {
            Members::File(_) => return Ok(None),
            Members::Contract(address) => address.clone(),
            Members::Auto => {
                if self.config.leaf_source.as_deref() == Some("demo") {
                    demo.map(|d| d.contract.clone()).ok_or_else(|| {
                        Error::Config(
                            "leaf source demo, but the canopy advertises no demo set".into(),
                        )
                    })?
                } else if let Some(profile) = &self.profile {
                    profile.contract.clone()
                } else {
                    return Err(Error::Config(
                        "no member source: pass a members file or a contract".into(),
                    ));
                }
            }
        };
        Ok(Some(MemberKey {
            contract,
            rpc_urls: self
                .config
                .rpc_url
                .as_deref()
                .map(|list| {
                    list.split(',')
                        .map(str::trim)
                        .filter(|url| !url.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .filter(|urls| !urls.is_empty())
                .or_else(|| self.profile.as_ref().map(|p| p.rpc_urls.clone()))
                .unwrap_or_else(|| vec!["http://127.0.0.1:8545".into()]),
            from_block: self
                .config
                .from_block
                .or_else(|| self.profile.as_ref().map(|p| p.deploy_block))
                .unwrap_or(0),
            block_tag: self.block_tag(),
        }))
    }

    async fn fetch_members(&self, key: &MemberKey) -> Result<Arc<DiscoveredMembers>, Error> {
        self.counters.member_fetches.fetch_add(1, Ordering::Relaxed);
        let rln_identifier = self.config.rln_identifier.parse::<u64>().unwrap_or(1);
        let request = key.clone();
        let result = tokio::task::spawn_blocking(move || {
            // ADR 0012: try every RPC endpoint in the record's order; the first complete member set
            // wins. A pool that drops history fails closed in `leaves` and the next endpoint is tried.
            let mut failures = Vec::new();
            for rpc_url in &request.rpc_urls {
                match leaves::fetch_members(
                    rpc_url,
                    &request.contract,
                    request.from_block,
                    &request.block_tag,
                    rln_identifier,
                ) {
                    Ok(set) => return Ok(set),
                    Err(error) => {
                        if request.rpc_urls.len() > 1 {
                            tracing::warn!(rpc = %rpc_url, %error, "member set fetch failed; trying the next RPC");
                        }
                        failures.push(format!("{rpc_url}: {error}"));
                    }
                }
            }
            Err(failures.join("; "))
        })
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;
        match result {
            Ok(set) => {
                tracing::debug!(
                    contract = %key.contract,
                    tag = %key.block_tag,
                    live = set.live_count,
                    root = %set.root,
                    "member set fetched"
                );
                Ok(Arc::new(set))
            }
            Err(error) => {
                self.counters
                    .member_fetch_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(Error::Rpc(error))
            }
        }
    }

    async fn members_for(
        &self,
        key: &MemberKey,
        max_age: Duration,
    ) -> Result<Arc<DiscoveredMembers>, Error> {
        {
            let cache = self.members.lock().await;
            if let Some(snapshot) = cache.get(key) {
                if snapshot.fetched_at.elapsed() < max_age {
                    return Ok(Arc::clone(&snapshot.set));
                }
            }
        }
        let set = self.fetch_members(key).await?;
        self.members.lock().await.insert(
            key.clone(),
            MemberSnapshot {
                set: Arc::clone(&set),
                fetched_at: Instant::now(),
            },
        );
        Ok(set)
    }

    async fn forget_members(&self) {
        self.members.lock().await.clear();
    }

    /// The ordered member set to prove against, checking the leaf is in it. A leaf missing from a
    /// finalized read is re-checked at `latest` to tell "not finalized yet" from "not admitted".
    async fn admitted_members(
        &self,
        leaf: &str,
        demo: Option<&DemoAdvert>,
    ) -> Result<(Vec<String>, String), Error> {
        let Some(key) = self.member_key(demo)? else {
            let Members::File(path) = &self.config.members else {
                unreachable!()
            };
            let raw = std::fs::read_to_string(path)
                .map_err(|e| Error::Config(format!("read members {}: {e}", path.display())))?;
            let file: MembersFile = serde_json::from_str(&raw).map_err(|e| {
                Error::Config(format!("members {} is not valid: {e}", path.display()))
            })?;
            if !file.members.iter().any(|member| member == leaf) {
                return Err(Error::NotAdmitted {
                    leaf: short(leaf),
                    set: path.display().to_string(),
                    live: file.members.iter().filter(|m| m.as_str() != "0").count(),
                });
            }
            return Ok((file.members, path.display().to_string()));
        };
        let mut set = self.members_for(&key, self.config.member_refresh).await?;
        if !set.document.members.iter().any(|member| member == leaf) {
            // A registration may have just finalized: re-read once unless the copy is brand new.
            set = self.members_for(&key, Duration::from_secs(5)).await?;
        }
        if set.document.members.iter().any(|member| member == leaf) {
            return Ok((set.document.members.clone(), key.contract));
        }
        if key.block_tag == "finalized" {
            let latest = MemberKey {
                block_tag: "latest".into(),
                ..key.clone()
            };
            if let Ok(pending) = self.members_for(&latest, Duration::from_secs(5)).await {
                if pending.document.members.iter().any(|member| member == leaf) {
                    return Err(Error::NotFinalized {
                        leaf: short(leaf),
                        set: key.contract,
                    });
                }
            }
        }
        Err(Error::NotAdmitted {
            leaf: short(leaf),
            set: key.contract,
            live: set.live_count,
        })
    }

    // ------------------------------------------------------------- selection

    /// Candidates for one tunnel, in dial order.
    async fn candidates(
        &self,
        port: u16,
    ) -> Result<(Vec<Gateway>, Option<Vec<String>>, Option<DemoAdvert>), Error> {
        match &self.config.discovery {
            Discovery::PlainTcp(list) => {
                return Ok((
                    list.iter()
                        .map(|address| Gateway::PlainTcp {
                            address: address.clone(),
                        })
                        .collect(),
                    None,
                    None,
                ))
            }
            Discovery::Onions(list) => {
                let mut gateways = Vec::with_capacity(list.len());
                for address in list {
                    let (onion, port) = parse_onion_addr(address, 80).map_err(Error::Config)?;
                    gateways.push(Gateway::Onion { onion, port });
                }
                return Ok((gateways, None, None));
            }
            _ => {}
        }
        let snapshot = self.canopy_snapshot().await?;
        let age = now_secs().saturating_sub(snapshot.dir.issued);
        if self.canopy_is_stale(snapshot.from_cache, age) {
            return Err(Error::Canopy(format!(
                "canopy stale: the last verified directory is {age}s old (cap {}s) and no Elder Tree can be reached; refusing to route on it",
                self.config.canopy_max_stale.as_secs()
            )));
        }
        let demo = snapshot.demo.clone();
        let mut dir = snapshot.dir;
        if let Ok(mut health) = self.health.lock() {
            let (cache, _) = &mut *health;
            health::seed(&mut dir, cache, now_ms());
        }
        let fleet = dir.gateways.clone();
        let admission = self.admission();
        if admission.is_active() {
            capability::filter_by_admission_with_demo(
                &mut dir.gateways,
                &admission,
                demo.as_ref().map(|d| d.gateways.as_slice()),
            );
            if dir.gateways.is_empty() {
                return Err(Error::NoEligibleNode(capability::admission_refusal(
                    &admission, &fleet,
                )));
            }
        }
        if let Some(profile) = &self.profile {
            let before = dir.gateways.len();
            filter_rates(&mut dir.gateways, &profile.rate_policy);
            if dir.gateways.is_empty() {
                return Err(Error::NoEligibleNode(format!(
                    "none of {before} admitted node(s) signs the network's rate policy"
                )));
            }
            // A node that advertises its admission sets and does not list ours would refuse
            // every proof `wrong-group-root` (dogfood #234: a staging identity against nodes on
            // the production set). Drop it here, so status says so instead of "ready". A node
            // without `sets` (older heartbeat) stays eligible, as before.
            let ours = profile.contract.to_ascii_lowercase();
            let before = dir.gateways.len();
            let theirs: Vec<String> = dir
                .gateways
                .iter()
                .filter_map(|g| {
                    g.caps
                        .as_ref()
                        .and_then(|c| shadenet_proto::canonical_caps(c).sets)
                })
                .flatten()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            dir.gateways.retain(|g| {
                g.caps
                    .as_ref()
                    .and_then(|c| shadenet_proto::canonical_caps(c).sets)
                    .is_none_or(|sets| sets.contains(&ours))
            });
            if dir.gateways.is_empty() {
                return Err(Error::NoEligibleNode(format!(
                    "none of {before} node(s) reads this record's admission set {}: they advertise {}",
                    profile.contract,
                    if theirs.is_empty() { "no set".to_string() } else { theirs.join(", ") }
                )));
            }
        }
        let mut requirement = Requirement {
            port: Some(u64::from(port)),
            ..self.config.requirement.clone()
        };
        if requirement.proto.is_none() && requirement.region.is_none() && port == 443 {
            // 443 is every node's floor; keep the historical no-filter path byte-identical.
            requirement.port = None;
        }
        if requirement.is_active() {
            let before = dir.gateways.clone();
            capability::filter_by_capability(&mut dir.gateways, &requirement);
            if dir.gateways.is_empty() {
                if requirement.proto.is_none() && requirement.region.is_none() {
                    return Err(Error::PortNotAllowed {
                        port,
                        allowed: capability::describe_fleet_ports(&before),
                    });
                }
                return Err(Error::NoEligibleNode(format!(
                    "no node meets {}",
                    requirement.describe()
                )));
            }
        }
        let mut rng = mulberry32(now_ms() as u32);
        let order: Vec<shadenet_proto::GatewayEntry> = if self.config.rotation_spread {
            let mut state = self
                .rotation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            spread_selection_order(&dir, &mut state, &mut rng)
                .into_iter()
                .cloned()
                .collect()
        } else {
            selection_order(&dir, &mut rng)
                .into_iter()
                .cloned()
                .collect()
        };
        if order.is_empty() {
            return Err(Error::NoEligibleNode("the canopy lists no nodes".into()));
        }
        let artifacts = order.iter().find_map(|g| {
            g.caps
                .as_ref()
                .and_then(|c| shadenet_proto::canonical_caps(c).artifacts)
                .filter(|a| !a.is_empty())
        });
        let mut gateways = Vec::with_capacity(order.len());
        for entry in &order {
            let (onion, _) = parse_onion_addr(&entry.onion, 80).map_err(Error::Canopy)?;
            gateways.push(Gateway::Onion { onion, port: 80 });
        }
        Ok((gateways, artifacts, demo))
    }

    async fn client_artifact(&self) -> Result<String, Error> {
        self.artifact
            .get_or_try_init(|| async {
                match &self.config.circuits_dir {
                    None => {
                        let checked =
                            tokio::task::spawn_blocking(shadenet_rln::artifacts::verify_embedded)
                                .await
                                .map_err(|e| Error::Internal(e.to_string()))?
                                .map_err(|e| Error::Artifact(e.to_string()))?;
                        tracing::info!(
                            artifact = %checked.artifact_id,
                            trust = %checked.trust,
                            provenance = %checked.provenance,
                            "embedded artifacts verified against the zk-artifacts lock"
                        );
                        Ok(checked.artifact_id)
                    }
                    Some(dir) => {
                        let path = dir.join("verification_key.json");
                        let bytes = std::fs::read(&path).map_err(|e| {
                            Error::Artifact(format!("read {}: {e}", path.display()))
                        })?;
                        Ok(shadenet_proto::artifact_id_of("rln", &bytes))
                    }
                }
            })
            .await
            .cloned()
    }

    fn report_health(&self, attempts: &[transport::Attempt]) {
        let Ok(mut health) = self.health.lock() else {
            return;
        };
        let (cache, known) = &mut *health;
        let mut changed = false;
        for attempt in attempts {
            if !attempt.dial_succeeded {
                tracing::warn!(
                    "candidate {} failed ({}); rotating",
                    attempt.gateway.label(),
                    attempt
                        .error
                        .as_deref()
                        .unwrap_or("unknown transport error")
                );
            }
            // Only canopy onions are remembered; an explicit address is never written to disk.
            if let Gateway::Onion { onion, .. } = &attempt.gateway {
                let full = format!("{}.onion", onion.trim_end_matches(".onion"));
                changed |= known.contains(&full);
                health::update(
                    cache,
                    known,
                    &full,
                    attempt.dial_succeeded,
                    attempt.latency_ms,
                    now_ms(),
                );
            }
        }
        if changed {
            if let Some(path) = health_path(&self.config) {
                let mut snapshot = cache.clone();
                std::thread::spawn(move || {
                    health::save(Some(&path), &mut snapshot);
                });
            }
        }
    }

    // ---------------------------------------------------------------- tunnel

    /// Open a proof-gated tunnel to `target` (`host:port`).
    ///
    /// With [`Config::queue_max_wait`] set, a spent budget holds the request for the next epoch
    /// (up to that long) instead of failing with `budget_exhausted`; see [`Client::connect_queued`].
    pub async fn connect(&self, target: &str) -> Result<Tunnel, Error> {
        match self.config.queue_max_wait {
            Some(max_wait) => self.connect_queued(target, max_wait).await,
            None => self.connect_once(target).await,
        }
    }

    /// Wait until the budget can open one more tunnel, for at most `max_wait` (ADR 0013).
    ///
    /// Returns how long it waited (zero when a slot or ticket was free at once). While waiting
    /// the request counts in [`Status::queue`]. It fails with `budget_exhausted` when the wait
    /// would exceed `max_wait`; that error's `retry_after` is the queue-aware ETA. Callers that
    /// hold resources a queued request should not (the proxy's setup permits) wait here first and
    /// connect after.
    pub async fn wait_for_budget(&self, max_wait: Duration) -> Result<Duration, Error> {
        let started = Instant::now();
        let mut queued = false;
        let mut stagger = 0;
        loop {
            let budget = self.budget_snapshot();
            if budget.available_now() > 0 {
                if queued {
                    self.queue.depth.fetch_sub(1, Ordering::Relaxed);
                    let waited = started.elapsed();
                    self.queue
                        .waited_ms_total
                        .fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
                    return Ok(waited);
                }
                return Ok(Duration::ZERO);
            }
            let position = if queued {
                self.queue.depth.load(Ordering::Relaxed).saturating_sub(1)
            } else {
                self.queue.depth.load(Ordering::Relaxed)
            };
            let boundary = Duration::from_secs(budget.resets_in_seconds.max(1));
            let eta = Duration::from_secs(
                scheduler::queue_eta_seconds(&budget, position).max(boundary.as_secs()),
            );
            if started.elapsed() + boundary > max_wait {
                if queued {
                    self.queue.depth.fetch_sub(1, Ordering::Relaxed);
                }
                let error = Error::BudgetExhausted {
                    detail: format!(
                        "used {}/{} tunnels in epoch {}; {position} request(s) queued ahead, the wait would exceed {}s",
                        budget.tier.saturating_sub(budget.slots_left),
                        budget.tier,
                        self.current_epoch(),
                        max_wait.as_secs()
                    ),
                    retry_after: eta,
                };
                self.record_error(&error);
                return Err(error);
            }
            if !queued {
                queued = true;
                self.queue.depth.fetch_add(1, Ordering::Relaxed);
                self.queue.queued_total.fetch_add(1, Ordering::Relaxed);
                stagger = self.queue.seq.fetch_add(1, Ordering::Relaxed) % 64;
                tracing::info!(
                    position,
                    eta_secs = eta.as_secs(),
                    "budget spent; queued for the next epoch"
                );
            }
            // Wake just past the boundary, staggered by arrival so slots go out in order.
            tokio::time::sleep(boundary + Duration::from_millis(100 + 25 * stagger)).await;
        }
    }

    /// Open a tunnel, holding the request while the epoch budget is spent (ADR 0013): see
    /// [`Client::wait_for_budget`]. A request that loses the race for the last slot after its
    /// wait goes back to waiting, within the same `max_wait`.
    pub async fn connect_queued(&self, target: &str, max_wait: Duration) -> Result<Tunnel, Error> {
        let started = Instant::now();
        let mut waited = Duration::ZERO;
        loop {
            let remaining = max_wait.saturating_sub(started.elapsed());
            waited += self.wait_for_budget(remaining).await?;
            match self.connect_once(target).await {
                Ok(mut tunnel) => {
                    tunnel.waited = waited;
                    if tunnel.waited >= Duration::from_secs(1) {
                        tracing::info!(%target, waited_ms = tunnel.waited.as_millis() as u64, "queued tunnel opened");
                    }
                    return Ok(tunnel);
                }
                Err(Error::BudgetExhausted { .. }) if started.elapsed() < max_wait => {
                    // Lost the race for the last slot of the epoch: wait for the next one.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// One attempt: no queueing. A node that refuses for an `upstream:*` reason (it could not
    /// reach the destination), or that could not be reached at all when it was the only
    /// candidate (a session book binds the proof to one node), is retried once on another node
    /// when the budget allows and [`Config::retry_other_node`] is on. The proof is never
    /// replayed: the retry spends a new ticket or slot, which is why it stops at one.
    async fn connect_once(&self, target: &str) -> Result<Tunnel, Error> {
        let mut result = self.connect_inner(target, None).await;
        let avoid = match &result {
            Err(Error::NodeRefused {
                gateway, reason, ..
            }) if reason.starts_with("upstream:") => {
                tracing::info!(%gateway, %reason, %target, "node could not reach the destination; trying another node once");
                Some(gateway.clone())
            }
            Err(Error::Transport(_)) => {
                let failed = self.last_failed_gateway.lock().ok().and_then(|g| g.clone());
                if let Some(gateway) = &failed {
                    tracing::info!(%gateway, %target, "node unreachable; trying another node once");
                }
                failed
            }
            _ => None,
        };
        if let Some(avoid) = avoid {
            if self.config.retry_other_node && self.budget_snapshot().available_now() > 0 {
                result = self.connect_inner(target, Some(&avoid)).await;
            }
        }
        match &result {
            Ok(_) => {
                self.counters.tunnels_opened.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => self.record_error(error),
        }
        result
    }

    async fn connect_inner(&self, target: &str, avoid: Option<&str>) -> Result<Tunnel, Error> {
        let port = target_port(target)?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Config("no identity configured".into()))?;
        if identity.secret.is_empty() {
            return Err(Error::Config(
                "the identity is passphrase-protected and was loaded without its passphrase; set SHADENET_PASSPHRASE_FILE".into(),
            ));
        }
        let (mut gateways, advertised, demo) = self.candidates(port).await?;
        if let Some(avoid) = avoid {
            gateways.retain(|g| g.label() != avoid);
            if gateways.is_empty() {
                return Err(Error::NoEligibleNode(format!(
                    "no node other than {avoid} is eligible"
                )));
            }
        }
        // Session tickets (ADR 0011): a live book at any candidate spends a ticket before any
        // proof; nothing here touches the slot cursor.
        if self.config.session_tickets {
            if let Some(tunnel) = self.session_spend(target, &gateways).await? {
                return Ok(tunnel);
            }
        }
        let (members, _set) = self.admitted_members(&identity.leaf, demo.as_ref()).await?;
        let limit = self.tier();
        if !(1..=crate::profile::MAX_LIMIT).contains(&limit) {
            return Err(Error::Config(format!(
                "tier {limit} is outside the RLN range"
            )));
        }
        let epoch = self.current_epoch();
        let ours = self.client_artifact().await?;
        let artifact =
            shadenet_proto::select_artifact(advertised.as_deref(), std::slice::from_ref(&ours))
                .map_err(|e| Error::Artifact(e.to_string()))?;
        // With session tickets on, the proof initializes a book at the first session-capable
        // candidate instead of buying one tunnel; the first ticket then opens this tunnel. A node
        // that answers `session-unsupported` (a canopy mid-roll, or a pinned onion whose record
        // predates H2) is remembered and this same call falls back to the v4 path at once.
        let mut allow_session = self.config.session_tickets;
        loop {
            let slots = match &self.config.slots {
                Slots::UnsafeForSlashingTest(message_id) => {
                    if *message_id >= limit {
                        return Err(Error::Config(format!(
                            "slot {message_id} is outside this tier (0..{limit})"
                        )));
                    }
                    transport::SlotPolicy::UnsafeForSlashingTest {
                        message_id: *message_id,
                    }
                }
                _ => transport::SlotPolicy::CrashSafe {
                    cursor: self
                        .slot_path(&identity.leaf)?
                        .ok_or_else(|| Error::Internal("no slot path".into()))?,
                },
            };
            let nonce = self.config.nonce.clone().unwrap_or_else(random_nonce);
            let session = if allow_session {
                self.session_candidate(&gateways).await
            } else {
                None
            };
            let candidates = match &session {
                Some((gateway, _)) => vec![gateway.clone()],
                None => gateways.clone(),
            };
            tracing::debug!(%target, epoch, limit, %artifact, candidates = candidates.len(), session = session.is_some(), "building RLN envelope");
            let request = transport::ConnectRequest {
                gateways: candidates,
                proof: transport::ProofRequest {
                    identity_secret: identity.secret.to_string(),
                    member_leaf: identity.leaf.clone(),
                    members: members.clone(),
                    target: target.to_string(),
                    nonce,
                    epoch,
                    rln_identifier: self.config.rln_identifier.clone(),
                    user_message_limit: limit,
                    circuits_dir: self
                        .config
                        .circuits_dir
                        .as_ref()
                        .map(|dir| dir.display().to_string()),
                },
                slots,
                artifact: artifact.clone(),
                session: None,
            };
            if let Some((gateway, class)) = session {
                // One book per node at a time (ADR 0013): concurrent tunnels wait for the first
                // initialization and then spend its tickets instead of each proving a book.
                let gate = self.session_init_gate.lock().await;
                if let Some(tunnel) = self.session_spend(target, &gateways).await? {
                    drop(gate);
                    return Ok(tunnel);
                }
                let outcome = self.session_init(target, gateway, class, request).await;
                drop(gate);
                match outcome {
                    Err(Error::NodeRefused {
                        gateway, reason, ..
                    }) if reason == "session-unsupported" => {
                        tracing::info!(%gateway, %target, "node has no session tickets; falling back to one proof per tunnel");
                        allow_session = false;
                        continue;
                    }
                    outcome => return outcome,
                }
            }
            let outcome = self.transport.connect(request).await;
            match &outcome {
                Ok(connected) => self.report_health(&connected.attempts),
                Err(transport::Error::GatewayRefused { attempts, .. })
                | Err(transport::Error::AllCandidatesFailed { attempts }) => {
                    self.report_health(attempts)
                }
                Err(_) => {}
            }
            return match outcome {
                Ok(connected) => {
                    let receipt = connected.ack.get("receipt").cloned();
                    tracing::info!(gateway = %connected.gateway.label(), %target, "tunnel accepted");
                    Ok(Tunnel {
                        stream: connected.stream,
                        early_data: connected.early_data,
                        gateway: connected.gateway.label(),
                        target: connected.proof.target,
                        nullifier: connected.proof.nullifier,
                        epoch,
                        receipt,
                        session: None,
                        waited: Duration::ZERO,
                    })
                }
                Err(error) => Err(self.map_transport_error(error).await),
            };
        }
    }

    // ---------------------------------------------------------------- session tickets

    /// The onion (no suffix) of a candidate, when it is an onion service.
    fn onion_of(gateway: &Gateway) -> Option<String> {
        match gateway {
            Gateway::Onion { onion, .. } => Some(onion.clone()),
            Gateway::PlainTcp { .. } => None,
        }
    }

    /// Candidates whose SIGNED caps advertise `session` with a class this client knows, each
    /// with the best such class (ADR 0013: `research-v2` over `research-v1`). A pinned onion
    /// (no canopy, no caps) is assumed to serve `research-v1` until it says
    /// `session-unsupported`.
    async fn session_capable(
        &self,
        gateways: &[Gateway],
    ) -> Vec<(Gateway, &'static shadenet_proto::session::ClassPolicy)> {
        use shadenet_proto::session::{preferred_class, ClassPolicy, RESEARCH_V1};
        let refused = self
            .session_refused
            .lock()
            .map(|set| set.clone())
            .unwrap_or_default();
        let advertised: Option<std::collections::HashMap<String, &'static ClassPolicy>> =
            match &self.config.discovery {
                Discovery::Onions(_) | Discovery::PlainTcp(_) => None,
                _ => {
                    let snapshot = match self.canopy_snapshot().await {
                        Ok(snapshot) => snapshot,
                        Err(_) => return Vec::new(),
                    };
                    Some(
                        snapshot
                            .dir
                            .gateways
                            .iter()
                            .filter_map(|g| {
                                let session = g
                                    .caps
                                    .as_ref()
                                    .and_then(|c| shadenet_proto::canonical_caps(c).session)?;
                                let class = preferred_class(&session.classes)?;
                                Some((g.onion.trim_end_matches(".onion").to_string(), class))
                            })
                            .collect(),
                    )
                }
            };
        gateways
            .iter()
            .filter_map(|g| {
                let onion = Self::onion_of(g)?;
                if refused.contains(&onion) {
                    return None;
                }
                let class = match &advertised {
                    Some(map) => *map.get(&onion)?,
                    None => &RESEARCH_V1,
                };
                Some((g.clone(), class))
            })
            .collect()
    }

    async fn session_candidate(
        &self,
        gateways: &[Gateway],
    ) -> Option<(Gateway, &'static shadenet_proto::session::ClassPolicy)> {
        self.session_capable(gateways).await.into_iter().next()
    }

    /// Spend a ticket from a live book at one of the candidates. `Ok(None)` means no usable
    /// book (or the book turned out to be gone): the caller proves as usual.
    async fn session_spend(
        &self,
        target: &str,
        gateways: &[Gateway],
    ) -> Result<Option<Tunnel>, Error> {
        let onions: Vec<String> = gateways.iter().filter_map(Self::onion_of).collect();
        let Some(ticket) = self.sessions.take(&onions) else {
            return Ok(None);
        };
        let gateway = gateways
            .iter()
            .find(|g| Self::onion_of(g).as_deref() == Some(ticket.onion.trim_end_matches(".onion")))
            .cloned()
            .ok_or_else(|| Error::Internal("ticket without its node".into()))?;
        let spend = transport::TicketSpend {
            ticket_book_digest: ticket.ticket_book_digest.clone(),
            index: ticket.index,
            secret: ticket.secret,
            request_nonce: ticket.request_nonce.clone(),
            target: target.to_string(),
        };
        match self.transport.spend_ticket(&gateway, spend).await {
            Ok(connected) => {
                self.report_health(&connected.attempts);
                tracing::info!(gateway = %connected.gateway.label(), %target, ticket = ticket.index, "ticket accepted");
                Ok(Some(Tunnel {
                    stream: connected.stream,
                    early_data: connected.early_data,
                    gateway: connected.gateway.label(),
                    target: target.to_string(),
                    nullifier: String::new(),
                    epoch: self.current_epoch(),
                    receipt: None,
                    session: Some(ticket.ticket_book_digest.clone()),
                    waited: Duration::ZERO,
                }))
            }
            Err(transport::Error::GatewayRefused { ack, attempts, .. }) => {
                self.report_health(&attempts);
                let reason = ack
                    .get("err")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                tracing::debug!(%reason, ticket = ticket.index, "ticket refused");
                if crate::session::refusal_drops_book(&reason) {
                    // The node no longer holds the book: a fresh proof opens a new one.
                    self.sessions.forget(&ticket.onion);
                    return Ok(None);
                }
                if crate::session::refusal_refunds_ticket(&reason) {
                    // The node refunded the ticket; the target itself is the problem.
                    self.sessions.refund(&ticket);
                    return Err(Error::NodeRefused {
                        gateway: gateway.label(),
                        reason,
                        ack,
                    });
                }
                // ticket-spent / mismatch / conflict: this ticket is lost; try the next one.
                Ok(None)
            }
            Err(transport::Error::AllCandidatesFailed { attempts }) => {
                self.report_health(&attempts);
                // The node was unreachable: the ticket is still unused on it.
                self.sessions.refund(&ticket);
                Err(self
                    .map_transport_error(transport::Error::AllCandidatesFailed { attempts })
                    .await)
            }
            Err(error) => Err(self.map_transport_error(error).await),
        }
    }

    /// Prove once to open a book of `class` at `gateway`, then spend its first ticket for
    /// `target`.
    async fn session_init(
        &self,
        target: &str,
        gateway: Gateway,
        class: &'static shadenet_proto::session::ClassPolicy,
        mut request: transport::ConnectRequest,
    ) -> Result<Tunnel, Error> {
        let onion = Self::onion_of(&gateway)
            .ok_or_else(|| Error::Internal("session node without an onion".into()))?;
        let pending = crate::session::PendingBook::draw(&onion, class).map_err(Error::Internal)?;
        request.session = Some(transport::SessionInit {
            class_id: class.class.to_string(),
            gateway: pending.onion.clone(),
            nonce: pending.nonce.clone(),
            commitments: pending.commitments.clone(),
            ticket_book_digest: pending.ticket_book_digest.clone(),
        });
        let outcome = self.transport.connect(request).await;
        match &outcome {
            Ok(connected) => self.report_health(&connected.attempts),
            Err(transport::Error::GatewayRefused { attempts, .. })
            | Err(transport::Error::AllCandidatesFailed { attempts }) => {
                self.report_health(attempts)
            }
            Err(_) => {}
        }
        match outcome {
            Ok(connected) => {
                let echo = connected.ack.get("session").cloned().unwrap_or_default();
                let digest_ok = echo
                    .get("ticketBookDigest")
                    .and_then(serde_json::Value::as_str)
                    == Some(pending.ticket_book_digest.as_str());
                let policy_ok = echo
                    .get("policy")
                    .map(|p| crate::session::policy_matches(p, class))
                    .unwrap_or(false);
                if !digest_ok || !policy_ok {
                    // Fail closed: a node that echoes another book or other limits is not trusted
                    // with this book. The slot is spent; the caller may try again.
                    return Err(Error::NodeRefused {
                        gateway: gateway.label(),
                        reason: "session-policy-mismatch".into(),
                        ack: Box::new(connected.ack),
                    });
                }
                tracing::info!(gateway = %gateway.label(), class = class.class, tickets = class.tickets, "session book opened");
                self.sessions.install(pending);
                drop(connected.stream);
                match self
                    .session_spend(target, std::slice::from_ref(&gateway))
                    .await?
                {
                    Some(tunnel) => Ok(tunnel),
                    None => Err(Error::NodeRefused {
                        gateway: gateway.label(),
                        reason: "session-lost".into(),
                        ack: Box::new(serde_json::Value::Null),
                    }),
                }
            }
            Err(transport::Error::GatewayRefused { ack, .. })
                if ack.get("err").and_then(serde_json::Value::as_str)
                    == Some("session-unsupported") =>
            {
                if let Ok(mut set) = self.session_refused.lock() {
                    set.insert(onion.clone());
                }
                Err(Error::NodeRefused {
                    gateway: gateway.label(),
                    reason: "session-unsupported".into(),
                    ack,
                })
            }
            Err(error) => Err(self.map_transport_error(error).await),
        }
    }

    /// Live session books as `(node, tickets left)`, for status.
    pub fn session_books(&self) -> Vec<(String, usize)> {
        self.sessions.summary()
    }

    // ---------------------------------------------------------------- budget and queue

    /// What the member can spend right now (ADR 0013). Reads the slot cursor without locking it.
    pub fn budget_snapshot(&self) -> Budget {
        let tier = self.tier();
        let epoch = self.current_epoch();
        let slots_used = self
            .identity
            .as_ref()
            .and_then(|identity| self.slot_path(&identity.leaf).ok().flatten())
            .and_then(|path| slot::peek(&path, epoch).ok())
            .unwrap_or(0);
        let class = &shadenet_proto::session::RESEARCH_V1;
        Budget {
            tier,
            epoch_seconds: self.epoch_seconds(),
            resets_in_seconds: self.resets_in().as_secs(),
            slots_left: tier.saturating_sub(slots_used),
            session_tickets: self.config.session_tickets,
            tickets_per_book: class.tickets,
            tickets_open: self
                .sessions
                .summary()
                .iter()
                .map(|(_, left)| *left as u64)
                .sum(),
        }
    }

    /// Requests held in the budget queue right now.
    pub fn queue_depth(&self) -> u64 {
        self.queue.depth.load(Ordering::Relaxed)
    }

    /// The queue as reported in [`Status`].
    pub fn queue_status(&self) -> QueueStatus {
        let budget = self.budget_snapshot();
        let depth = self.queue_depth();
        QueueStatus {
            enabled: self.config.queue_max_wait.is_some(),
            depth,
            max_wait_seconds: self.config.queue_max_wait.map(|d| d.as_secs()).unwrap_or(0),
            next_slot_in_seconds: scheduler::queue_eta_seconds(&budget, depth),
            capacity_per_epoch: budget.capacity_per_epoch(),
            available_now: budget.available_now(),
            queued_total: self.queue.queued_total.load(Ordering::Relaxed),
            waited_seconds_total: self.queue.waited_ms_total.load(Ordering::Relaxed) / 1000,
        }
    }

    /// Plan `requests` tunnels behind whatever is queued now.
    pub fn plan(&self, requests: u64) -> Plan {
        scheduler::plan(&self.budget_snapshot(), requests, self.queue_depth())
    }

    // ---------------------------------------------------------------- nodes

    /// Every eligible node with the health and latency this client has measured, in the order
    /// the next tunnel would try them.
    pub async fn nodes_status(&self) -> Vec<NodeStatus> {
        let Ok((gateways, _, _)) = self.candidates(443).await else {
            return Vec::new();
        };
        let dir_health: std::collections::HashMap<String, String> =
            match self.canopy_snapshot().await {
                Ok(snapshot) => snapshot
                    .dir
                    .gateways
                    .iter()
                    .map(|g| {
                        (
                            g.onion.trim_end_matches(".onion").to_string(),
                            g.health.clone(),
                        )
                    })
                    .collect(),
                Err(_) => std::collections::HashMap::new(),
            };
        let cache = self.health.lock().map(|h| h.0.clone()).unwrap_or_default();
        gateways
            .iter()
            .enumerate()
            .filter_map(|(index, gateway)| {
                let onion = Self::onion_of(gateway)?;
                let entry = cache
                    .get(&format!("{onion}.onion"))
                    .cloned()
                    .unwrap_or_default();
                Some(NodeStatus {
                    health: dir_health.get(&onion).cloned().unwrap_or_default(),
                    onion: format!("{onion}.onion"),
                    latency_ms: entry.latency_ms,
                    fails: entry.fails,
                    preferred: index == 0,
                })
            })
            .collect()
    }

    /// Keep circuits to the `count` best nodes warm: every `every`, open and close one stream
    /// to each, so the first tunnel after a quiet spell does not pay the full onion rendezvous
    /// (ADR 0013). The dials also measure latency for [`Status::nodes`]. Only onion nodes are
    /// warmed; plain-TCP test transports are left alone.
    pub fn spawn_warmer(
        self: &Arc<Self>,
        count: usize,
        every: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if count == 0
            || !matches!(
                self.config.discovery,
                Discovery::Network
                    | Discovery::ElderTree { .. }
                    | Discovery::CanopyFile { .. }
                    | Discovery::Onions(_)
            )
        {
            return None;
        }
        let weak = Arc::downgrade(self);
        Some(tokio::spawn(async move {
            // The first warm-up follows the canopy fetch; later ones pace at `every`.
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                let Some(client) = weak.upgrade() else { return };
                client.warm_nodes(count).await;
                drop(client);
                let jitter = every.mul_f64(0.2 * (now_ms() % 1000) as f64 / 1000.0);
                tokio::time::sleep(every + jitter).await;
            }
        }))
    }

    async fn warm_nodes(&self, count: usize) {
        let Ok((gateways, _, _)) = self.candidates(443).await else {
            return;
        };
        let mut attempts = Vec::new();
        for gateway in gateways
            .iter()
            .filter(|g| Self::onion_of(g).is_some())
            .take(count)
        {
            let started = Instant::now();
            let outcome =
                tokio::time::timeout(self.config.tor_timeout, self.transport.open(gateway)).await;
            let (ok, error) = match outcome {
                Ok(Ok(stream)) => {
                    drop(stream);
                    (true, None)
                }
                Ok(Err(error)) => (false, Some(error)),
                Err(_) => (false, Some("warm-up dial timed out".to_string())),
            };
            let latency = started.elapsed().as_secs_f64() * 1000.0;
            tracing::debug!(gateway = %gateway.label(), ok, latency_ms = latency as u64, "warm-up dial");
            attempts.push(transport::Attempt {
                gateway: gateway.clone(),
                dial_succeeded: ok,
                error,
                latency_ms: ok.then_some(latency),
            });
        }
        self.report_health(&attempts);
    }

    async fn map_transport_error(&self, error: transport::Error) -> Error {
        match error {
            transport::Error::NoGateways => Error::NoEligibleNode("no candidates".into()),
            transport::Error::Prove(e) => Error::Prove(e),
            transport::Error::Join(e) => Error::Internal(e),
            transport::Error::Slot(slot::Error::Exhausted { epoch, limit }) => {
                Error::BudgetExhausted {
                    detail: format!("used {limit}/{limit} tunnels in epoch {epoch}"),
                    retry_after: self.resets_in(),
                }
            }
            transport::Error::Slot(other) => Error::Slot(other.to_string()),
            transport::Error::UnsafeSlotOutOfRange { message_id, limit } => {
                Error::Config(format!("slot {message_id} is outside 0..{limit}"))
            }
            transport::Error::GatewayRefused {
                gateway, kind, ack, ..
            } => {
                if kind == transport::GatewayRefusalKind::PayloadLimit {
                    return Error::BudgetExhausted {
                        detail: "this slot's payload allowance is used up".into(),
                        retry_after: self.resets_in(),
                    };
                }
                let reason = ack
                    .get("err")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(no reason)")
                    .to_string();
                if reason.starts_with("wrong-group-root") {
                    // Our member set is older than the node's roots: fetch it again next time.
                    self.forget_members().await;
                }
                Error::NodeRefused {
                    gateway: gateway.label(),
                    reason,
                    ack,
                }
            }
            transport::Error::AllCandidatesFailed { attempts } => {
                // Only a single-candidate failure names a node worth avoiding on the retry:
                // with several candidates the transport already rotated through them.
                if let Ok(mut last) = self.last_failed_gateway.lock() {
                    *last = (attempts.len() == 1).then(|| attempts[0].gateway.label());
                }
                Error::Transport(format!(
                    "all {} candidate(s) failed; last: {}",
                    attempts.len(),
                    attempts
                        .last()
                        .and_then(|a| a.error.as_deref())
                        .unwrap_or("(none)")
                ))
            }
        }
    }

    // ---------------------------------------------------------------- status

    /// Admission, budget and canopy state. Refreshes a stale canopy or member set as needed.
    pub async fn status(&self) -> Status {
        let epoch_seconds = self.epoch_seconds();
        let epoch = self.current_epoch();
        let mut status = Status {
            version: crate::VERSION.into(),
            network: self.config.network.name.clone(),
            state: "ready".into(),
            admitted: None,
            finalized: None,
            leaf: self.identity.as_ref().map(|i| short(&i.leaf)),
            admission_set: None,
            tier: self.identity.as_ref().map(|_| self.tier()),
            epoch,
            epoch_seconds,
            epoch_resets_in_seconds: self.resets_in().as_secs(),
            slots_used: None,
            slots_left: None,
            canopy: CanopyStatus::default(),
            tor_ready: self.tor_bootstraps() > 0,
            last_error: self.last_error.lock().ok().and_then(|e| e.clone()),
            problems: Vec::new(),
            nodes: Vec::new(),
            queue: QueueStatus::default(),
            plan: None,
        };
        let mut demo = None;
        let mut incidents = Vec::new();
        if self.signers().is_some() {
            match self.canopy_snapshot().await {
                Ok(snapshot) => {
                    let eligible = match self.candidates(443).await {
                        Ok((gateways, _, _)) => gateways.len(),
                        Err(error) => {
                            status.canopy.error = Some(error.to_string());
                            0
                        }
                    };
                    let age = now_secs().saturating_sub(snapshot.dir.issued);
                    status.canopy = CanopyStatus {
                        nodes: snapshot.dir.gateways.len(),
                        eligible,
                        issued: Some(snapshot.dir.issued),
                        age_seconds: Some(age),
                        from_last_known_good: snapshot.from_cache,
                        stale: self.canopy_is_stale(snapshot.from_cache, age),
                        error: status.canopy.error.take().or(snapshot.fresh_error.clone()),
                    };
                    demo = snapshot.demo;
                    incidents = snapshot.incidents;
                    if eligible == 0 {
                        status.state = "degraded".into();
                    }
                    status.nodes = self.nodes_status().await;
                }
                Err(error) => {
                    status.canopy.error = Some(error.to_string());
                    status.state = "degraded".into();
                }
            }
        }
        status.tor_ready = self.tor_bootstraps() > 0;
        let Some(identity) = &self.identity else {
            status.state = "no_identity".into();
            status.problems = problems_for(&status, None, &incidents);
            return status;
        };
        let mut admission_error = None;
        match self.admitted_members(&identity.leaf, demo.as_ref()).await {
            Ok((_, set)) => {
                status.admitted = Some(true);
                status.finalized = Some(true);
                status.admission_set = Some(set);
            }
            Err(error @ Error::NotFinalized { .. }) => {
                if let Error::NotFinalized { set, .. } = &error {
                    status.admission_set = Some(set.clone());
                }
                status.admitted = Some(false);
                status.finalized = Some(false);
                status.state = "not_finalized".into();
                admission_error = Some(error);
            }
            Err(error @ Error::NotAdmitted { .. }) => {
                if let Error::NotAdmitted { set, .. } = &error {
                    status.admission_set = Some(set.clone());
                }
                status.admitted = Some(false);
                status.state = "not_admitted".into();
                admission_error = Some(error);
            }
            Err(error) => {
                status.state = "degraded".into();
                status.last_error = Some(error.to_json()["error"].clone());
                admission_error = Some(error);
            }
        }
        if let Ok(Some(path)) = self.slot_path(&identity.leaf) {
            if let Ok(used) = slot::peek(&path, epoch) {
                let tier = self.tier();
                status.slots_used = Some(used);
                status.slots_left = Some(tier.saturating_sub(used));
                if used >= tier && status.state == "ready" {
                    status.state = "budget_exhausted".into();
                }
            }
        }
        status.problems = problems_for(&status, admission_error.as_ref(), &incidents);
        status.queue = self.queue_status();
        status.plan = Some(self.plan(1));
        status
    }
}

/// Build the `problems[]` an agent reads before retrying: the state's cause and fix, canopy
/// sources that fell back, the last error, and the operators' open incidents (newest first).
fn problems_for(
    status: &Status,
    admission_error: Option<&Error>,
    incidents: &[crate::incidents::Incident],
) -> Vec<Problem> {
    let mut out = Vec::new();
    let plain = |kind: &str, code: &str, e: crate::error::Explanation| Problem {
        kind: kind.into(),
        code: code.into(),
        cause: e.cause,
        fix: e.fix,
        component: None,
        instance: None,
        since: None,
    };
    match status.state.as_str() {
        "ready" => {}
        "no_identity" => out.push(plain(
            "state",
            "no_identity",
            crate::error::Explanation {
                cause: "no identity file is configured, so there is nothing to prove with".into(),
                fix: "run `shadenet init`, or pass `--identity <file>` to the identity a sponsor gave you".into(),
            },
        )),
        "budget_exhausted" => out.push(plain(
            "state",
            "budget_exhausted",
            Error::BudgetExhausted {
                detail: format!(
                    "{} of {} slots used this epoch",
                    status.slots_used.unwrap_or_default(),
                    status.tier.unwrap_or_default()
                ),
                retry_after: Duration::from_secs(status.epoch_resets_in_seconds),
            }
            .explain(),
        )),
        state => {
            if let Some(error) = admission_error {
                out.push(plain("state", state, error.explain()));
            } else if state == "degraded" {
                out.push(plain(
                    "state",
                    "degraded",
                    crate::error::Explanation {
                        cause: status
                            .canopy
                            .error
                            .clone()
                            .unwrap_or_else(|| "no eligible node in the canopy".into()),
                        fix: "run `shadenet doctor`; it names the Elder, RPC or artifact mismatch".into(),
                    },
                ));
            }
        }
    }
    if status.canopy.from_last_known_good {
        out.push(plain(
            "canopy",
            "from_last_known_good",
            crate::error::Explanation {
                cause: format!(
                    "no Elder Tree answered over Tor; the client is using its last verified canopy ({}s old){}",
                    status.canopy.age_seconds.unwrap_or_default(),
                    status
                        .canopy
                        .error
                        .as_deref()
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default()
                ),
                fix: "tunnels still work against the cached nodes; if this persists for more than 15 minutes, check Tor with `shadenet doctor`".into(),
            },
        ));
    } else if let Some(error) = &status.canopy.error {
        if status.canopy.issued.is_some() {
            out.push(plain(
                "canopy",
                "partial",
                crate::error::Explanation {
                    cause: format!("one canopy source failed or fell back: {error}"),
                    fix: "nothing to do; the other Elder served a fresh canopy. Persistent: `shadenet doctor`".into(),
                },
            ));
        }
    }
    if let Some(last) = &status.last_error {
        let code = last["code"].as_str().unwrap_or("error");
        if !out.iter().any(|p| p.code == code) {
            out.push(Problem {
                kind: "last_error".into(),
                code: code.into(),
                cause: last["cause"].as_str().unwrap_or("").to_string(),
                fix: last["fix"].as_str().unwrap_or("").to_string(),
                component: None,
                instance: None,
                since: None,
            });
        }
    }
    let mut open: Vec<&crate::incidents::Incident> = incidents.iter().collect();
    open.sort_by_key(|i| std::cmp::Reverse(i.since));
    for incident in open {
        out.push(Problem {
            kind: "incident".into(),
            code: incident.id.clone(),
            cause: format!(
                "{} ({}): {}",
                incident.instance, incident.severity, incident.summary
            ),
            fix: match incident.component.as_str() {
                "elder" => "tunnels keep working from the cached canopy and the other Elder; nothing to do".into(),
                "node" => "the client skips a node that fails and picks another; expect one slow retry".into(),
                "rpc" => "member-set reads fall back to the next RPC in the record; `shadenet doctor --rpc` shows which".into(),
                _ => "operator-declared; retry later if requests fail".into(),
            },
            component: Some(incident.component.clone()),
            instance: Some(incident.instance.clone()),
            since: Some(incident.since),
        });
    }
    out
}

fn health_path(config: &Config) -> Option<PathBuf> {
    config
        .health_cache
        .clone()
        .or_else(|| config.cache_dir.as_ref().map(|dir| dir.join("health.json")))
}

fn filter_rates(
    gateways: &mut Vec<shadenet_proto::GatewayEntry>,
    expected: &shadenet_proto::CanonicalRate,
) {
    gateways.retain(|gateway| {
        gateway
            .caps
            .as_ref()
            .and_then(|caps| shadenet_proto::canonical_caps(caps).rate)
            .is_some_and(|actual| actual == *expected)
    });
}

fn short(leaf: &str) -> String {
    if leaf.len() > 12 {
        format!("{}..", &leaf[..12])
    } else {
        leaf.to_string()
    }
}

/// Split `host:port` and validate the port.
pub fn target_port(target: &str) -> Result<u16, Error> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| Error::Config(format!("target {target:?} must be host:port")))?;
    if host.is_empty() || target.len() > 512 {
        return Err(Error::Config(format!("target {target:?} has no host")));
    }
    port.parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| Error::Config(format!("target {target:?} has an invalid port")))
}

/// Parse `<addr[:port]>` into (onion without suffix, port).
pub fn parse_onion_addr(addr: &str, default_port: u16) -> Result<(String, u16), String> {
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (addr, default_port),
        },
        None => (addr, default_port),
    };
    let onion = host.trim_end_matches(".onion").to_string();
    if onion.is_empty() {
        return Err(format!("empty onion address in {addr:?}"));
    }
    Ok((onion, port))
}

fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6D2B_79F5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        (((t ^ (t >> 14)) as f64) / 4_294_967_296.0).fract()
    }
}

/// 16 bytes from the OS RNG as 32 hex characters (the JS client's `randomBytes(16)`).
fn random_nonce() -> String {
    let mut out = [0u8; 16];
    if getrandom::fill(&mut out).is_err() {
        // The nonce needs uniqueness, not secrecy. Fall back to time and a counter.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        out[..8].copy_from_slice(&now_ms().to_le_bytes());
        out[8..].copy_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    }
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_onions_parse_strictly() {
        assert_eq!(target_port("example.com:443").unwrap(), 443);
        assert!(target_port("example.com").is_err());
        assert!(target_port(":443").is_err());
        assert!(target_port("example.com:0").is_err());
        assert!(target_port("example.com:99999").is_err());
        assert_eq!(
            parse_onion_addr("abc.onion:8080", 80).unwrap(),
            ("abc".into(), 8080)
        );
        assert_eq!(parse_onion_addr("abc", 80).unwrap(), ("abc".into(), 80));
        assert!(parse_onion_addr(".onion", 80).is_err());
    }

    fn outcome(issued: u64, onions: &[&str]) -> dircache::LoadOutcome {
        dircache::LoadOutcome {
            dir: Directory {
                version: 1,
                issued,
                gateways: onions
                    .iter()
                    .map(|onion| shadenet_proto::GatewayEntry {
                        onion: onion.to_string(),
                        pubkey: String::new(),
                        weight: if issued > 100 { 7 } else { 1 },
                        health: "up".into(),
                        operator: None,
                        staked: None,
                        caps: None,
                        caps_sig: None,
                    })
                    .collect(),
                signer: None,
                signature: None,
                signers: None,
                signatures: None,
                threshold: None,
            },
            demo: None,
            source: dircache::Source::Fresh,
            fresh_error: None,
        }
    }

    #[test]
    fn canopies_merge_into_a_union_and_the_newest_entry_wins() {
        let (dir, _) = merge_canopies(vec![
            outcome(100, &["a.onion", "b.onion"]),
            outcome(200, &["b.onion", "c.onion"]),
        ]);
        let onions: Vec<_> = dir.gateways.iter().map(|g| g.onion.as_str()).collect();
        assert_eq!(onions, vec!["b.onion", "c.onion", "a.onion"]);
        assert_eq!(dir.issued, 200);
        // The shared node comes from the newer directory.
        assert_eq!(dir.gateways[0].weight, 7);
    }

    #[test]
    fn nonces_are_32_hex_and_distinct() {
        let a = random_nonce();
        let b = random_nonce();
        assert_eq!(a.len(), 32);
        assert!(hex::decode(&a).is_ok());
        assert_ne!(a, b);
    }
}
