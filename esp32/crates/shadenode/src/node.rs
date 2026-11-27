//! The node: accept a stream from the onion service, admit one envelope, relay one tunnel.
//!
//! Steps and refusal strings follow the reference node (`crates/shadenet-node/src/node.rs`)
//! so an unmodified client cannot tell the difference.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::mpsc::{channel, TryRecvError};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use microtor::cell::end_reason;
use microtor::circuit::Stream;
use microtor::hs::{Incoming, OnionService};
use microtor::netdir::now_unix;
use microtor::rt::{note_progress, spawn, timeout, yield_now};
use serde_json::Value;

use crate::egress::{parse_target, Dial, DialConfig, Policy, Target};
use crate::proto::{
    artifact_id_of, json_string, DEFAULT_PAYLOAD_BYTES_PER_SLOT, PROTO_MAX, PROTO_MIN,
};
use crate::rln::{members_root, VerifyingKey, BUILTIN_VKEY};
use crate::session::{self, Books};
use crate::spent::{slot_key, Admission, Budget, SpentSet};
use crate::verify::{pairing_refusal, Binding, PairingJob, Refusal, Verified, Verifier};

/// The onion virtual port clients dial.
pub const SERVICE_PORT: u16 = 80;
/// Roots listed in a `wrong-group-root` reply.
const MAX_ROOTS_IN_REPLY: usize = 16;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// RLN epoch length. The Sepolia deployment record says 60; a client pinned to a node with
    /// a members file assumes 120.
    pub epoch_seconds: u64,
    pub rln_identifier: u64,
    /// The invited member set: rate-commitment leaves in tree order.
    pub members: Vec<String>,
    /// Roots accepted in addition to the members root (for example one provisioned from a
    /// staking contract).
    pub extra_roots: Vec<String>,
    pub allow: String,
    pub deny: String,
    pub allow_private_targets: bool,
    /// Tunnels open at once. The reference default is 1024; a device sets a handful.
    pub max_conns: usize,
    pub max_conns_per_nullifier: usize,
    pub max_envelope_bytes: usize,
    pub envelope_timeout: Duration,
    pub replay_window_ms: u64,
    pub payload_bytes_per_slot: u64,
    pub idle_timeout: Duration,
    pub dns_timeout: Duration,
    /// Bytes per second across every tunnel, both directions; `None` is unlimited.
    pub bandwidth: Option<u64>,
    /// Nullifiers remembered at once (each lives two epochs).
    pub spent_capacity: usize,
    /// Stack for the proof-verification thread.
    pub verify_stack: usize,
    pub dial_stack: usize,
    pub ipv4_only: bool,
    /// Serve session tickets (one proof opens a book of six tunnels).
    pub session_tickets: bool,
    /// Live ticket books at once; zero is unlimited.
    pub session_max: usize,
    /// Longest a ticket stream may run.
    pub session_stream_max: Duration,
    /// Refuse proofs for the epoch the node booted in. The spent set lives in RAM, so without
    /// this a restart would forget which slots of the running epoch were already used.
    pub quarantine_boot_epoch: bool,
    /// Attach a signed liveness receipt to each tunnel acknowledgement.
    pub receipts: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            epoch_seconds: 60,
            rln_identifier: 1,
            members: Vec::new(),
            extra_roots: Vec::new(),
            allow: "*:443".into(),
            deny: String::new(),
            allow_private_targets: false,
            max_conns: 1024,
            max_conns_per_nullifier: 8,
            max_envelope_bytes: 65_536,
            envelope_timeout: Duration::from_secs(30),
            replay_window_ms: 5000,
            payload_bytes_per_slot: DEFAULT_PAYLOAD_BYTES_PER_SLOT,
            idle_timeout: Duration::from_secs(300),
            dns_timeout: Duration::from_secs(5),
            bandwidth: None,
            spent_capacity: 100_000,
            verify_stack: 512 * 1024,
            dial_stack: 256 * 1024,
            ipv4_only: false,
            session_tickets: true,
            session_max: 256,
            session_stream_max: Duration::from_secs(900),
            quarantine_boot_epoch: true,
            receipts: false,
        }
    }
}

impl NodeConfig {
    /// Limits sized for an ESP32 with no external RAM.
    pub fn for_small_device() -> Self {
        Self {
            max_conns: 4,
            max_conns_per_nullifier: 2,
            max_envelope_bytes: 8 * 1024,
            spent_capacity: 256,
            verify_stack: 32 * 1024,
            dial_stack: 8 * 1024,
            ipv4_only: true,
            session_max: 4,
            ..Self::default()
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct NodeStats {
    pub connections: u64,
    pub admitted: u64,
    pub refused: u64,
    pub tunnels_open: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub verify_ms_last: u64,
    pub over_spends: u64,
    pub sessions_opened: u64,
    pub tickets_spent: u64,
}

struct Bucket {
    rate: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate).min(self.rate);
        self.at = now;
    }
}

struct State {
    verifier: Verifier,
    roots: Vec<String>,
    /// The invited set's root and provisioned roots: accepted whatever the chain says.
    fixed_roots: Vec<String>,
    spent: SpentSet,
    budget: Budget,
    conns: usize,
    per_nullifier: HashMap<String, usize>,
    bucket: Option<Bucket>,
    books: Books,
    /// Drain asked for by the operator, and by the reputation canary; either one counts.
    draining: bool,
    canary_drain: bool,
    over_spends: Vec<OverSpend>,
    stats: NodeStats,
    last_sweep: Instant,
}

/// Two shares on one proof slot: enough to recover the member's identity secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverSpend {
    pub first: (String, String),
    pub second: (String, String),
}

#[derive(Clone)]
pub struct Node {
    config: Rc<NodeConfig>,
    policy: Rc<Policy>,
    service: OnionService,
    state: Rc<RefCell<State>>,
}

fn now_ms() -> u64 {
    // The spent set only needs a monotonic millisecond clock that agrees with itself.
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn refusal_line(err: &str, extras: &str) -> String {
    format!("{{\"ok\":false,\"err\":{}{extras}}}\n", json_string(err))
}

fn proto_extra() -> String {
    format!(",\"proto\":{{\"min\":{PROTO_MIN},\"max\":{PROTO_MAX}}}")
}

/// The version gate: only the integer 4 passes. A missing version is the legacy v3 shape.
fn version_gate(envelope: &Value) -> Result<(), String> {
    let repr = match envelope.get("v") {
        None | Some(Value::Null) => return Err("unsupported-version:3".into()),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(v) if (PROTO_MIN as i64..=PROTO_MAX as i64).contains(&v) => return Ok(()),
            Some(v) => return Err(format!("unsupported-version:{v}")),
            None => n.to_string(),
        },
        Some(Value::String(s)) => json_string(&s.chars().take(16).collect::<String>()),
        Some(Value::Bool(_)) => "boolean".into(),
        Some(_) => "object".into(),
    };
    Err(format!("bad-version:{repr}"))
}

impl Node {
    /// Build the node around an onion service. Parses the verification key and computes the
    /// members root, so it can take a moment on a slow CPU.
    pub fn new(service: OnionService, config: NodeConfig) -> Result<Self, String> {
        // The key's one pairing needs more stack than a device's main task has.
        let key = std::thread::Builder::new()
            .name("vkey".into())
            .stack_size(config.verify_stack)
            .spawn(VerifyingKey::builtin)
            .map_err(|e| format!("could not start the key thread: {e}"))?
            .join()
            .map_err(|_| "verification key thread panicked".to_string())??;
        let key = Arc::new(key);
        let artifact_id = artifact_id_of("rln", BUILTIN_VKEY);
        let mut roots = config.extra_roots.clone();
        if !config.members.is_empty() {
            roots.push(members_root(config.rln_identifier, &config.members)?);
        }
        let policy = Policy::new(&config.allow, &config.deny);
        let mut state = State {
            verifier: Verifier::new(
                key,
                artifact_id,
                config.epoch_seconds,
                config.rln_identifier,
            ),
            fixed_roots: roots.clone(),
            roots,
            spent: SpentSet::new(
                config.epoch_seconds,
                config.replay_window_ms,
                config.spent_capacity,
            ),
            budget: Budget::new(config.payload_bytes_per_slot, config.epoch_seconds),
            conns: 0,
            per_nullifier: HashMap::new(),
            bucket: config.bandwidth.map(|rate| Bucket {
                rate: rate as f64,
                tokens: rate as f64,
                at: Instant::now(),
            }),
            books: Books::new(config.session_max),
            draining: false,
            canary_drain: false,
            over_spends: Vec::new(),
            stats: NodeStats::default(),
            last_sweep: Instant::now(),
        };
        if config.quarantine_boot_epoch {
            let boot_epoch = state.verifier.current_epoch(now_unix());
            state.verifier.min_epoch = boot_epoch + 1;
        }
        Ok(Self {
            config: Rc::new(config),
            policy: Rc::new(policy),
            service,
            state: Rc::new(RefCell::new(state)),
        })
    }

    pub fn service(&self) -> &OnionService {
        &self.service
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn stats(&self) -> NodeStats {
        self.state.borrow().stats.clone()
    }

    pub fn roots(&self) -> Vec<String> {
        self.state.borrow().roots.clone()
    }

    /// Replace the roots that come from on-chain sets; the invited set's root and any
    /// provisioned roots stay. Returns whether the accepted set changed.
    pub fn set_chain_roots(&self, chain: Vec<String>) -> bool {
        let mut s = self.state.borrow_mut();
        let mut roots = s.fixed_roots.clone();
        for root in chain {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        let changed = roots != s.roots;
        s.roots = roots;
        changed
    }

    /// Whether the node asks clients to prefer other nodes (advertised as `draining`).
    pub fn is_draining(&self) -> bool {
        let s = self.state.borrow();
        s.draining || s.canary_drain
    }

    /// The operator's drain switch.
    pub fn set_draining(&self, draining: bool) {
        self.state.borrow_mut().draining = draining;
    }

    /// The canary's drain; it never touches the operator's.
    pub fn set_canary_drain(&self, draining: bool) {
        self.state.borrow_mut().canary_drain = draining;
    }

    /// Over-spends seen since the last call, for whoever submits slashes.
    pub fn take_over_spends(&self) -> Vec<OverSpend> {
        core::mem::take(&mut self.state.borrow_mut().over_spends)
    }

    pub fn artifact_ids(&self) -> Vec<String> {
        self.state.borrow().verifier.artifact_ids()
    }

    /// Start the onion service and the accept loop.
    pub fn start(&self) {
        self.service.start();
        if self.config.session_tickets {
            let node = self.clone();
            spawn(async move {
                loop {
                    microtor::rt::sleep(Duration::from_millis(250)).await;
                    node.state.borrow_mut().books.sweep(Instant::now());
                }
            });
        }
        let node = self.clone();
        spawn(async move {
            loop {
                let incoming = node.service.accept().await;
                let node = node.clone();
                spawn(async move { node.connection(incoming).await });
            }
        });
    }

    async fn connection(self, incoming: Incoming) {
        if incoming.port != SERVICE_PORT {
            incoming.reject();
            return;
        }
        let over_cap = {
            let mut s = self.state.borrow_mut();
            s.stats.connections += 1;
            if s.last_sweep.elapsed() > Duration::from_secs(2) {
                s.last_sweep = Instant::now();
                s.spent.sweep(now_ms());
            }
            let over = s.conns >= self.config.max_conns;
            if !over {
                s.conns += 1;
            }
            over
        };
        let Ok(stream) = incoming.accept() else {
            if !over_cap {
                self.state.borrow_mut().conns -= 1;
            }
            return;
        };
        if over_cap {
            let _ = stream
                .write_all(refusal_line("too-many-connections", "").as_bytes())
                .await;
            self.state.borrow_mut().stats.refused += 1;
            stream.end(end_reason::DONE);
            return;
        }
        let outcome = self.serve(&stream).await;
        {
            let mut s = self.state.borrow_mut();
            s.conns -= 1;
            match &outcome {
                Ok(()) => {}
                Err(reason) => {
                    s.stats.refused += 1;
                    log::info!("refused: {}", reason.trim_end());
                }
            }
        }
        match outcome {
            Err(line) if !line.is_empty() => {
                let _ = stream.write_all(line.as_bytes()).await;
            }
            _ => {}
        }
        stream.end(end_reason::DONE);
    }

    /// Read the first frame: one JSON line, then whatever the client sent after it.
    async fn read_envelope(&self, stream: &Stream) -> Result<(Value, Vec<u8>), String> {
        let max = self.config.max_envelope_bytes;
        let mut line: Vec<u8> = Vec::with_capacity(2048);
        let mut chunk = [0u8; 512];
        let read = async {
            loop {
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|_| "closed before envelope".to_string())?;
                if n == 0 {
                    return Err("closed before envelope".to_string());
                }
                line.extend_from_slice(&chunk[..n]);
                match line.iter().position(|&b| b == b'\n') {
                    Some(at) if at > max => return Err("envelope too large".to_string()),
                    Some(at) => return Ok(at),
                    None if line.len() > max => return Err("envelope too large".to_string()),
                    None => {}
                }
            }
        };
        let at = match timeout(self.config.envelope_timeout, "envelope", async {
            Ok::<_, microtor::Error>(read.await)
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err("envelope timeout".into()),
        };
        let early = line.split_off(at + 1);
        line.pop();
        let envelope: Value = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
        if !envelope.is_object() && !envelope.is_array() {
            return Err("envelope is not an object".into());
        }
        Ok((envelope, early))
    }

    /// Run the pairing on its own thread and wait for it without blocking the event loop.
    /// One heavy job at a time: a verification needs on the order of 100 KB of heap.
    async fn pairing(&self, job: PairingJob) -> Result<bool, String> {
        let _heavy = microtor::rt::heavy().await;
        let started = Instant::now();
        let (tx, rx) = channel();
        let spawned = std::thread::Builder::new()
            .name("verify".into())
            .stack_size(self.config.verify_stack)
            .spawn(move || {
                let _ = tx.send(job.run());
            });
        let result = match spawned {
            Err(_) => Err("verifier thread could not start".to_string()),
            Ok(_) => {
                poll_fn(|_| match rx.try_recv() {
                    Ok(result) => Poll::Ready(result),
                    Err(TryRecvError::Empty) => Poll::Pending,
                    Err(TryRecvError::Disconnected) => {
                        Poll::Ready(Err("verifier thread died".to_string()))
                    }
                })
                .await
            }
        };
        let mut s = self.state.borrow_mut();
        s.stats.verify_ms_last = started.elapsed().as_millis() as u64;
        note_progress();
        result
    }

    fn gate_refusal(&self, refusal: Refusal) -> String {
        match refusal {
            Refusal::Reason(reason) => refusal_line(&format!("gate:{reason}"), ""),
            Refusal::WrongRoot => {
                let roots: Vec<String> = self
                    .state
                    .borrow()
                    .roots
                    .iter()
                    .take(MAX_ROOTS_IN_REPLY)
                    .map(|r| json_string(r))
                    .collect();
                refusal_line(
                    "gate:wrong-group-root",
                    &format!(",\"roots\":[{}]", roots.join(",")),
                )
            }
            Refusal::Artifact(reason) => {
                let ids: Vec<String> = self.artifact_ids().iter().map(|i| json_string(i)).collect();
                refusal_line(
                    &format!("gate:{reason}"),
                    &format!(",\"artifacts\":[{}]", ids.join(",")),
                )
            }
        }
    }

    /// Everything from the first byte to the end of the tunnel. `Err` is the refusal line to
    /// write before closing (empty for a silent close).
    async fn serve(&self, stream: &Stream) -> Result<(), String> {
        let (envelope, early) = self
            .read_envelope(stream)
            .await
            .map_err(|text| refusal_line(&format!("bad-envelope:{text}"), ""))?;
        version_gate(&envelope).map_err(|reason| refusal_line(&reason, &proto_extra()))?;
        let has_session = envelope.get("session").is_some();
        if has_session || envelope.get("ticket").is_some() {
            if !self.config.session_tickets {
                return Err(refusal_line("session-unsupported", ""));
            }
            return if has_session {
                self.session_init(stream, envelope).await
            } else {
                self.ticket_spend(stream, envelope, early).await
            };
        }

        let target = self.target_of(&envelope)?;
        let verified = self.verify(&envelope, Binding::Target).await?;
        let nonce = envelope.get("nonce").and_then(Value::as_str).unwrap_or("");
        self.admit(&verified, nonce)?;
        drop(envelope);

        // One tunnel slot per nullifier, then a hold on the slot's byte allowance.
        let key = slot_key(&verified.external_nullifier, &verified.nullifier);
        {
            let mut s = self.state.borrow_mut();
            let limit = self.config.max_conns_per_nullifier;
            let open = s
                .per_nullifier
                .entry(verified.nullifier.clone())
                .or_insert(0);
            if limit != 0 && *open >= limit {
                return Err(refusal_line("nullifier-conn-limit", ""));
            }
            *open += 1;
        }
        let result = self.plain_tunnel(stream, &target, &key, early).await;
        let mut s = self.state.borrow_mut();
        if let Some(open) = s.per_nullifier.get_mut(&verified.nullifier) {
            *open -= 1;
            if *open == 0 {
                s.per_nullifier.remove(&verified.nullifier);
            }
        }
        result
    }

    /// Target grammar, then the operator's policy.
    fn target_of(&self, envelope: &Value) -> Result<Target, String> {
        let target = envelope
            .get("target")
            .and_then(Value::as_str)
            .and_then(parse_target)
            .ok_or_else(|| refusal_line("bad-target", ""))?;
        if !self.policy.permits(&target) {
            return Err(refusal_line("bad-target-policy", ""));
        }
        Ok(target)
    }

    /// Cheap checks, then the pairing. The verified values only count once it passes.
    async fn verify(&self, envelope: &Value, binding: Binding<'_>) -> Result<Verified, String> {
        let prechecked = {
            let mut s = self.state.borrow_mut();
            let roots = s.roots.clone();
            s.verifier.precheck(envelope, &roots, binding, now_unix())
        };
        let (verified, job) = prechecked.map_err(|r| self.gate_refusal(r))?;
        match pairing_refusal(self.pairing(job).await) {
            Some(refusal) => Err(self.gate_refusal(refusal)),
            None => Ok(verified),
        }
    }

    fn admit(&self, verified: &Verified, nonce: &str) -> Result<(), String> {
        let mut s = self.state.borrow_mut();
        match s.spent.admit(
            &verified.nullifier,
            &verified.share_x,
            &verified.share_y,
            nonce,
            now_ms(),
        ) {
            Admission::First | Admission::Replay => Ok(()),
            Admission::Refused(reason) => Err(refusal_line(reason, "")),
            Admission::OverSpend { first, second } => {
                // Two shares on one slot reveal the member's identity secret; whoever runs
                // the chain side (`chain::Slasher`) picks them up from here.
                s.stats.over_spends += 1;
                if s.over_spends.len() < 8 {
                    s.over_spends.push(OverSpend { first, second });
                }
                log::warn!("over-spend on one proof slot: a member exceeded its rate");
                Err(refusal_line("over-spend-slashed", ""))
            }
        }
    }

    /// The acknowledgement for an admitted tunnel, with a receipt when those are on.
    fn ok_line(&self) -> String {
        if !self.config.receipts {
            return "{\"ok\":true}\n".into();
        }
        let onion = self.service.onion();
        let epoch = self.state.borrow().verifier.current_epoch(now_unix());
        let receipt = crate::proto::build_receipt(self.service.identity(), &onion, epoch);
        format!("{{\"ok\":true,\"receipt\":{receipt}}}\n")
    }

    fn dial_config(&self) -> DialConfig {
        DialConfig {
            allow_private: self.config.allow_private_targets,
            dns_timeout: self.config.dns_timeout,
            connect_timeout: self.config.idle_timeout.min(Duration::from_secs(30)),
            thread_stack: self.config.dial_stack,
            ipv4_only: self.config.ipv4_only,
        }
    }

    async fn plain_tunnel(
        &self,
        stream: &Stream,
        target: &Target,
        key: &str,
        early: Vec<u8>,
    ) -> Result<(), String> {
        if !self.state.borrow_mut().budget.acquire(key, now_ms()) {
            return Err(refusal_line("payload-limit", ""));
        }
        let result = async {
            let dial = Dial::start(target.clone(), self.dial_config())
                .map_err(|r| refusal_line(&r, ""))?;
            let upstream = poll_fn(|_| match dial.poll() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            })
            .await
            .map_err(|reason| refusal_line(&reason, ""))?;
            upstream
                .set_nonblocking(true)
                .map_err(|_| refusal_line("upstream:EIO", ""))?;
            stream
                .write_all(self.ok_line().as_bytes())
                .await
                .map_err(|_| String::new())?;
            {
                let mut s = self.state.borrow_mut();
                s.stats.admitted += 1;
                s.stats.tunnels_open += 1;
            }
            let close = self.relay(stream, upstream, key, early, None).await;
            log::info!("tunnel closed: {close}");
            self.state.borrow_mut().stats.tunnels_open -= 1;
            Ok(())
        }
        .await;
        self.state.borrow_mut().budget.release(key, now_ms());
        result
    }

    /// A proof-carrying envelope that opens a ticket book instead of a tunnel.
    async fn session_init(&self, stream: &Stream, envelope: Value) -> Result<(), String> {
        let init = session::parse_init(&envelope["session"]).map_err(|r| refusal_line(r, ""))?;
        if init.gateway != self.service.onion() {
            return Err(refusal_line("session-wrong-gateway", ""));
        }
        let signal = init.signal();
        let verified = self.verify(&envelope, Binding::Signal(&signal)).await?;
        self.admit(&verified, &init.nonce)?;
        let slot = slot_key(&verified.external_nullifier, &verified.nullifier);
        {
            let mut s = self.state.borrow_mut();
            s.books
                .open(&init, &slot, Instant::now())
                .map_err(|r| refusal_line(r, ""))?;
            s.stats.sessions_opened += 1;
        }
        let reply = session::init_reply(
            &init,
            crate::proto::DEFAULT_PAYLOAD_BYTES_PER_SLOT,
            self.config.session_stream_max.as_millis() as u64,
        );
        stream
            .write_all(reply.as_bytes())
            .await
            .map_err(|_| String::new())?;
        log::info!("session book opened ({})", init.class.id);
        Ok(())
    }

    /// A proof-less envelope that spends one ticket of a book for one tunnel.
    async fn ticket_spend(
        &self,
        stream: &Stream,
        envelope: Value,
        early: Vec<u8>,
    ) -> Result<(), String> {
        let ticket = session::parse_ticket(&envelope["ticket"]).map_err(|r| refusal_line(r, ""))?;
        let target = self.target_of(&envelope)?;
        let named = format!("{}:{}", target.host, target.port);
        let reservation = self
            .state
            .borrow_mut()
            .books
            .reserve(&ticket, &named, Instant::now())
            .map_err(|r| refusal_line(r, ""))?;
        let key = reservation.slot.clone();
        let book = reservation.book;

        if !self.state.borrow_mut().budget.acquire(&key, now_ms()) {
            self.state
                .borrow_mut()
                .books
                .settle(&reservation, false, false);
            return Err(refusal_line("payload-limit", ""));
        }
        let result = async {
            let dial = match Dial::start(target.clone(), self.dial_config()) {
                Ok(dial) => dial,
                Err(reason) => {
                    self.state
                        .borrow_mut()
                        .books
                        .settle(&reservation, false, true);
                    return Err(refusal_line(&reason, ""));
                }
            };
            // The connect races the book: if it expires or closes meanwhile, the ticket is
            // burned and the client gets no reply.
            let dialed = poll_fn(|_| {
                if !self.state.borrow().books.accepts_spends(&book) {
                    return Poll::Ready(None);
                }
                match dial.poll() {
                    Some(result) => Poll::Ready(Some(result)),
                    None => Poll::Pending,
                }
            })
            .await;
            let upstream = match dialed {
                None => {
                    self.state
                        .borrow_mut()
                        .books
                        .settle(&reservation, false, false);
                    return Err(String::new());
                }
                Some(Err(reason)) => {
                    // A definite failure before connecting gives the ticket back; a timeout
                    // is ambiguous and burns it.
                    let refund = reason != "upstream:ETIMEDOUT";
                    self.state
                        .borrow_mut()
                        .books
                        .settle(&reservation, false, refund);
                    return Err(refusal_line(&reason, ""));
                }
                Some(Ok(upstream)) => upstream,
            };
            if upstream.set_nonblocking(true).is_err() {
                self.state
                    .borrow_mut()
                    .books
                    .settle(&reservation, false, false);
                return Err(refusal_line("upstream:EIO", ""));
            }
            if !self
                .state
                .borrow_mut()
                .books
                .settle(&reservation, true, false)
            {
                return Err(String::new());
            }
            if stream.write_all(b"{\"ok\":true}\n").await.is_err() {
                self.state.borrow_mut().books.stream_closed(&book);
                return Err(String::new());
            }
            {
                let mut s = self.state.borrow_mut();
                s.stats.admitted += 1;
                s.stats.tickets_spent += 1;
                s.stats.tunnels_open += 1;
            }
            let close = self.relay(stream, upstream, &key, early, Some(book)).await;
            log::info!("ticket stream closed: {close}");
            let mut s = self.state.borrow_mut();
            s.stats.tunnels_open -= 1;
            if close == "payload-limit" {
                // The slot's allowance is gone: the whole book ends with it.
                s.books.close(&book);
            } else {
                s.books.stream_closed(&book);
            }
            Ok(())
        }
        .await;
        self.state.borrow_mut().budget.release(&key, now_ms());
        result
    }

    /// How many bytes one direction may read right now (at most `max`): the node-wide
    /// bandwidth cap and, for a ticket stream, the book's shaper.
    fn quota(&self, max: usize, book: Option<&[u8; 32]>, upward: bool) -> usize {
        let mut s = self.state.borrow_mut();
        let mut allowed = match s.bucket.as_mut() {
            Some(bucket) => {
                bucket.refill();
                max.min(bucket.tokens.max(0.0) as usize)
            }
            None => max,
        };
        if let Some(book) = book {
            allowed = s.books.quota(book, upward, allowed, Instant::now());
        }
        allowed
    }

    /// Account for `n` relayed bytes. Returns how many the slot budget covers and whether the
    /// slot is now exhausted.
    fn charge(&self, key: &str, n: usize, book: Option<&[u8; 32]>, upward: bool) -> (usize, bool) {
        let mut s = self.state.borrow_mut();
        if let Some(bucket) = s.bucket.as_mut() {
            bucket.tokens -= n as f64;
        }
        if let Some(book) = book {
            s.books.moved(book, upward, n, Instant::now());
        }
        s.budget.take(key, n)
    }

    /// Copy bytes both ways until either side ends. There is no half-close: the first EOF tears
    /// the tunnel down, as the reference node does. Bytes past the slot's allowance are dropped
    /// and the tunnel closes once what was allowed has been delivered. A ticket stream is also
    /// shaped by its book, ends when the book closes, and has a hard maximum age.
    async fn relay(
        &self,
        stream: &Stream,
        mut upstream: TcpStream,
        key: &str,
        early: Vec<u8>,
        book: Option<[u8; 32]>,
    ) -> &'static str {
        let book = book.as_ref();
        let started = Instant::now();
        // Client to destination: bytes read from the onion stream, waiting to be written.
        // Early data (sent right after the envelope) goes first and counts like any other.
        let mut exhausted = false;
        let mut up = early;
        if !up.is_empty() {
            let (allowed, done) = self.charge(key, up.len(), book, true);
            up.truncate(allowed);
            exhausted = done;
        }
        let mut up_at = 0;
        // Destination to client.
        let mut down = vec![0u8; 4 * microtor::cell::RELAY_DATA_MAX];
        let (mut down_len, mut down_at) = (0, 0);
        let mut chunk = [0u8; 1024];
        let mut last_activity = Instant::now();

        loop {
            let mut moved = false;

            // Onion stream -> destination.
            if up_at == up.len() && !exhausted {
                let quota = self.quota(chunk.len(), book, true);
                if quota > 0 {
                    match stream.try_read(&mut chunk[..quota]) {
                        Ok(Some(0)) => return "peer",
                        Ok(Some(n)) => {
                            let (allowed, done) = self.charge(key, n, book, true);
                            exhausted = done;
                            up.clear();
                            up.extend_from_slice(&chunk[..allowed]);
                            up_at = 0;
                            moved = true;
                        }
                        Ok(None) => {}
                        Err(_) => return "client-error",
                    }
                }
            }
            while up_at < up.len() {
                match upstream.write(&up[up_at..]) {
                    Ok(0) => return "upstream-error",
                    Ok(n) => {
                        up_at += n;
                        self.state.borrow_mut().stats.bytes_up += n as u64;
                        moved = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return "upstream-error",
                }
            }

            // Destination -> onion stream, only while the stream's flow-control window is open
            // so nothing piles up in this node.
            if down_at == down_len && !exhausted {
                let quota = self.quota(down.len(), book, false);
                match stream.can_send() {
                    Ok(true) if quota > 0 => match upstream.read(&mut down[..quota]) {
                        Ok(0) => return "peer",
                        Ok(n) => {
                            let (allowed, done) = self.charge(key, n, book, false);
                            exhausted = done;
                            down_len = allowed;
                            down_at = 0;
                            moved = true;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => return "upstream-error",
                    },
                    Ok(_) => {}
                    Err(_) => return "peer",
                }
            }
            while down_at < down_len {
                match stream.try_write(&down[down_at..down_len]) {
                    Ok(0) => break,
                    Ok(n) => {
                        down_at += n;
                        self.state.borrow_mut().stats.bytes_down += n as u64;
                        moved = true;
                    }
                    Err(_) => return "client-error",
                }
            }

            if exhausted && up_at == up.len() && down_at == down_len {
                return "payload-limit";
            }
            if let Some(book) = book {
                if !self.state.borrow().books.is_live(book) {
                    return "session";
                }
                if started.elapsed() > self.config.session_stream_max {
                    return "session-stream-max";
                }
            }
            if moved {
                last_activity = Instant::now();
                note_progress();
            } else if last_activity.elapsed() > self.config.idle_timeout {
                return "idle-timeout";
            }
            yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn version_gate_reasons() {
        assert_eq!(version_gate(&json!({"v": 4})), Ok(()));
        assert_eq!(
            version_gate(&json!({})),
            Err("unsupported-version:3".into())
        );
        assert_eq!(
            version_gate(&json!({"v": null})),
            Err("unsupported-version:3".into())
        );
        assert_eq!(
            version_gate(&json!({"v": 5})),
            Err("unsupported-version:5".into())
        );
        assert_eq!(
            version_gate(&json!({"v": "abc"})),
            Err("bad-version:\"abc\"".into())
        );
        assert_eq!(
            version_gate(&json!({"v": 4.5})),
            Err("bad-version:4.5".into())
        );
        assert_eq!(
            version_gate(&json!({"v": true})),
            Err("bad-version:boolean".into())
        );
        assert_eq!(
            version_gate(&json!({"v": [4]})),
            Err("bad-version:object".into())
        );
        assert_eq!(
            version_gate(&json!([])),
            Err("unsupported-version:3".into())
        );
    }

    #[test]
    fn refusal_lines_are_one_json_object() {
        let line = refusal_line("unsupported-version:3", &proto_extra());
        assert_eq!(
            line,
            "{\"ok\":false,\"err\":\"unsupported-version:3\",\"proto\":{\"min\":4,\"max\":4}}\n"
        );
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["ok"], json!(false));
    }
}
