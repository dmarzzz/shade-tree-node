//! Session-ticket books (session-v1, ADR 0011; `packages/node/gateway/session.mjs`,
//! `packages/node/lib/session-tickets.mjs`). One verified initialization proof opens a book of
//! single-use tickets at this node; each ticket opens one tunnel with a proof-less envelope. The
//! transitions UNUSED -> RESERVED -> SPENT (and RESERVED -> UNUSED on a definite pre-connect
//! failure) happen under the books mutex before any DNS or TCP work. The lifetime ends spends,
//! not streams: an expired book refuses new tickets, resets pending connects, and lets
//! established streams drain under the byte ceiling, the book's idle clock and the per-stream
//! hard cap.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use shadenet_proto::session::{
    decode_ticket_secret, is_class_id, is_hex64, is_nonce32, is_session_onion, spend_digest,
    ticket_book_digest, ticket_commitment, MAX_TICKETS, SESSION_VERSION,
};
use tokio::sync::Notify;

use crate::tunnel::Shaping;

pub(crate) const DEFAULT_MAX_SESSIONS: u64 = 256;
pub(crate) const DEFAULT_STREAM_MAX_MS: u64 = 900_000;
const SWEEP_INTERVAL: Duration = Duration::from_millis(250);

/// One policy class, operator-enforced and echoed after initialization.
pub(crate) struct Policy {
    pub(crate) class: &'static str,
    pub(crate) tickets: usize,
    pub(crate) max_payload_bytes: u64,
    pub(crate) lifetime: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_concurrent_streams: usize,
    pub(crate) max_pending_connects: usize,
    pub(crate) up_bytes_per_second: u64,
    pub(crate) up_burst_bytes: u64,
    pub(crate) down_bytes_per_second: u64,
    pub(crate) down_burst_bytes: u64,
}

const RESEARCH_V1: Policy = Policy {
    class: "research-v1",
    tickets: 6,
    max_payload_bytes: 41_943_040,
    lifetime: Duration::from_millis(90_000),
    idle_timeout: Duration::from_millis(15_000),
    max_concurrent_streams: 4,
    max_pending_connects: 4,
    up_bytes_per_second: 64 * 1024,
    up_burst_bytes: 128 * 1024,
    down_bytes_per_second: 512 * 1024,
    down_burst_bytes: 1024 * 1024,
};

const RESEARCH_V2: Policy = Policy {
    class: "research-v2",
    idle_timeout: Duration::from_millis(60_000),
    ..RESEARCH_V1
};

pub(crate) const CLASSES: [Policy; 2] = [RESEARCH_V1, RESEARCH_V2];

pub(crate) fn class_policy(id: &str) -> Option<&'static Policy> {
    CLASSES.iter().find(|p| p.class == id)
}

/// The policy echo of a successful initialization, in the wire key order.
pub(crate) fn policy_echo(policy: &Policy, stream_max: Option<Duration>) -> String {
    format!(
        "{{\"class\":\"{}\",\"tickets\":{},\"maxPayloadBytes\":{},\"lifetimeMs\":{},\"idleTimeoutMs\":{},\"maxConcurrentStreams\":{},\"streamMaxMs\":{}}}",
        policy.class,
        policy.tickets,
        policy.max_payload_bytes,
        policy.lifetime.as_millis(),
        policy.idle_timeout.as_millis(),
        policy.max_concurrent_streams,
        stream_max.map_or(0, |d| d.as_millis())
    )
}

/// A validated initialization: the fields the signal is rebuilt from.
pub(crate) struct Init {
    pub(crate) policy: &'static Policy,
    pub(crate) class: String,
    pub(crate) gateway: String,
    pub(crate) nonce: String,
    pub(crate) commitments: Vec<String>,
    pub(crate) digest: String,
}

/// `validateSessionInit`: total, bounded reasons, never peer bytes.
pub(crate) fn validate_init(session: &Value) -> Result<Init, &'static str> {
    let Value::Object(fields) = session else {
        return Err("session-malformed");
    };
    if fields.get("v").and_then(Value::as_u64) != Some(SESSION_VERSION) {
        return Err("session-version");
    }
    let class = fields
        .get("class")
        .and_then(Value::as_str)
        .filter(|c| is_class_id(c))
        .ok_or("session-class")?;
    let policy = class_policy(class).ok_or("session-class")?;
    let gateway = fields
        .get("gateway")
        .and_then(Value::as_str)
        .filter(|g| is_session_onion(g))
        .ok_or("session-gateway")?;
    let nonce = fields
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|n| is_nonce32(n))
        .ok_or("session-nonce")?;
    let list = fields
        .get("ticketCommitments")
        .and_then(Value::as_array)
        .filter(|l| l.len() == policy.tickets)
        .ok_or("session-ticket-count")?;
    let commitments: Vec<String> = list
        .iter()
        .map(|c| c.as_str().filter(|c| is_hex64(c)).map(str::to_string))
        .collect::<Option<Vec<_>>>()
        .ok_or("session-commitment")?;
    let mut dedup = commitments.clone();
    dedup.sort_unstable();
    dedup.dedup();
    if dedup.len() != commitments.len() {
        return Err("session-commitment");
    }
    let digest = fields
        .get("ticketBookDigest")
        .and_then(Value::as_str)
        .filter(|d| is_hex64(d))
        .ok_or("session-digest")?;
    if ticket_book_digest(&commitments).as_deref() != Ok(digest) {
        return Err("session-digest");
    }
    Ok(Init {
        policy,
        class: class.to_string(),
        gateway: gateway.to_string(),
        nonce: nonce.to_string(),
        commitments,
        digest: digest.to_string(),
    })
}

/// A validated ticket spend.
pub(crate) struct Ticket {
    pub(crate) book: String,
    pub(crate) index: u16,
    pub(crate) secret: [u8; 32],
    pub(crate) request_nonce: String,
}

/// `validateTicket`: total, bounded reasons.
pub(crate) fn validate_ticket(ticket: &Value) -> Result<Ticket, &'static str> {
    let Value::Object(fields) = ticket else {
        return Err("ticket-malformed");
    };
    if fields.get("v").and_then(Value::as_u64) != Some(SESSION_VERSION) {
        return Err("ticket-version");
    }
    let book = fields
        .get("book")
        .and_then(Value::as_str)
        .filter(|b| is_hex64(b))
        .ok_or("ticket-book")?;
    let index = fields
        .get("i")
        .and_then(Value::as_u64)
        .filter(|i| (*i as usize) < MAX_TICKETS)
        .and_then(|i| u16::try_from(i).ok())
        .ok_or("ticket-index")?;
    let secret = fields
        .get("t")
        .and_then(Value::as_str)
        .and_then(decode_ticket_secret)
        .ok_or("ticket-secret")?;
    let request_nonce = fields
        .get("n")
        .and_then(Value::as_str)
        .filter(|n| is_nonce32(n))
        .ok_or("ticket-nonce")?;
    Ok(Ticket {
        book: book.to_string(),
        index,
        secret,
        request_nonce: request_nonce.to_string(),
    })
}

#[derive(Clone, PartialEq, Eq)]
enum State {
    Unused,
    Reserved { spend_digest: String, stream: u64 },
    Spent,
}

struct Stream {
    cancel: Arc<Notify>,
    established_at: Option<Instant>,
}

struct Book {
    policy: &'static Policy,
    commitments: Vec<[u8; 32]>,
    tickets: Vec<State>,
    ticket_streams: Vec<Option<u64>>,
    slot: String,
    expires_at: Instant,
    draining: bool,
    open_streams: usize,
    pending_connects: usize,
    streams: HashMap<u64, Stream>,
    shaping: Arc<Shaping>,
}

struct Inner {
    books: HashMap<String, Book>,
    by_slot: HashMap<String, String>,
    next_stream: u64,
}

/// A reserved ticket: what the spend path holds while it resolves, dials and relays.
pub(crate) struct Reservation {
    pub(crate) book: String,
    pub(crate) index: u16,
    pub(crate) stream: u64,
    pub(crate) slot_key: (String, String),
    pub(crate) shaping: Arc<Shaping>,
    pub(crate) cancel: Arc<Notify>,
}

pub(crate) enum Opened {
    New,
    Replay,
}

pub(crate) struct Books {
    inner: Mutex<Inner>,
    max_sessions: usize,
    stream_max: Option<Duration>,
}

fn slot_key(nullifier: &str, epoch: &str) -> String {
    format!("{epoch}\0{nullifier}")
}

impl Books {
    pub(crate) fn new(max_sessions: usize, stream_max: Option<Duration>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                books: HashMap::new(),
                by_slot: HashMap::new(),
                next_stream: 0,
            }),
            max_sessions,
            stream_max,
        }
    }

    pub(crate) fn stream_max(&self) -> Option<Duration> {
        self.stream_max
    }

    /// Open a book for a verified initialization. An exact replay of a live book is
    /// idempotent; a different digest for the same proof slot is a conflict.
    pub(crate) fn open(
        &self,
        init: &Init,
        nullifier: &str,
        epoch: &str,
    ) -> Result<Opened, &'static str> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slot_key(nullifier, epoch);
        if let Some(existing) = inner.by_slot.get(&slot) {
            if existing == &init.digest {
                return match inner.books.get(&init.digest) {
                    Some(book) if book.draining => Err("session-expired"),
                    Some(_) => Ok(Opened::Replay),
                    None => Err("session-conflict"),
                };
            }
            return Err("session-conflict");
        }
        if inner.books.contains_key(&init.digest) {
            return Err("session-conflict");
        }
        if inner.books.len() >= self.max_sessions {
            return Err("session-capacity");
        }
        let commitments = init
            .commitments
            .iter()
            .map(|c| {
                hex::decode(c)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("session-commitment")?;
        let now = Instant::now();
        let policy = init.policy;
        inner.books.insert(
            init.digest.clone(),
            Book {
                policy,
                tickets: vec![State::Unused; commitments.len()],
                ticket_streams: vec![None; commitments.len()],
                commitments,
                slot: slot.clone(),
                expires_at: now + policy.lifetime,
                draining: false,
                open_streams: 0,
                pending_connects: 0,
                streams: HashMap::new(),
                shaping: Arc::new(Shaping::new(
                    policy.up_bytes_per_second,
                    policy.up_burst_bytes,
                    policy.down_bytes_per_second,
                    policy.down_burst_bytes,
                )),
            },
        );
        inner.by_slot.insert(slot, init.digest.clone());
        Ok(Opened::New)
    }

    /// Verify the ticket against its commitment and move it UNUSED -> RESERVED, taking one
    /// stream and one pending-connect slot.
    pub(crate) fn reserve(
        &self,
        ticket: &Ticket,
        target: &str,
    ) -> Result<Reservation, &'static str> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let stream = inner.next_stream + 1;
        inner.next_stream = stream;
        let Some(book) = inner.books.get_mut(&ticket.book) else {
            return Err("session-unknown");
        };
        if !book.draining && Instant::now() >= book.expires_at {
            Self::expire(book);
        }
        if book.draining {
            return Err("session-expired");
        }
        let index = usize::from(ticket.index);
        if index >= book.tickets.len() {
            return Err("ticket-index");
        }
        let expected = book.commitments[index];
        let claimed =
            hex::decode(ticket_commitment(ticket.index, &ticket.secret)).unwrap_or_default();
        if claimed != expected {
            return Err("ticket-mismatch");
        }
        let digest = spend_digest(&ticket.book, ticket.index, target, &ticket.request_nonce)
            .map_err(|_| "ticket-nonce")?;
        match &book.tickets[index] {
            State::Spent => return Err("ticket-spent"),
            State::Reserved { spend_digest, .. } if *spend_digest == digest => {
                return Err("ticket-inflight")
            }
            State::Reserved { .. } => return Err("ticket-conflict"),
            State::Unused => {}
        }
        if book.open_streams >= book.policy.max_concurrent_streams {
            return Err("session-streams");
        }
        if book.pending_connects >= book.policy.max_pending_connects {
            return Err("session-pending");
        }
        book.tickets[index] = State::Reserved {
            spend_digest: digest,
            stream,
        };
        book.ticket_streams[index] = Some(stream);
        book.open_streams += 1;
        book.pending_connects += 1;
        let cancel = Arc::new(Notify::new());
        book.streams.insert(
            stream,
            Stream {
                cancel: Arc::clone(&cancel),
                established_at: None,
            },
        );
        let (epoch, nullifier) = book.slot.split_once('\0').unwrap_or(("", ""));
        Ok(Reservation {
            book: ticket.book.clone(),
            index: ticket.index,
            stream,
            slot_key: (epoch.to_string(), nullifier.to_string()),
            shaping: Arc::clone(&book.shaping),
            cancel,
        })
    }

    /// A definite pre-connect failure: the reservation returns to UNUSED for an exact retry.
    pub(crate) fn release(&self, reservation: &Reservation) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(book) = inner.books.get_mut(&reservation.book) else {
            return;
        };
        let index = usize::from(reservation.index);
        if !matches!(&book.tickets[index], State::Reserved { stream, .. } if *stream == reservation.stream)
        {
            return;
        }
        book.tickets[index] = State::Unused;
        book.ticket_streams[index] = None;
        book.streams.remove(&reservation.stream);
        book.pending_connects = book.pending_connects.saturating_sub(1);
        book.open_streams = book.open_streams.saturating_sub(1);
    }

    /// The commit point, inside the successful upstream connect and before the ack.
    pub(crate) fn spend(&self, reservation: &Reservation) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(book) = inner.books.get_mut(&reservation.book) else {
            return false;
        };
        let index = usize::from(reservation.index);
        if !matches!(&book.tickets[index], State::Reserved { stream, .. } if *stream == reservation.stream)
        {
            return false;
        }
        book.tickets[index] = State::Spent;
        book.pending_connects = book.pending_connects.saturating_sub(1);
        if let Some(stream) = book.streams.get_mut(&reservation.stream) {
            stream.established_at = Some(Instant::now());
        }
        true
    }

    /// Any end of a stream after reservation. A still-pending connect burns its ticket.
    pub(crate) fn stream_closed(&self, reservation: &Reservation) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(book) = inner.books.get_mut(&reservation.book) else {
            return;
        };
        let index = usize::from(reservation.index);
        book.streams.remove(&reservation.stream);
        if matches!(&book.tickets[index], State::Reserved { stream, .. } if *stream == reservation.stream)
        {
            book.tickets[index] = State::Spent;
            book.pending_connects = book.pending_connects.saturating_sub(1);
        }
        if book.ticket_streams[index] == Some(reservation.stream) {
            book.ticket_streams[index] = None;
            book.open_streams = book.open_streams.saturating_sub(1);
        }
        let established = book.streams.values().any(|s| s.established_at.is_some());
        if book.draining && !established {
            let book = inner.books.remove(&reservation.book);
            if let Some(book) = book {
                Self::close(&mut inner, &reservation.book, book, "session-expired");
            }
        }
    }

    /// Close every stream of a book now (the shared payload ceiling ran out).
    pub(crate) fn close_book(&self, digest: &str, reason: &'static str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(book) = inner.books.remove(digest) {
            Self::close(&mut inner, digest, book, reason);
        }
    }

    fn expire(book: &mut Book) {
        if book.draining {
            return;
        }
        book.draining = true;
        for stream in book.streams.values() {
            if stream.established_at.is_none() {
                stream.cancel.notify_one();
            }
        }
    }

    fn close(inner: &mut Inner, digest: &str, book: Book, reason: &'static str) {
        if inner.by_slot.get(&book.slot).is_some_and(|d| d == digest) {
            inner.by_slot.remove(&book.slot);
        }
        for stream in book.streams.values() {
            stream.cancel.notify_one();
        }
        tracing::debug!(reason, "session closed");
    }

    /// Lifetimes, idle clocks and the per-stream hard cap, checked on a short tick.
    pub(crate) async fn sweep(self: Arc<Self>) {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            let now = Instant::now();
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut closing: Vec<(String, &'static str)> = Vec::new();
            for (digest, book) in inner.books.iter_mut() {
                if !book.draining && now >= book.expires_at {
                    Self::expire(book);
                    if !book.streams.values().any(|s| s.established_at.is_some()) {
                        closing.push((digest.clone(), "session-expired"));
                        continue;
                    }
                }
                if now.duration_since(book.shaping.last_payload()) >= book.policy.idle_timeout {
                    closing.push((digest.clone(), "session-idle"));
                    continue;
                }
                if let Some(cap) = self.stream_max {
                    for stream in book.streams.values() {
                        if stream
                            .established_at
                            .is_some_and(|at| now.duration_since(at) >= cap)
                        {
                            tracing::debug!(reason = "session-stream-max", "stream closed");
                            stream.cancel.notify_one();
                        }
                    }
                }
            }
            for (digest, reason) in closing {
                if let Some(book) = inner.books.remove(&digest) {
                    Self::close(&mut inner, &digest, book, reason);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use shadenet_proto::session::{build_ticket_book, encode_ticket_secret};

    fn book() -> (Vec<[u8; 32]>, Init) {
        let secrets: Vec<[u8; 32]> = (1..=6_u8).map(|i| [i; 32]).collect();
        let built = build_ticket_book(&secrets).unwrap();
        let init = validate_init(&json!({
            "v": 1,
            "class": "research-v1",
            "gateway": format!("{}.onion", "a".repeat(56)),
            "nonce": "00112233445566778899aabbccddeeff",
            "ticketCommitments": built.commitments,
            "ticketBookDigest": built.ticket_book_digest,
        }))
        .ok()
        .unwrap();
        (secrets, init)
    }

    fn ticket(init: &Init, index: u16, secret: &[u8; 32], nonce: &str) -> Ticket {
        validate_ticket(&json!({
            "v": 1,
            "book": init.digest,
            "i": index,
            "t": encode_ticket_secret(secret),
            "n": nonce,
        }))
        .ok()
        .unwrap()
    }

    #[test]
    fn initialization_validation_names_each_failure() {
        let (_, init) = book();
        assert_eq!(init.policy.class, "research-v1");
        let base = json!({
            "v": 1, "class": "research-v1", "gateway": format!("{}.onion", "a".repeat(56)),
            "nonce": "00112233445566778899aabbccddeeff",
            "ticketCommitments": init.commitments, "ticketBookDigest": init.digest,
        });
        let with = |key: &str, value: Value| {
            let mut v = base.clone();
            v[key] = value;
            validate_init(&v).err().unwrap()
        };
        assert_eq!(
            validate_init(&json!([])).err().unwrap(),
            "session-malformed"
        );
        assert_eq!(with("v", json!(2)), "session-version");
        assert_eq!(with("class", json!("research-v9")), "session-class");
        assert_eq!(with("gateway", json!("example.com")), "session-gateway");
        assert_eq!(with("nonce", json!("xyz")), "session-nonce");
        assert_eq!(with("ticketCommitments", json!([])), "session-ticket-count");
        let mut dup = init.commitments.clone();
        dup[1] = dup[0].clone();
        assert_eq!(with("ticketCommitments", json!(dup)), "session-commitment");
        assert_eq!(
            with("ticketBookDigest", json!("0".repeat(64))),
            "session-digest"
        );
    }

    #[test]
    fn tickets_move_through_their_states_under_the_caps() {
        let books = Books::new(256, None);
        let (secrets, init) = book();
        assert!(matches!(books.open(&init, "n", "e"), Ok(Opened::New)));
        assert!(matches!(books.open(&init, "n", "e"), Ok(Opened::Replay)));
        assert_eq!(
            books.open(&init, "n", "other").err(),
            Some("session-conflict"),
            "a book digest belongs to one slot"
        );

        let nonce = "0123456789abcdef0123456789abcdef";
        let t0 = ticket(&init, 0, &secrets[0], nonce);
        let r0 = books.reserve(&t0, "example.com:443").ok().unwrap();
        assert_eq!(
            books.reserve(&t0, "example.com:443").err(),
            Some("ticket-inflight")
        );
        let other = ticket(&init, 0, &secrets[0], "ffffffffffffffffffffffffffffffff");
        assert_eq!(
            books.reserve(&other, "example.com:443").err(),
            Some("ticket-conflict")
        );
        let wrong = ticket(&init, 1, &secrets[0], nonce);
        assert_eq!(
            books.reserve(&wrong, "example.com:443").err(),
            Some("ticket-mismatch")
        );
        let beyond = ticket(&init, 9, &secrets[0], nonce);
        assert_eq!(
            books.reserve(&beyond, "example.com:443").err(),
            Some("ticket-index")
        );

        books.release(&r0);
        let r0 = books.reserve(&t0, "example.com:443").ok().unwrap();
        assert!(books.spend(&r0));
        assert!(!books.spend(&r0));
        assert_eq!(
            books.reserve(&t0, "example.com:443").err(),
            Some("ticket-spent")
        );

        let mut held = Vec::new();
        for i in 1..4_u16 {
            let t = ticket(&init, i, &secrets[usize::from(i)], nonce);
            held.push(books.reserve(&t, "example.com:443").ok().unwrap());
        }
        let t4 = ticket(&init, 4, &secrets[4], nonce);
        assert_eq!(
            books.reserve(&t4, "example.com:443").err(),
            Some("session-streams")
        );
        books.stream_closed(&held[0]);
        assert!(books.reserve(&t4, "example.com:443").is_ok());
        let t1_again = ticket(&init, 1, &secrets[1], nonce);
        assert_eq!(
            books.reserve(&t1_again, "example.com:443").err(),
            Some("ticket-spent"),
            "a pending connect that ended burned its ticket"
        );

        let unknown = Ticket {
            book: "0".repeat(64),
            ..ticket(&init, 5, &secrets[5], nonce)
        };
        assert_eq!(
            books.reserve(&unknown, "example.com:443").err(),
            Some("session-unknown")
        );
    }

    #[test]
    fn capacity_is_bounded() {
        let books = Books::new(1, None);
        let (_, init) = book();
        assert!(books.open(&init, "n", "e").is_ok());
        let (_, other) = {
            let secrets: Vec<[u8; 32]> = (7..=12_u8).map(|i| [i; 32]).collect();
            let built = build_ticket_book(&secrets).unwrap();
            (secrets, validate_init(&json!({
                "v": 1, "class": "research-v2", "gateway": format!("{}.onion", "b".repeat(56)),
                "nonce": "00112233445566778899aabbccddeeff",
                "ticketCommitments": built.commitments, "ticketBookDigest": built.ticket_book_digest,
            })).ok().unwrap())
        };
        assert_eq!(
            books.open(&other, "n2", "e").err(),
            Some("session-capacity")
        );
        assert_eq!(books.open(&other, "n", "e").err(), Some("session-conflict"));
    }

    #[test]
    fn the_policy_echo_keeps_the_wire_order() {
        assert_eq!(
            policy_echo(&RESEARCH_V2, Some(Duration::from_millis(900_000))),
            "{\"class\":\"research-v2\",\"tickets\":6,\"maxPayloadBytes\":41943040,\"lifetimeMs\":90000,\"idleTimeoutMs\":60000,\"maxConcurrentStreams\":4,\"streamMaxMs\":900000}"
        );
    }
}
