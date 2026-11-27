//! Session tickets (session-v1): one proof opens a "book" of single-use tickets, and each
//! ticket opens one tunnel without another proof.
//!
//! The state machine and every refusal string follow the reference node
//! (`crates/shadenet-node/src/session.rs`, design in `docs/design/SESSION-TICKETS.md`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

const COMMITMENT_DOMAIN: &[u8] = b"Shade Tree session ticket v1\n";
const BOOK_DOMAIN: &[u8] = b"Shade Tree session ticket book v1\n";
const SPEND_DOMAIN: &[u8] = b"Shade Tree session ticket spend v1\n";
/// A ticket index is always below this, whatever the class.
const MAX_TICKET_INDEX: u64 = 64;

/// What a book of one class allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    pub id: &'static str,
    pub tickets: usize,
    pub lifetime: Duration,
    pub idle: Duration,
    pub max_streams: usize,
    pub max_pending: usize,
    /// Token buckets shared by every stream of a book: `(bytes per second, burst)`.
    pub up: (u64, u64),
    pub down: (u64, u64),
}

pub const CLASSES: [Class; 2] = [
    Class {
        id: "research-v1",
        tickets: 6,
        lifetime: Duration::from_secs(90),
        idle: Duration::from_secs(15),
        max_streams: 4,
        max_pending: 4,
        up: (65_536, 131_072),
        down: (524_288, 1_048_576),
    },
    Class {
        id: "research-v2",
        tickets: 6,
        lifetime: Duration::from_secs(90),
        idle: Duration::from_secs(60),
        max_streams: 4,
        max_pending: 4,
        up: (65_536, 131_072),
        down: (524_288, 1_048_576),
    },
];

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    is_lower_hex(s, 64)
        .then(|| microtor::util::hex_fixed::<32>(s).ok())
        .flatten()
}

fn class_id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let head = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty() && b.len() <= 32 && head(b[0]) && b[1..].iter().all(|&c| head(c) || c == b'-')
}

fn onion_ok(s: &str) -> bool {
    s.strip_suffix(".onion").is_some_and(|label| {
        label.len() == 56
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

pub fn ticket_commitment(index: u16, secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(index.to_be_bytes());
    h.update(secret);
    h.finalize().into()
}

pub fn book_digest(commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BOOK_DOMAIN);
    h.update((commitments.len() as u16).to_be_bytes());
    for c in commitments {
        h.update(c);
    }
    h.finalize().into()
}

fn spend_digest(book: &[u8; 32], index: u16, target: &str, request_nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SPEND_DOMAIN);
    h.update(book);
    h.update(index.to_be_bytes());
    h.update((target.len() as u16).to_be_bytes());
    h.update(target.as_bytes());
    h.update(request_nonce);
    h.finalize().into()
}

/// The signal a session-initialization proof commits to.
pub fn session_signal(gateway: &str, class: &str, nonce: &str, digest_hex: &str) -> String {
    format!("shade-tree:session:v1\n{gateway}\n{class}\n{nonce}\n{digest_hex}")
}

/// A validated `session` object from an initialization envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub class: Class,
    pub gateway: String,
    pub nonce: String,
    pub commitments: Vec<[u8; 32]>,
    pub digest: [u8; 32],
}

impl Init {
    pub fn signal(&self) -> String {
        session_signal(
            &self.gateway,
            self.class.id,
            &self.nonce,
            &microtor::util::hex_encode(&self.digest),
        )
    }
}

/// Validate the `session` field; the first failure is the refusal.
pub fn parse_init(session: &Value) -> Result<Init, &'static str> {
    let obj = session.as_object().ok_or("session-malformed")?;
    if obj.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("session-version");
    }
    let class = obj
        .get("class")
        .and_then(Value::as_str)
        .filter(|c| class_id_ok(c))
        .and_then(|c| CLASSES.iter().find(|k| k.id == c))
        .copied()
        .ok_or("session-class")?;
    let gateway = obj
        .get("gateway")
        .and_then(Value::as_str)
        .filter(|g| onion_ok(g))
        .ok_or("session-gateway")?;
    let nonce = obj
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|n| is_lower_hex(n, 32))
        .ok_or("session-nonce")?;
    let listed = obj
        .get("ticketCommitments")
        .and_then(Value::as_array)
        .filter(|a| a.len() == class.tickets)
        .ok_or("session-ticket-count")?;
    let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(listed.len());
    for entry in listed {
        let c = entry.as_str().and_then(hex32).ok_or("session-commitment")?;
        if commitments.contains(&c) {
            return Err("session-commitment");
        }
        commitments.push(c);
    }
    let digest = obj
        .get("ticketBookDigest")
        .and_then(Value::as_str)
        .and_then(hex32)
        .filter(|d| *d == book_digest(&commitments))
        .ok_or("session-digest")?;
    Ok(Init {
        class,
        gateway: gateway.to_string(),
        nonce: nonce.to_string(),
        commitments,
        digest,
    })
}

/// A validated `ticket` object from a spend envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub book: [u8; 32],
    pub index: u16,
    pub secret: [u8; 32],
    pub request_nonce: [u8; 16],
}

fn base64url_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    let standard: String = s
        .chars()
        .map(|c| match c {
            '-' => Some('+'),
            '_' => Some('/'),
            c if c.is_ascii_alphanumeric() => Some(c),
            _ => None,
        })
        .collect::<Option<String>>()?;
    microtor::util::b64_fixed::<32>(&standard).ok()
}

pub fn parse_ticket(ticket: &Value) -> Result<Ticket, &'static str> {
    let obj = ticket.as_object().ok_or("ticket-malformed")?;
    if obj.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("ticket-version");
    }
    let book = obj
        .get("book")
        .and_then(Value::as_str)
        .and_then(hex32)
        .ok_or("ticket-book")?;
    let index = obj
        .get("i")
        .and_then(Value::as_u64)
        .filter(|i| *i < MAX_TICKET_INDEX)
        .ok_or("ticket-index")? as u16;
    let secret = obj
        .get("t")
        .and_then(Value::as_str)
        .and_then(base64url_32)
        .ok_or("ticket-secret")?;
    let request_nonce = obj
        .get("n")
        .and_then(Value::as_str)
        .filter(|n| is_lower_hex(n, 32))
        .and_then(|n| microtor::util::hex_fixed::<16>(n).ok())
        .ok_or("ticket-nonce")?;
    Ok(Ticket {
        book,
        index,
        secret,
        request_nonce,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TicketState {
    Unused,
    Reserved([u8; 32]),
    Spent,
}

struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new((rate, burst): (u64, u64)) -> Self {
        Self {
            rate: rate as f64,
            burst: burst as f64,
            tokens: burst as f64,
            at: Instant::now(),
        }
    }

    fn available(&mut self, now: Instant) -> usize {
        self.tokens =
            (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate).min(self.burst);
        self.at = now;
        self.tokens.max(0.0) as usize
    }
}

struct Book {
    /// `"<externalNullifier>\0<nullifier>"`: the proof slot that paid for the book.
    slot: String,
    class: Class,
    commitments: Vec<[u8; 32]>,
    tickets: Vec<TicketState>,
    opened: Instant,
    last_payload: Instant,
    streams: usize,
    pending: usize,
    /// Past its lifetime: no new spends, established streams run on.
    draining: bool,
    up: Bucket,
    down: Bucket,
}

/// Every live book on this node.
pub struct Books {
    books: HashMap<[u8; 32], Book>,
    by_slot: HashMap<String, [u8; 32]>,
    max: usize,
}

/// A ticket reservation: what a spend holds between reserving and committing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub book: [u8; 32],
    pub index: u16,
    pub slot: String,
}

impl Books {
    /// `max` of zero means unlimited.
    pub fn new(max: usize) -> Self {
        Self {
            books: HashMap::new(),
            by_slot: HashMap::new(),
            max,
        }
    }

    pub fn len(&self) -> usize {
        self.books.len()
    }

    pub fn is_empty(&self) -> bool {
        self.books.is_empty()
    }

    /// Expire lifetimes, close idle books, drop finished ones. Call a few times a second.
    pub fn sweep(&mut self, now: Instant) {
        let mut closed: Vec<[u8; 32]> = Vec::new();
        for (digest, book) in self.books.iter_mut() {
            if !book.draining && now.duration_since(book.opened) >= book.class.lifetime {
                book.draining = true;
            }
            let idle = now.duration_since(book.last_payload) >= book.class.idle;
            if idle || (book.draining && book.streams == 0) {
                closed.push(*digest);
            }
        }
        for digest in closed {
            self.close(&digest);
        }
    }

    /// Close a book: every stream of it sees `is_live` turn false and stops.
    pub fn close(&mut self, digest: &[u8; 32]) {
        if let Some(book) = self.books.remove(digest) {
            self.by_slot.remove(&book.slot);
        }
    }

    /// Whether streams of this book may keep running.
    pub fn is_live(&self, digest: &[u8; 32]) -> bool {
        self.books.contains_key(digest)
    }

    /// Whether a pending connect of this book may still complete.
    pub fn accepts_spends(&self, digest: &[u8; 32]) -> bool {
        self.books.get(digest).is_some_and(|b| !b.draining)
    }

    /// Open the book for a verified initialization. An exact repeat for a live book is fine.
    pub fn open(&mut self, init: &Init, slot: &str, now: Instant) -> Result<(), &'static str> {
        self.sweep(now);
        match self.by_slot.get(slot) {
            Some(existing) if *existing == init.digest => {
                return match self.books.get(existing) {
                    Some(book) if !book.draining => Ok(()),
                    _ => Err("session-expired"),
                };
            }
            Some(_) => return Err("session-conflict"),
            None => {}
        }
        if self.books.contains_key(&init.digest) {
            return Err("session-conflict");
        }
        if self.max != 0 && self.books.len() >= self.max {
            return Err("session-capacity");
        }
        self.books.insert(
            init.digest,
            Book {
                slot: slot.to_string(),
                class: init.class,
                commitments: init.commitments.clone(),
                tickets: vec![TicketState::Unused; init.commitments.len()],
                opened: now,
                last_payload: now,
                streams: 0,
                pending: 0,
                draining: false,
                up: Bucket::new(init.class.up),
                down: Bucket::new(init.class.down),
            },
        );
        self.by_slot.insert(slot.to_string(), init.digest);
        Ok(())
    }

    /// Reserve a ticket for `target` (`host:port` as the node parsed it).
    pub fn reserve(
        &mut self,
        ticket: &Ticket,
        target: &str,
        now: Instant,
    ) -> Result<Reservation, &'static str> {
        self.sweep(now);
        let book = self.books.get_mut(&ticket.book).ok_or("session-unknown")?;
        if book.draining {
            return Err("session-expired");
        }
        let index = usize::from(ticket.index);
        if index >= book.tickets.len() {
            return Err("ticket-index");
        }
        if ticket_commitment(ticket.index, &ticket.secret) != book.commitments[index] {
            return Err("ticket-mismatch");
        }
        let spend = spend_digest(&ticket.book, ticket.index, target, &ticket.request_nonce);
        match book.tickets[index] {
            TicketState::Spent => return Err("ticket-spent"),
            TicketState::Reserved(existing) if existing == spend => return Err("ticket-inflight"),
            TicketState::Reserved(_) => return Err("ticket-conflict"),
            TicketState::Unused => {}
        }
        if book.streams >= book.class.max_streams {
            return Err("session-streams");
        }
        if book.pending >= book.class.max_pending {
            return Err("session-pending");
        }
        book.tickets[index] = TicketState::Reserved(spend);
        book.streams += 1;
        book.pending += 1;
        Ok(Reservation {
            book: ticket.book,
            index: ticket.index,
            slot: book.slot.clone(),
        })
    }

    /// The connect finished one way or another. `refund` returns the ticket to unused (a
    /// definite failure before connecting); otherwise it is spent. Returns false when the
    /// reservation no longer exists (the book closed meanwhile).
    pub fn settle(&mut self, reservation: &Reservation, established: bool, refund: bool) -> bool {
        let Some(book) = self.books.get_mut(&reservation.book) else {
            return false;
        };
        book.pending = book.pending.saturating_sub(1);
        let index = usize::from(reservation.index);
        if !matches!(book.tickets[index], TicketState::Reserved(_)) {
            return false;
        }
        book.tickets[index] = if refund {
            TicketState::Unused
        } else {
            TicketState::Spent
        };
        if !established {
            book.streams = book.streams.saturating_sub(1);
        }
        true
    }

    /// A stream of the book ended.
    pub fn stream_closed(&mut self, digest: &[u8; 32]) {
        if let Some(book) = self.books.get_mut(digest) {
            book.streams = book.streams.saturating_sub(1);
        }
    }

    /// How many bytes the book's shaper lets one direction move now (at most `max`).
    pub fn quota(&mut self, digest: &[u8; 32], upward: bool, max: usize, now: Instant) -> usize {
        match self.books.get_mut(digest) {
            Some(book) => {
                let bucket = if upward { &mut book.up } else { &mut book.down };
                max.min(bucket.available(now))
            }
            None => 0,
        }
    }

    /// Account for payload that moved: charge the shaper and reset the idle clock.
    pub fn moved(&mut self, digest: &[u8; 32], upward: bool, bytes: usize, now: Instant) {
        if let Some(book) = self.books.get_mut(digest) {
            let bucket = if upward { &mut book.up } else { &mut book.down };
            bucket.tokens -= bytes as f64;
            book.last_payload = now;
        }
    }
}

/// The success line for an initialization.
pub fn init_reply(init: &Init, max_payload_bytes: u64, stream_max_ms: u64) -> String {
    format!(
        "{{\"ok\":true,\"session\":{{\"ticketBookDigest\":\"{}\",\"policy\":{{\"class\":\"{}\",\"tickets\":{},\"maxPayloadBytes\":{},\"lifetimeMs\":{},\"idleTimeoutMs\":{},\"maxConcurrentStreams\":{},\"streamMaxMs\":{}}}}}}}\n",
        microtor::util::hex_encode(&init.digest),
        init.class.id,
        init.class.tickets,
        max_payload_bytes,
        init.class.lifetime.as_millis(),
        init.class.idle.as_millis(),
        init.class.max_streams,
        stream_max_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex(b: &[u8]) -> String {
        microtor::util::hex_encode(b)
    }

    fn book(class: &str) -> (Value, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (0..6u8).map(|i| [i + 1; 32]).collect();
        let commitments: Vec<[u8; 32]> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| ticket_commitment(i as u16, s))
            .collect();
        let session = json!({
            "v": 1,
            "class": class,
            "gateway": format!("{}.onion", "a".repeat(56)),
            "nonce": "00112233445566778899aabbccddeeff",
            "ticketCommitments": commitments.iter().map(|c| hex(c)).collect::<Vec<_>>(),
            "ticketBookDigest": hex(&book_digest(&commitments)),
        });
        (session, secrets)
    }

    fn b64url(bytes: &[u8]) -> String {
        microtor::util::b64_encode(bytes, false)
            .replace('+', "-")
            .replace('/', "_")
    }

    #[test]
    fn init_validation_order() {
        let (good, _) = book("research-v1");
        assert!(parse_init(&good).is_ok());
        let check = |edit: &dyn Fn(&mut Value)| {
            let mut s = good.clone();
            edit(&mut s);
            parse_init(&s).err()
        };
        assert_eq!(parse_init(&json!("x")).err(), Some("session-malformed"));
        assert_eq!(check(&|s| s["v"] = 2.into()), Some("session-version"));
        assert_eq!(
            check(&|s| s["class"] = "research-v9".into()),
            Some("session-class")
        );
        assert_eq!(
            check(&|s| s["gateway"] = "short.onion".into()),
            Some("session-gateway")
        );
        assert_eq!(
            check(&|s| s["nonce"] = "AA112233445566778899aabbccddeeff".into()),
            Some("session-nonce")
        );
        assert_eq!(
            check(&|s| {
                s["ticketCommitments"].as_array_mut().unwrap().pop();
            }),
            Some("session-ticket-count")
        );
        assert_eq!(
            check(&|s| s["ticketCommitments"][1] = s["ticketCommitments"][0].clone()),
            Some("session-commitment")
        );
        assert_eq!(
            check(&|s| s["ticketBookDigest"] = hex(&[0; 32]).into()),
            Some("session-digest")
        );
    }

    #[test]
    fn signal_matches_the_spec_shape() {
        let (session, _) = book("research-v2");
        let init = parse_init(&session).unwrap();
        assert_eq!(
            init.signal(),
            format!(
                "shade-tree:session:v1\n{}.onion\nresearch-v2\n00112233445566778899aabbccddeeff\n{}",
                "a".repeat(56),
                hex(&init.digest)
            )
        );
        let reply = init_reply(&init, 41_943_040, 900_000);
        let parsed: Value = serde_json::from_str(reply.trim_end()).unwrap();
        assert_eq!(parsed["session"]["policy"]["idleTimeoutMs"], json!(60_000));
        assert_eq!(parsed["session"]["policy"]["tickets"], json!(6));
        assert_eq!(
            parsed["session"]["ticketBookDigest"],
            json!(hex(&init.digest))
        );
    }

    #[test]
    fn tickets_move_through_their_states() {
        let (session, secrets) = book("research-v1");
        let init = parse_init(&session).unwrap();
        let mut books = Books::new(2);
        let now = Instant::now();
        books.open(&init, "ext\0null", now).unwrap();
        // The same initialization again is idempotent; another digest on the slot conflicts.
        books.open(&init, "ext\0null", now).unwrap();
        let (other_session, _) = {
            let (mut s, secrets) = book("research-v1");
            let commitments: Vec<[u8; 32]> =
                (0..6u16).map(|i| ticket_commitment(i, &[9; 32])).collect();
            s["ticketCommitments"] = commitments
                .iter()
                .map(|c| hex(c))
                .collect::<Vec<_>>()
                .into();
            s["ticketBookDigest"] = hex(&book_digest(&commitments)).into();
            (s, secrets)
        };
        let other = parse_init(&other_session).unwrap();
        assert_eq!(
            books.open(&other, "ext\0null", now),
            Err("session-conflict")
        );

        let ticket = |i: u16, nonce: u8| {
            parse_ticket(&json!({
                "v": 1, "book": hex(&init.digest), "i": i,
                "t": b64url(&secrets[usize::from(i)]), "n": hex(&[nonce; 16]),
            }))
            .unwrap()
        };
        let r0 = books
            .reserve(&ticket(0, 1), "example.com:443", now)
            .unwrap();
        assert_eq!(
            books.reserve(&ticket(0, 1), "example.com:443", now),
            Err("ticket-inflight")
        );
        assert_eq!(
            books.reserve(&ticket(0, 2), "example.com:443", now),
            Err("ticket-conflict")
        );
        // A definite failure before connecting refunds the ticket.
        assert!(books.settle(&r0, false, true));
        let r0 = books
            .reserve(&ticket(0, 3), "example.com:443", now)
            .unwrap();
        assert!(books.settle(&r0, true, false));
        assert_eq!(
            books.reserve(&ticket(0, 3), "example.com:443", now),
            Err("ticket-spent")
        );

        // A wrong secret, an index past the book, and an unknown book.
        let mut wrong = ticket(1, 1);
        wrong.secret = [0xee; 32];
        assert_eq!(
            books.reserve(&wrong, "example.com:443", now),
            Err("ticket-mismatch")
        );
        let mut far = ticket(1, 1);
        far.index = 7;
        assert_eq!(
            books.reserve(&far, "example.com:443", now),
            Err("ticket-index")
        );
        let mut unknown = ticket(1, 1);
        unknown.book = [0; 32];
        assert_eq!(
            books.reserve(&unknown, "example.com:443", now),
            Err("session-unknown")
        );

        // Four streams at once, no more.
        for i in 1..4u16 {
            let r = books
                .reserve(&ticket(i, 1), "example.com:443", now)
                .unwrap();
            assert!(books.settle(&r, true, false));
        }
        assert_eq!(
            books.reserve(&ticket(4, 1), "example.com:443", now),
            Err("session-streams")
        );
        books.stream_closed(&init.digest);
        assert!(books.reserve(&ticket(4, 1), "example.com:443", now).is_ok());

        // Past the lifetime the book takes no spends; streams keep it alive until they end.
        let later = now + Duration::from_secs(91);
        books.moved(&init.digest, true, 10, later);
        assert_eq!(
            books.reserve(&ticket(5, 1), "example.com:443", later),
            Err("session-expired")
        );
        assert!(books.is_live(&init.digest));
        // Idle for the class timeout: closed, and later spends do not know it.
        books.sweep(later + Duration::from_secs(16));
        assert!(!books.is_live(&init.digest));
        assert_eq!(
            books.reserve(
                &ticket(5, 1),
                "example.com:443",
                later + Duration::from_secs(16)
            ),
            Err("session-unknown")
        );
    }

    /// The pinned session vectors (`testdata/vectors.json`, `sessionTickets`).
    #[test]
    fn digests_match_the_pinned_vectors() {
        let all: Value =
            serde_json::from_str(include_str!("../../../../testdata/vectors.json")).unwrap();
        let v = &all["sessionTickets"];
        let text = |x: &Value| x.as_str().unwrap().to_string();
        let secrets: Vec<[u8; 32]> = v["secretsHex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| microtor::util::hex_fixed::<32>(s.as_str().unwrap()).unwrap())
            .collect();
        let commitments: Vec<[u8; 32]> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| ticket_commitment(i as u16, s))
            .collect();
        let pinned: Vec<String> = v["commitments"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        assert_eq!(
            commitments.iter().map(|c| hex(c)).collect::<Vec<_>>(),
            pinned
        );
        let digest = book_digest(&commitments);
        assert_eq!(hex(&digest), text(&v["ticketBookDigest"]));
        let signal = session_signal(
            &text(&v["onion"]),
            &text(&v["classId"]),
            &text(&v["sessionNonce"]),
            &hex(&digest),
        );
        assert_eq!(signal, text(&v["signal"]));
        assert_eq!(
            crate::proto::calculate_signal_hash(&signal),
            text(&v["signalHashDecimal"])
        );
        let ticket = parse_ticket(&v["spend"]["ticket"]).unwrap();
        assert_eq!(ticket.secret, secrets[2]);
        assert_eq!(
            hex(&spend_digest(
                &ticket.book,
                ticket.index,
                &text(&v["spend"]["target"]),
                &ticket.request_nonce
            )),
            text(&v["spend"]["spendDigest"])
        );
        // The policy echo carries exactly the pinned fields.
        let init = Init {
            class: CLASSES[0],
            gateway: text(&v["onion"]),
            nonce: text(&v["sessionNonce"]),
            commitments,
            digest,
        };
        let reply: Value =
            serde_json::from_str(init_reply(&init, 41_943_040, 900_000).trim_end()).unwrap();
        assert_eq!(reply["session"]["policy"], v["policy"]);
    }

    #[test]
    fn ticket_grammar() {
        let good = json!({"v": 1, "book": hex(&[1; 32]), "i": 3, "t": b64url(&[7; 32]), "n": hex(&[2; 16])});
        assert!(parse_ticket(&good).is_ok());
        let check = |edit: &dyn Fn(&mut Value)| {
            let mut t = good.clone();
            edit(&mut t);
            parse_ticket(&t).err()
        };
        assert_eq!(parse_ticket(&json!(1)).err(), Some("ticket-malformed"));
        assert_eq!(check(&|t| t["v"] = 2.into()), Some("ticket-version"));
        assert_eq!(check(&|t| t["book"] = "zz".into()), Some("ticket-book"));
        assert_eq!(check(&|t| t["i"] = 64.into()), Some("ticket-index"));
        assert_eq!(check(&|t| t["t"] = "short".into()), Some("ticket-secret"));
        assert_eq!(check(&|t| t["n"] = "xyz".into()), Some("ticket-nonce"));
    }
}
