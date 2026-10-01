//! Session tickets (session-v1): the pure ticket-book cryptography, byte for byte the same
//! as `lib/session-tickets.mjs` (pinned by `testdata/vectors.json` `sessionTickets`).
//!
//! One RLN proof whose signal commits to one node, one policy class, a session nonce and the
//! digest of a client-generated ticket book buys a bounded book of single-use tickets at that
//! node; each ticket then opens one destination tunnel with a cheap proof-less envelope inside
//! the proof's epoch payload budget (ADR 0011, `docs/design/SESSION-TICKETS.md`).
//!
//! Every string hashed here is a frozen wire string (`test/wire-freeze.selftest.mjs`).

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

pub const SESSION_VERSION: u64 = 1;
pub const SESSION_SIGNAL_PREFIX: &str = "shade-tree:session:v1\n";
pub const TICKET_DOMAIN: &str = "Shade Tree session ticket v1\n";
pub const TICKET_BOOK_DOMAIN: &str = "Shade Tree session ticket book v1\n";
pub const TICKET_SPEND_DOMAIN: &str = "Shade Tree session ticket spend v1\n";
pub const MAX_TICKETS: usize = 64;
pub const TICKET_SECRET_BYTES: usize = 32;

/// One policy class as the node echoes it after initialization (`lib/session-tickets.mjs
/// SESSION_CLASSES` / `policyEcho`). A client compares the echo field by field and fails
/// closed on any difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPolicy {
    pub class: &'static str,
    pub tickets: u64,
    pub max_payload_bytes: u64,
    pub lifetime_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_concurrent_streams: u64,
}

/// The only class of the research preview.
pub const RESEARCH_V1: ClassPolicy = ClassPolicy {
    class: "research-v1",
    tickets: 6,
    max_payload_bytes: 41_943_040,
    lifetime_ms: 90_000,
    idle_timeout_ms: 15_000,
    max_concurrent_streams: 4,
};

/// `research-v2` (ADR 0013): the same book and limits, with a 60 s idle timeout instead of
/// 15 s, so an agent that opens one connection at a time (curl, httpx without a pool, SearXNG
/// engines, one-shot fetches through the proxy) keeps its book across the gaps. Nodes that
/// advertise it are preferred by clients; nodes that do not still serve `research-v1`.
pub const RESEARCH_V2: ClassPolicy = ClassPolicy {
    class: "research-v2",
    tickets: 6,
    max_payload_bytes: 41_943_040,
    lifetime_ms: 90_000,
    idle_timeout_ms: 60_000,
    max_concurrent_streams: 4,
};

/// The classes this implementation understands, preferred first.
pub const CLASSES: [ClassPolicy; 2] = [RESEARCH_V2, RESEARCH_V1];

/// The best class a node that advertises `advertised` can serve, in this implementation's
/// order of preference.
pub fn preferred_class(advertised: &[String]) -> Option<&'static ClassPolicy> {
    CLASSES
        .iter()
        .find(|class| advertised.iter().any(|id| id == class.class))
}

pub fn class_policy(id: &str) -> Option<&'static ClassPolicy> {
    CLASSES.iter().find(|c| c.class == id)
}

/// Class-id grammar `^[a-z0-9][a-z0-9-]{0,31}$`.
pub fn is_class_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    let ok_first = b[0].is_ascii_lowercase() || b[0].is_ascii_digit();
    ok_first
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn is_nonce32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `<56 base32>.onion`, lowercase.
pub fn is_session_onion(s: &str) -> bool {
    let Some(name) = s.strip_suffix(".onion") else {
        return false;
    };
    name.len() == 56
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

pub fn normalize_onion(onion: &str) -> String {
    let s = onion.trim().to_ascii_lowercase();
    if s.ends_with(".onion") {
        s
    } else {
        format!("{s}.onion")
    }
}

/// `ticketCommitment_i = SHA256(TICKET_DOMAIN || u16be(i) || secret_i)`, lowercase hex.
pub fn ticket_commitment(index: u16, secret: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(TICKET_DOMAIN.as_bytes());
    h.update(index.to_be_bytes());
    h.update(secret);
    hex::encode(h.finalize())
}

/// `ticketBookDigest = SHA256(TICKET_BOOK_DOMAIN || u16be(N) || c_0 || ... || c_(N-1))` over
/// the raw commitment bytes.
pub fn ticket_book_digest(commitments: &[String]) -> Result<String, String> {
    if commitments.is_empty() || commitments.len() > MAX_TICKETS {
        return Err("a ticket book holds 1..64 commitments".into());
    }
    let mut h = Sha256::new();
    h.update(TICKET_BOOK_DOMAIN.as_bytes());
    h.update((commitments.len() as u16).to_be_bytes());
    for c in commitments {
        if !is_hex64(c) {
            return Err("commitments are 64 lowercase hex characters".into());
        }
        h.update(hex::decode(c).map_err(|e| e.to_string())?);
    }
    Ok(hex::encode(h.finalize()))
}

/// `spendDigest = SHA256(TICKET_SPEND_DOMAIN || digest || u16be(i) || u16be(len(target))
/// || target || requestNonce)`; node-local and ephemeral.
pub fn spend_digest(
    ticket_book_digest: &str,
    index: u16,
    target: &str,
    request_nonce: &str,
) -> Result<String, String> {
    if !is_hex64(ticket_book_digest) {
        return Err("ticketBookDigest must be 64 hex characters".into());
    }
    if !is_nonce32(request_nonce) {
        return Err("requestNonce must be 32 hex characters".into());
    }
    let t = target.as_bytes();
    if t.is_empty() || t.len() > 256 {
        return Err("target must be 1..256 bytes".into());
    }
    let mut h = Sha256::new();
    h.update(TICKET_SPEND_DOMAIN.as_bytes());
    h.update(hex::decode(ticket_book_digest).map_err(|e| e.to_string())?);
    h.update(index.to_be_bytes());
    h.update((t.len() as u16).to_be_bytes());
    h.update(t);
    h.update(hex::decode(request_nonce).map_err(|e| e.to_string())?);
    Ok(hex::encode(h.finalize()))
}

/// The RLN signal of a session initialization:
/// `shade-tree:session:v1\n<onion>\n<class>\n<nonce>\n<digest>`.
pub fn session_signal(
    gateway: &str,
    class_id: &str,
    nonce: &str,
    ticket_book_digest: &str,
) -> Result<String, String> {
    let onion = normalize_onion(gateway);
    if !is_session_onion(&onion) {
        return Err("gateway must be a v3 .onion".into());
    }
    if !is_class_id(class_id) {
        return Err("class id grammar is ^[a-z0-9][a-z0-9-]{0,31}$".into());
    }
    if !is_nonce32(nonce) {
        return Err("session nonce must be 32 hex characters".into());
    }
    if !is_hex64(ticket_book_digest) {
        return Err("ticketBookDigest must be 64 hex characters".into());
    }
    Ok(format!(
        "{SESSION_SIGNAL_PREFIX}{onion}\n{class_id}\n{nonce}\n{ticket_book_digest}"
    ))
}

/// A client-side ticket book built from caller-supplied 32-byte secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBook {
    pub commitments: Vec<String>,
    pub ticket_book_digest: String,
}

pub fn build_ticket_book(secrets: &[[u8; 32]]) -> Result<TicketBook, String> {
    let commitments: Vec<String> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| ticket_commitment(i as u16, s))
        .collect();
    let mut dedup = commitments.clone();
    dedup.sort_unstable();
    dedup.dedup();
    if dedup.len() != commitments.len() {
        return Err("duplicate ticket secret".into());
    }
    let ticket_book_digest = ticket_book_digest(&commitments)?;
    Ok(TicketBook {
        commitments,
        ticket_book_digest,
    })
}

/// Unpadded base64url of a ticket secret (43 chars).
pub fn encode_ticket_secret(secret: &[u8; 32]) -> String {
    BASE64URL_NOPAD.encode(secret)
}

/// Decodes exactly one canonical 32-byte secret; anything else is `None`.
pub fn decode_ticket_secret(s: &str) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    let bytes = BASE64URL_NOPAD.decode(s.as_bytes()).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        assert!(is_class_id("research-v1"));
        assert!(is_class_id("research-v2"));
        assert_eq!(
            class_policy("research-v2").map(|c| c.idle_timeout_ms),
            Some(60_000)
        );
        assert_eq!(
            preferred_class(&["research-v1".into(), "research-v2".into()]).map(|c| c.class),
            Some("research-v2")
        );
        assert_eq!(
            preferred_class(&["research-v1".into()]).map(|c| c.class),
            Some("research-v1")
        );
        assert!(preferred_class(&["research-v9".into()]).is_none());
        assert!(!is_class_id("Research"));
        assert!(!is_class_id("-x"));
        assert!(!is_class_id(""));
        assert!(!is_class_id(&"a".repeat(33)));
        assert!(is_nonce32(&"a".repeat(32)));
        assert!(!is_nonce32(&"A".repeat(32)));
        assert!(is_session_onion(
            "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion"
        ));
        assert!(!is_session_onion("example.com"));
    }

    #[test]
    fn base64url_roundtrip_and_non_canonical_rejected() {
        let s = [3u8; 32];
        let enc = encode_ticket_secret(&s);
        assert_eq!(enc.len(), 43);
        assert_eq!(decode_ticket_secret(&enc), Some(s));
        // Non-canonical trailing bits and padding are rejected.
        let mut bad = enc.clone();
        bad.pop();
        bad.push('B');
        assert_eq!(decode_ticket_secret(&bad), None);
        assert_eq!(decode_ticket_secret(&format!("{enc}=")), None);
    }

    #[test]
    fn signal_rejects_bad_fields() {
        let d = "0".repeat(64);
        let n = "0".repeat(32);
        let onion = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad";
        assert!(session_signal(onion, "research-v1", &n, &d).is_ok());
        assert!(session_signal("nope", "research-v1", &n, &d).is_err());
        assert!(session_signal(onion, "Bad", &n, &d).is_err());
        assert!(session_signal(onion, "research-v1", "zz", &d).is_err());
        assert!(session_signal(onion, "research-v1", &n, "zz").is_err());
    }
}
