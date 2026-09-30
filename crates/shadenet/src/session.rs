//! Client-side session-ticket books (ADR 0011). A [`SessionPool`] keeps at most one live
//! book per node onion; [`Client::connect`](crate::Client::connect) spends a ticket from a
//! live book before it proves anything, and initializes a new book (one RLN slot) only when
//! no usable ticket is left. Secrets are zeroized when a book is dropped.
//!
//! Linkability is explicit: every tunnel of one book is linkable to the serving node as the
//! same book (the RLN proof still hides the member). Per-tunnel gateway rotation is traded
//! for cheap tunnels; the flag stays off unless the deployment record or the operator says so.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shadenet_proto::session::{self as st, ClassPolicy};
use zeroize::Zeroizing;

/// The ticket the pool hands out for one spend.
pub struct Ticket {
    pub onion: String,
    pub ticket_book_digest: String,
    pub index: u16,
    pub secret: [u8; 32],
    pub request_nonce: String,
}

/// One live book at one node.
pub struct LiveBook {
    pub onion: String,
    pub class: &'static ClassPolicy,
    pub nonce: String,
    pub commitments: Vec<String>,
    pub ticket_book_digest: String,
    secrets: Vec<Zeroizing<[u8; 32]>>,
    unused: Vec<u16>,
    opened_at: Instant,
    last_use: Instant,
}

impl LiveBook {
    fn expired(&self, now: Instant) -> bool {
        // Leave a margin under the node's clocks: a ticket spent in the last second of the
        // lifetime is a wasted round trip, and an idle book closes on the node first.
        let lifetime = Duration::from_millis(self.class.lifetime_ms.saturating_sub(1_000));
        let idle = Duration::from_millis(self.class.idle_timeout_ms.saturating_sub(1_000));
        now.duration_since(self.opened_at) >= lifetime || now.duration_since(self.last_use) >= idle
    }

    pub fn tickets_left(&self) -> usize {
        self.unused.len()
    }
}

/// A book under construction: secrets drawn, commitments and digest computed, not yet proved.
pub struct PendingBook {
    pub onion: String,
    pub class: &'static ClassPolicy,
    pub nonce: String,
    pub commitments: Vec<String>,
    pub ticket_book_digest: String,
    secrets: Vec<Zeroizing<[u8; 32]>>,
}

impl PendingBook {
    /// Draw `class.tickets` fresh secrets from the OS CSPRNG and commit to them.
    pub fn draw(onion: &str, class: &'static ClassPolicy) -> Result<Self, String> {
        let mut secrets = Vec::with_capacity(class.tickets as usize);
        let mut raw = Vec::with_capacity(class.tickets as usize);
        for _ in 0..class.tickets {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).map_err(|e| format!("ticket randomness: {e}"))?;
            raw.push(s);
            secrets.push(Zeroizing::new(s));
        }
        let book = st::build_ticket_book(&raw)?;
        for s in raw.iter_mut() {
            *s = [0u8; 32];
        }
        let mut n = [0u8; 16];
        getrandom::fill(&mut n).map_err(|e| format!("session nonce: {e}"))?;
        Ok(Self {
            onion: st::normalize_onion(onion),
            class,
            nonce: hex::encode(n),
            commitments: book.commitments,
            ticket_book_digest: book.ticket_book_digest,
            secrets,
        })
    }
}

/// Verify the node's policy echo against the class table; a difference fails closed.
pub fn policy_matches(echo: &serde_json::Value, class: &ClassPolicy) -> bool {
    let u = |k: &str| echo.get(k).and_then(serde_json::Value::as_u64);
    echo.get("class").and_then(serde_json::Value::as_str) == Some(class.class)
        && u("tickets") == Some(class.tickets)
        && u("maxPayloadBytes") == Some(class.max_payload_bytes)
        && u("lifetimeMs") == Some(class.lifetime_ms)
        && u("idleTimeoutMs") == Some(class.idle_timeout_ms)
        && u("maxConcurrentStreams") == Some(class.max_concurrent_streams)
}

#[derive(Default)]
pub struct SessionPool {
    books: Mutex<HashMap<String, LiveBook>>,
}

impl SessionPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a book the node accepted (its ack carried a matching policy echo).
    pub fn install(&self, pending: PendingBook) {
        let now = Instant::now();
        let unused = (0..pending.class.tickets as u16).collect();
        let book = LiveBook {
            onion: pending.onion.clone(),
            class: pending.class,
            nonce: pending.nonce,
            commitments: pending.commitments,
            ticket_book_digest: pending.ticket_book_digest,
            secrets: pending.secrets,
            unused,
            opened_at: now,
            last_use: now,
        };
        self.books
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(pending.onion, book);
    }

    /// Take one unused ticket from a live, unexpired book at one of `onions` (in order).
    pub fn take(&self, onions: &[String]) -> Option<Ticket> {
        let now = Instant::now();
        let mut books = self.books.lock().unwrap_or_else(|p| p.into_inner());
        books.retain(|_, b| !b.expired(now));
        for onion in onions {
            let key = st::normalize_onion(onion);
            let Some(book) = books.get_mut(&key) else {
                continue;
            };
            if book.unused.is_empty() {
                continue;
            }
            let index = book.unused.remove(0);
            book.last_use = now;
            let mut n = [0u8; 16];
            if getrandom::fill(&mut n).is_err() {
                return None;
            }
            return Some(Ticket {
                onion: key,
                ticket_book_digest: book.ticket_book_digest.clone(),
                index,
                secret: *book.secrets[index as usize],
                request_nonce: hex::encode(n),
            });
        }
        None
    }

    /// A definite pre-connect refusal that the node refunded (`upstream:*`, `bad-target*`):
    /// the ticket may be tried again.
    pub fn refund(&self, ticket: &Ticket) {
        let mut books = self.books.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(book) = books.get_mut(&ticket.onion) {
            if book.ticket_book_digest == ticket.ticket_book_digest
                && !book.unused.contains(&ticket.index)
            {
                book.unused.insert(0, ticket.index);
            }
        }
    }

    /// The node no longer knows the book (expired, idle, conflict): drop it.
    pub fn forget(&self, onion: &str) {
        self.books
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&st::normalize_onion(onion));
    }

    /// Live books and their remaining tickets, for `status`.
    pub fn summary(&self) -> Vec<(String, usize)> {
        let now = Instant::now();
        let books = self.books.lock().unwrap_or_else(|p| p.into_inner());
        books
            .values()
            .filter(|b| !b.expired(now))
            .map(|b| (b.onion.clone(), b.tickets_left()))
            .collect()
    }
}

/// Whether a session refusal means the whole book is gone (vs. one ticket).
pub fn refusal_drops_book(reason: &str) -> bool {
    matches!(
        reason,
        "session-unknown"
            | "session-expired"
            | "session-idle"
            | "session-conflict"
            | "session-unsupported"
    )
}

/// Whether a refusal left the ticket unused on the node (definite pre-connect failure).
pub fn refusal_refunds_ticket(reason: &str) -> bool {
    reason.starts_with("upstream:") && !reason.contains("ETIMEDOUT")
        || reason.starts_with("bad-target")
        || reason == "session-streams"
        || reason == "session-pending"
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";

    #[test]
    fn a_book_hands_out_each_ticket_once_and_refunds_only_definite_failures() {
        let pool = SessionPool::new();
        let pending = PendingBook::draw(ONION, &st::RESEARCH_V1).unwrap();
        assert_eq!(pending.commitments.len(), 6);
        assert_eq!(
            st::ticket_book_digest(&pending.commitments).unwrap(),
            pending.ticket_book_digest
        );
        let commitments = pending.commitments.clone();
        pool.install(pending);
        let onions = vec![ONION.to_string()];
        let mut seen = Vec::new();
        for _ in 0..6 {
            let t = pool.take(&onions).expect("a ticket");
            assert_eq!(t.onion, ONION);
            seen.push(t);
        }
        assert!(pool.take(&onions).is_none(), "six tickets, no more");
        let indices: Vec<u16> = seen.iter().map(|t| t.index).collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5]);
        // Each ticket's secret commits to its index.
        for t in &seen {
            assert_eq!(
                st::ticket_commitment(t.index, &t.secret),
                commitments[t.index as usize]
            );
        }
        pool.refund(&seen[2]);
        let again = pool.take(&onions).unwrap();
        assert_eq!(again.index, 2);
        pool.refund(&again);
        pool.refund(&again);
        assert_eq!(pool.summary(), vec![(ONION.to_string(), 1)]);
        pool.forget(ONION);
        assert!(pool.take(&onions).is_none());
    }

    #[test]
    fn policy_echo_must_match_the_class_exactly() {
        let good = serde_json::json!({
            "class": "research-v1", "tickets": 6, "maxPayloadBytes": 41943040,
            "lifetimeMs": 90000, "idleTimeoutMs": 15000, "maxConcurrentStreams": 4
        });
        assert!(policy_matches(&good, &st::RESEARCH_V1));
        let mut bad = good.clone();
        bad["tickets"] = serde_json::json!(7);
        assert!(!policy_matches(&bad, &st::RESEARCH_V1));
        assert!(!policy_matches(&serde_json::json!({}), &st::RESEARCH_V1));
    }

    #[test]
    fn refusal_classification() {
        assert!(refusal_drops_book("session-expired"));
        assert!(!refusal_drops_book("ticket-spent"));
        assert!(refusal_refunds_ticket("upstream:ECONNREFUSED"));
        assert!(!refusal_refunds_ticket("upstream:ETIMEDOUT"));
        assert!(refusal_refunds_ticket("bad-target-dns"));
        assert!(!refusal_refunds_ticket("ticket-mismatch"));
    }
}
