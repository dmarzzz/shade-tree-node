//! Tor circuit isolation for session-ticket books (ADR 0011).
//!
//! Every tunnel of one book is already linkable at its node as that book, so the client lets
//! them share one Tor circuit: the initialization and every ticket spend of a book dial with the
//! book's [`CircuitIsolation`], and a ticket spend costs one `RELAY_BEGIN` instead of a new
//! rendezvous. Different books never share a value. `--circuit-per-tunnel`
//! (`Config::circuit_per_tunnel`) keeps the stricter posture: every tunnel gets its own
//! isolation group, as a proof-carrying tunnel always does.

/// One isolation group: streams dialed with equal values may share a circuit; streams with
/// different values never do. [`CircuitIsolation::new`] never returns a value it returned
/// before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitIsolation(Token);

#[cfg(feature = "live")]
type Token = arti_client::IsolationToken;

#[cfg(not(feature = "live"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Token(u64);

#[cfg(not(feature = "live"))]
impl Token {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl CircuitIsolation {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Token::new())
    }

    /// The Arti token streams of this group carry (`StreamPrefs::set_isolation`).
    #[cfg(feature = "live")]
    pub(crate) fn token(self) -> arti_client::IsolationToken {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_new_group_is_distinct_and_copies_are_equal() {
        let a = CircuitIsolation::new();
        let b = CircuitIsolation::new();
        assert_ne!(a, b);
        let copy = a;
        assert_eq!(a, copy);
    }
}
