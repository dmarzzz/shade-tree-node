//! The spent set and the per-slot byte budget.
//!
//! One RLN message slot yields one nullifier per epoch. Seeing the same nullifier with a
//! second signal means the member spent a slot twice; the two shares together reveal the
//! identity secret, which is what makes the rate limit enforceable.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// First sighting of this nullifier.
    First,
    /// The same envelope again inside the retry window.
    Replay,
    Refused(&'static str),
    /// A second distinct signal on one slot: `(first share, this share)`.
    OverSpend {
        first: (String, String),
        second: (String, String),
    },
}

struct Seen {
    x: String,
    y: String,
    slashed: bool,
    at_ms: u64,
}

pub struct SpentSet {
    seen: HashMap<String, Seen>,
    /// `nullifier|x|nonce` to the time it was first seen.
    envelopes: HashMap<String, u64>,
    replay_window_ms: u64,
    max_age_ms: u64,
    capacity: usize,
}

impl SpentSet {
    /// Entries live for two epochs. `capacity` bounds memory: when full, new nullifiers are
    /// refused rather than old ones forgotten, because forgetting one would reopen its slot.
    pub fn new(epoch_seconds: u64, replay_window_ms: u64, capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            envelopes: HashMap::new(),
            replay_window_ms: if replay_window_ms == 0 {
                5000
            } else {
                replay_window_ms
            },
            max_age_ms: 2 * epoch_seconds * 1000,
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn sweep(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.max_age_ms);
        self.seen.retain(|_, s| s.at_ms >= cutoff);
        self.envelopes.retain(|_, at| *at >= cutoff);
    }

    pub fn admit(
        &mut self,
        nullifier: &str,
        x: &str,
        y: &str,
        nonce: &str,
        now_ms: u64,
    ) -> Admission {
        let envelope_key = format!("{nullifier}|{x}|{nonce}");
        match self.seen.get_mut(nullifier) {
            None => {
                if self.seen.len() >= self.capacity {
                    self.sweep(now_ms);
                    if self.seen.len() >= self.capacity {
                        return Admission::Refused("busy");
                    }
                }
                self.seen.insert(
                    nullifier.to_string(),
                    Seen {
                        x: x.to_string(),
                        y: y.to_string(),
                        slashed: false,
                        at_ms: now_ms,
                    },
                );
                self.envelopes.insert(envelope_key, now_ms);
                Admission::First
            }
            Some(seen) if seen.slashed => Admission::Refused("rate-slashed"),
            Some(seen) if seen.x == x => match self.envelopes.get(&envelope_key) {
                Some(first) if now_ms.saturating_sub(*first) <= self.replay_window_ms => {
                    Admission::Replay
                }
                _ => Admission::Refused("replayed-envelope"),
            },
            Some(seen) => {
                seen.slashed = true;
                Admission::OverSpend {
                    first: (seen.x.clone(), seen.y.clone()),
                    second: (x.to_string(), y.to_string()),
                }
            }
        }
    }
}

struct Slot {
    used: u64,
    active: u32,
    touched_ms: u64,
}

/// Bytes relayed per `(externalNullifier, nullifier)`, both directions together.
pub struct Budget {
    slots: HashMap<String, Slot>,
    max: u64,
    idle_ms: u64,
}

pub fn slot_key(external_nullifier: &str, nullifier: &str) -> String {
    format!("{external_nullifier}\0{nullifier}")
}

impl Budget {
    /// `max` of zero means unlimited.
    pub fn new(max: u64, epoch_seconds: u64) -> Self {
        Self {
            slots: HashMap::new(),
            max,
            idle_ms: 2 * epoch_seconds * 1000,
        }
    }

    /// Take a hold on a slot for one tunnel. False when the allowance is already used up.
    pub fn acquire(&mut self, key: &str, now_ms: u64) -> bool {
        let idle = self.idle_ms;
        self.slots
            .retain(|_, s| s.active > 0 || now_ms.saturating_sub(s.touched_ms) < idle);
        let slot = self.slots.entry(key.to_string()).or_insert(Slot {
            used: 0,
            active: 0,
            touched_ms: now_ms,
        });
        if self.max != 0 && slot.used >= self.max {
            return false;
        }
        slot.active += 1;
        slot.touched_ms = now_ms;
        true
    }

    pub fn release(&mut self, key: &str, now_ms: u64) {
        if let Some(slot) = self.slots.get_mut(key) {
            slot.active = slot.active.saturating_sub(1);
            slot.touched_ms = now_ms;
        }
    }

    /// How many of `wanted` bytes may pass, and whether the allowance is now exhausted.
    pub fn take(&mut self, key: &str, wanted: usize) -> (usize, bool) {
        if self.max == 0 {
            return (wanted, false);
        }
        let Some(slot) = self.slots.get_mut(key) else {
            return (0, true);
        };
        let remaining = self.max.saturating_sub(slot.used);
        let allowed = (wanted as u64).min(remaining);
        slot.used += allowed;
        (allowed as usize, slot.used >= self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_replays_and_over_spends() {
        let mut set = SpentSet::new(60, 5000, 8);
        assert_eq!(set.admit("n1", "x1", "y1", "nonce", 1000), Admission::First);
        assert_eq!(
            set.admit("n1", "x1", "y1", "nonce", 3000),
            Admission::Replay
        );
        assert_eq!(
            set.admit("n1", "x1", "y1", "nonce", 7000),
            Admission::Refused("replayed-envelope")
        );
        assert_eq!(
            set.admit("n1", "x1", "y1", "other", 2000),
            Admission::Refused("replayed-envelope")
        );
        assert_eq!(
            set.admit("n1", "x2", "y2", "nonce", 2000),
            Admission::OverSpend {
                first: ("x1".into(), "y1".into()),
                second: ("x2".into(), "y2".into())
            }
        );
        assert_eq!(
            set.admit("n1", "x1", "y1", "nonce", 2100),
            Admission::Refused("rate-slashed")
        );
        // Two epochs later the entry is gone.
        set.sweep(1000 + 120_001);
        assert!(set.is_empty());
    }

    #[test]
    fn a_full_set_refuses_instead_of_forgetting() {
        let mut set = SpentSet::new(60, 5000, 2);
        assert_eq!(set.admit("a", "x", "y", "n", 0), Admission::First);
        assert_eq!(set.admit("b", "x", "y", "n", 0), Admission::First);
        assert_eq!(
            set.admit("c", "x", "y", "n", 10),
            Admission::Refused("busy")
        );
        assert_eq!(set.admit("c", "x", "y", "n", 120_001), Admission::First);
    }

    #[test]
    fn budget_truncates_at_the_limit() {
        let mut budget = Budget::new(100, 60);
        let key = slot_key("e", "n");
        assert!(budget.acquire(&key, 0));
        assert_eq!(budget.take(&key, 60), (60, false));
        assert_eq!(budget.take(&key, 60), (40, true));
        assert_eq!(budget.take(&key, 1), (0, true));
        budget.release(&key, 10);
        // A retry on the same slot gets what is left: nothing.
        assert!(!budget.acquire(&key, 20));
        // After two idle epochs the slot is forgotten.
        assert!(budget.acquire(&key, 10 + 120_000));
    }
}
