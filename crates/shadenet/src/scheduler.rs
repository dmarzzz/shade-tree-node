//! Budget planning and request-queue arithmetic (ADR 0013).
//!
//! Pure functions over a [`Budget`] snapshot. The proxy, `shadenet plan` and the `shadenet_plan`
//! MCP tool feed them live numbers; tests feed them fixtures. Nothing here touches the network,
//! the slot cursor or a session book.
//!
//! The model: a tier-`K` member proves at most `K` times per epoch. With session tickets off,
//! one proof is one tunnel. With tickets on (ADR 0011), one proof opens a book of
//! `tickets_per_book` tunnels at one node, so an epoch can open `K × tickets` tunnels, and
//! tickets left in live books are usable now without a proof.

use serde::{Deserialize, Serialize};

/// Default queue depth of time: hold a request for at most this many epochs before refusing.
pub const DEFAULT_MAX_WAIT_EPOCHS: u64 = 2;

/// A point-in-time view of what the member can spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Budget {
    /// `userMessageLimit`: proofs per epoch.
    pub tier: u64,
    pub epoch_seconds: u64,
    /// Seconds until the next epoch boundary.
    pub resets_in_seconds: u64,
    /// Proofs left in the current epoch.
    pub slots_left: u64,
    pub session_tickets: bool,
    /// Tunnels one proof buys when tickets are on (1 when they are off).
    pub tickets_per_book: u64,
    /// Unused tickets in live books right now (0 when tickets are off).
    pub tickets_open: u64,
}

impl Budget {
    /// Tunnels one proof buys.
    pub fn per_proof(&self) -> u64 {
        if self.session_tickets {
            self.tickets_per_book.max(1)
        } else {
            1
        }
    }

    /// Tunnels one whole epoch can open at most.
    pub fn capacity_per_epoch(&self) -> u64 {
        self.tier.max(1).saturating_mul(self.per_proof())
    }

    /// Tunnels openable now without waiting for an epoch boundary.
    pub fn available_now(&self) -> u64 {
        self.slots_left
            .saturating_mul(self.per_proof())
            .saturating_add(if self.session_tickets {
                self.tickets_open
            } else {
                0
            })
    }
}

/// What a batch of requests costs in epochs and seconds. Field names are the public JSON
/// contract of `shadenet plan --json`, `shadenet_plan` and the proxy's `/_shadenet/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub requests: u64,
    /// Requests already queued ahead of this batch.
    pub queue_depth: u64,
    pub tier: u64,
    pub epoch_seconds: u64,
    pub session_tickets: bool,
    pub tickets_per_book: u64,
    pub capacity_per_epoch: u64,
    pub available_now: u64,
    /// The batch opens without waiting.
    pub fits_now: bool,
    /// Epoch boundaries the batch has to wait through.
    pub waits: u64,
    /// Epochs touched, including the current one (0 for an empty batch).
    pub epochs_needed: u64,
    /// Seconds until the last request of the batch can open (0 when it fits now). A lower
    /// bound: proving and the Tor rendezvous add to it.
    pub completes_in_seconds: u64,
    /// The tier at which the whole batch fits in one epoch.
    pub one_epoch_tier: u64,
    pub advice: String,
}

/// Plan `requests` new tunnels behind `queue_depth` already-queued ones.
pub fn plan(budget: &Budget, requests: u64, queue_depth: u64) -> Plan {
    let per_proof = budget.per_proof();
    let capacity = budget.capacity_per_epoch();
    let available = budget.available_now();
    let total = queue_depth.saturating_add(requests);
    let (waits, completes_in) = if requests == 0 || total <= available {
        (0, 0)
    } else {
        let remaining = total - available;
        let waits = remaining.div_ceil(capacity);
        (
            waits,
            budget
                .resets_in_seconds
                .saturating_add(waits.saturating_sub(1).saturating_mul(budget.epoch_seconds)),
        )
    };
    let one_epoch_tier = if requests == 0 {
        budget.tier.max(1)
    } else {
        requests
            .div_ceil(per_proof)
            .clamp(1, crate::profile::MAX_LIMIT)
    };
    let fits_now = requests == 0 || waits == 0;
    let advice = if requests == 0 {
        "nothing to plan".to_string()
    } else if fits_now {
        format!("fits now: {available} tunnel(s) available this epoch, {requests} asked")
    } else {
        let tier_note = if one_epoch_tier > budget.tier {
            format!("; tier {one_epoch_tier} would do it in one epoch")
        } else {
            String::new()
        };
        format!(
            "needs {waits} more epoch(s): about {completes_in}s until the last tunnel can open{tier_note}"
        )
    };
    Plan {
        requests,
        queue_depth,
        tier: budget.tier,
        epoch_seconds: budget.epoch_seconds,
        session_tickets: budget.session_tickets,
        tickets_per_book: budget.tickets_per_book,
        capacity_per_epoch: capacity,
        available_now: available,
        fits_now,
        waits,
        epochs_needed: if requests == 0 { 0 } else { waits + 1 },
        completes_in_seconds: completes_in,
        one_epoch_tier,
        advice,
    }
}

/// Seconds until the request with `position` others ahead of it can open.
pub fn queue_eta_seconds(budget: &Budget, position: u64) -> u64 {
    plan(budget, 1, position).completes_in_seconds
}

/// How long a queued request may wait before the proxy refuses it instead.
pub fn default_max_wait_seconds(epoch_seconds: u64) -> u64 {
    epoch_seconds.max(1).saturating_mul(DEFAULT_MAX_WAIT_EPOCHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier1() -> Budget {
        Budget {
            tier: 1,
            epoch_seconds: 60,
            resets_in_seconds: 20,
            slots_left: 1,
            session_tickets: false,
            tickets_per_book: 6,
            tickets_open: 0,
        }
    }

    #[test]
    fn one_tunnel_per_proof_without_tickets() {
        let b = tier1();
        assert_eq!(b.per_proof(), 1);
        assert_eq!(b.capacity_per_epoch(), 1);
        assert_eq!(b.available_now(), 1);
        let p = plan(&b, 1, 0);
        assert!(p.fits_now);
        assert_eq!(
            (p.waits, p.epochs_needed, p.completes_in_seconds),
            (0, 1, 0)
        );
        // Ten fetches at tier 1: one now, nine more epochs; the ninth boundary is 20 + 8 × 60.
        let p = plan(&b, 10, 0);
        assert!(!p.fits_now);
        assert_eq!((p.waits, p.epochs_needed), (9, 10));
        assert_eq!(p.completes_in_seconds, 20 + 8 * 60);
        assert_eq!(p.one_epoch_tier, 10);
        assert!(p.advice.contains("tier 10 would do it in one epoch"));
    }

    #[test]
    fn tickets_multiply_capacity_and_open_tickets_count_now() {
        let b = Budget {
            session_tickets: true,
            slots_left: 0,
            tickets_open: 3,
            ..tier1()
        };
        assert_eq!(b.per_proof(), 6);
        assert_eq!(b.capacity_per_epoch(), 6);
        assert_eq!(b.available_now(), 3);
        assert!(plan(&b, 3, 0).fits_now);
        let p = plan(&b, 4, 0);
        assert_eq!((p.waits, p.completes_in_seconds), (1, 20));
        // Thirteen fetches need three proofs: tier 3 does it in one epoch.
        assert_eq!(plan(&b, 13, 0).one_epoch_tier, 3);
        // Tickets off: open tickets are not counted.
        let off = Budget {
            session_tickets: false,
            ..b
        };
        assert_eq!(off.available_now(), 0);
    }

    #[test]
    fn the_queue_ahead_pushes_the_eta_out() {
        let b = Budget {
            tier: 2,
            slots_left: 0,
            ..tier1()
        };
        assert_eq!(queue_eta_seconds(&b, 0), 20);
        assert_eq!(queue_eta_seconds(&b, 1), 20);
        assert_eq!(queue_eta_seconds(&b, 2), 80);
        assert_eq!(queue_eta_seconds(&b, 4), 140);
        let p = plan(&b, 2, 3);
        assert_eq!(p.queue_depth, 3);
        assert_eq!(p.waits, 3);
    }

    #[test]
    fn empty_batches_and_limits() {
        let b = tier1();
        let p = plan(&b, 0, 0);
        assert_eq!(
            (p.epochs_needed, p.waits, p.completes_in_seconds),
            (0, 0, 0)
        );
        assert_eq!(p.one_epoch_tier, 1);
        assert_eq!(
            plan(&b, u64::MAX, 0).one_epoch_tier,
            crate::profile::MAX_LIMIT
        );
        assert_eq!(default_max_wait_seconds(60), 120);
        assert_eq!(default_max_wait_seconds(0), 2);
    }
}
