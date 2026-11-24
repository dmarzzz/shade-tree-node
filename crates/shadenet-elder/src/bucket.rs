//! The global announce token bucket (`makeAnnounceBucket`): the last gate before signature
//! verification, bounding how many announces per second reach ed25519 whoever sends them.
//! Refill is driven by the caller's clock in whole seconds; fractional tokens accumulate, so a
//! rate under one per second still refills. Rate and burst both zero disables it.

pub(crate) struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: u64,
    disabled: bool,
}

/// The default sizing from the registry cap and the fleet heartbeat: refill
/// `2 * max_entries / heartbeat` per second, burst `max(100, max_entries / 10)`.
pub(crate) fn defaults(max_entries: f64, heartbeat_secs: f64) -> (f64, f64) {
    (
        2.0 * max_entries / heartbeat_secs,
        (max_entries / 10.0).floor().max(100.0),
    )
}

impl Bucket {
    pub(crate) fn new(rate: f64, burst: f64, now: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last: now,
            disabled: rate <= 0.0 && burst <= 0.0,
        }
    }

    pub(crate) fn rate(&self) -> f64 {
        self.rate
    }

    pub(crate) fn burst(&self) -> f64 {
        self.burst
    }

    /// Tokens available at `now`, after refilling.
    pub(crate) fn tokens(&mut self, now: u64) -> f64 {
        if now > self.last {
            self.tokens = (self.tokens + (now - self.last) as f64 * self.rate).min(self.burst);
            self.last = now;
        }
        self.tokens
    }

    /// Spend one token if there is one.
    pub(crate) fn take(&mut self, now: u64) -> bool {
        if self.disabled {
            return true;
        }
        if self.tokens(now) < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    /// Seconds until one token is available, for `Retry-After`; at least 1.
    pub(crate) fn retry_after_secs(&self) -> u64 {
        if self.rate > 0.0 {
            (((1.0 - self.tokens) / self.rate).ceil() as u64).max(1)
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill_at_rate_with_fractional_tokens() {
        let mut t = 1000;
        let mut b = Bucket::new(0.5, 3.0, t);
        assert!(b.take(t) && b.take(t) && b.take(t));
        assert!(!b.take(t), "fourth in the same instant refused");
        assert!(b.retry_after_secs() >= 1);
        t += 1;
        assert!(!b.take(t), "half a token after one second");
        t += 1;
        assert!(b.take(t), "one token after two seconds");
        t += 100;
        assert_eq!(b.tokens(t), 3.0, "refill caps at burst");
        let mut off = Bucket::new(0.0, 0.0, t);
        assert!((0..20).all(|_| off.take(t)), "rate and burst zero disables");
    }

    #[test]
    fn defaults_derive_from_the_cap_and_the_heartbeat() {
        let (rate, burst) = defaults(10_000.0, 300.0);
        assert!((rate - 66.666).abs() < 0.01);
        assert_eq!(burst, 1000.0);
        assert_eq!(
            defaults(50.0, 300.0).1,
            100.0,
            "floor of 100 for tiny registries"
        );
        assert!(
            10_000.0 / 300.0 < rate,
            "a full fleet at cadence draws half the refill"
        );
    }

    #[test]
    fn a_fleet_at_heartbeat_cadence_never_hits_the_bucket() {
        let (n, heartbeat) = (200_u64, 300_u64);
        let (rate, burst) = defaults(n as f64, heartbeat as f64);
        let mut b = Bucket::new(rate, burst, 0);
        let mut refused = 0;
        for sec in 0..heartbeat * 6 {
            for g in 0..n {
                if sec % heartbeat == (g * 7919) % heartbeat && !b.take(sec) {
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 0);
        let (rate, burst) = defaults(10_000.0, 300.0);
        let mut b = Bucket::new(rate, burst, 0);
        for cycle in 0..4 {
            for _ in 0..1000 {
                assert!(
                    b.take(cycle * heartbeat),
                    "a lockstep restart of a burst-sized fleet passes"
                );
            }
        }
        let passed = (0..10_000).filter(|_| b.take(10_000)).count();
        assert_eq!(
            passed, burst as usize,
            "a fresh-onion flood gets exactly burst verifies"
        );
    }
}
