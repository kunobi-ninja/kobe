//! Optional admission throttling, shared per replica and authenticated identity.
//! With the default zero burst, requests are counted but never throttled. A
//! configured burst refills over twenty seconds. The bucket is charged before
//! admission work, including failed attempts. Rejections carry Retry-After.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Explicit burst used by admission regression tests.
#[cfg(test)]
pub(crate) const ADMISSION_BURST: f64 = 10.0;

/// Refill rate for the test fixture's ten-token burst.
#[cfg(test)]
const ADMISSION_REFILL_PER_SEC: f64 = 0.5;

/// Ceiling on distinct principals tracked at once.
///
/// The map only ever holds principals that attempted admission within the last
/// twenty seconds (anything older
/// has refilled and is pruned), so this bound is reached only under a genuine
/// flood from thousands of distinct credentials.
const MAX_TRACKED_PRINCIPALS: usize = 10_000;

/// What the limiter decided about one attempt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RateLimitDecision {
    /// Budget was available and has been spent. The attempt may proceed.
    Allowed,
    /// No budget. Nothing was spent, and the caller may retry after this long.
    Throttled { retry_after: Duration },
}

/// One principal's budget.
///
/// A bucket that has refilled to its configured burst is indistinguishable from
/// a bucket that has never been used, which is what makes eviction safe: the
/// limiter can forget an idle principal without ever giving them budget they
/// had not already earned back.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    burst: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn fresh(now: Instant, burst: f64) -> Self {
        Self {
            tokens: burst,
            burst,
            updated_at: now,
        }
    }

    /// Tokens accrued since the last update, clamped to the burst ceiling.
    ///
    /// `saturating_duration_since` matters even though [`Instant`] is
    /// monotonic: on a platform where two reads can tie, an unchecked
    /// subtraction would panic in a release-critical path to save nothing.
    fn refilled(self, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.updated_at).as_secs_f64();
        (self.tokens + elapsed * (self.burst / 20.0)).min(self.burst)
    }

    /// Spend one token if there is one. Pure: `now` is supplied, so every
    /// boundary here is testable without sleeping or reaching a cluster.
    fn take(&mut self, now: Instant) -> RateLimitDecision {
        let tokens = self.refilled(now);
        self.updated_at = now;
        if tokens >= 1.0 {
            self.tokens = tokens - 1.0;
            return RateLimitDecision::Allowed;
        }
        self.tokens = tokens;
        RateLimitDecision::Throttled {
            retry_after: Duration::from_secs_f64((1.0 - tokens) / (self.burst / 20.0)),
        }
    }

    /// Whether this bucket now carries exactly what a new one would, and can
    /// therefore be dropped without changing any future decision.
    fn is_idle(&self, now: Instant) -> bool {
        self.refilled(now) >= self.burst
    }
}

/// Shared, per-process admission budget keyed by principal.
///
/// Mirrors the connect cache's shape — a `std::sync::Mutex` around a small map.
/// Entries are two words and every operation is a hash lookup, so a coarse lock
/// is cheaper here than anything asynchronous, and it is never held across an
/// `.await`.
#[derive(Clone)]
pub struct AdmissionRateLimiter(Arc<Mutex<HashMap<String, TokenBucket>>>, u64);

impl Default for AdmissionRateLimiter {
    fn default() -> Self {
        Self::with_burst(crate::sandbox_limits::get().admission_burst)
    }
}

impl AdmissionRateLimiter {
    /// Zero disables rate enforcement. A configured bucket refills in 20s.
    pub(crate) fn with_burst(burst: u64) -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())), burst)
    }

    /// Charge one admission attempt against `principal`.
    ///
    /// `principal` must be the same digest that names the quota and alias
    /// reservations, so the limiter and the ledger cannot disagree about who a
    /// caller is — a limiter keyed on anything narrower would be evadable by
    /// whatever the two definitions disagreed on.
    pub(crate) fn charge(&self, principal: &str) -> RateLimitDecision {
        self.charge_at(principal, Instant::now())
    }

    fn charge_at(&self, principal: &str, now: Instant) -> RateLimitDecision {
        crate::metrics::SANDBOX_ADMISSION_ATTEMPTS.inc();
        if self.1 == 0 {
            return RateLimitDecision::Allowed;
        }

        let mut buckets = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(bucket) = buckets.get_mut(principal) {
            return bucket.take(now);
        }

        if buckets.len() >= MAX_TRACKED_PRINCIPALS {
            buckets.retain(|_, bucket| !bucket.is_idle(now));
        }
        if buckets.len() >= MAX_TRACKED_PRINCIPALS {
            // Fail closed. Forgetting an active principal to make room is the
            // evasion itself: a flood of distinct credentials would evict the
            // very buckets holding it back, and the limiter would disable
            // itself exactly when it is needed. Refusing instead keeps the
            // apiserver-write bound intact, which is what this protects.
            return RateLimitDecision::Throttled {
                retry_after: Duration::from_secs_f64(20.0 / self.1 as f64),
            };
        }

        let mut bucket = TokenBucket::fresh(now, self.1 as f64);
        let decision = bucket.take(now);
        buckets.insert(principal.to_string(), bucket);
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_unlimited_by_default() {
        let limiter = AdmissionRateLimiter::default();
        for _ in 0..1000 {
            assert_eq!(limiter.charge("caller"), RateLimitDecision::Allowed);
        }
        assert!(limiter.0.lock().unwrap().is_empty());
    }

    /// A caller who is refused must still be charged.
    ///
    /// If budget were spent only by attempts that end in success, a principal
    /// at their concurrency limit could retry forever: every attempt fails, so
    /// every attempt is free, while each one still costs the apiserver a lease
    /// CREATE plus reservation CREATEs plus a DELETE. The limiter has no view
    /// of the outcome by construction — this pins that it never grows one.
    #[test]
    fn budget_is_spent_by_the_attempt_not_by_its_outcome() {
        let limiter = AdmissionRateLimiter::with_burst(10);
        let now = Instant::now();
        for attempt in 0..ADMISSION_BURST as u32 {
            assert_eq!(
                limiter.charge_at("principal", now),
                RateLimitDecision::Allowed,
                "attempt {attempt} is within the burst"
            );
        }
        assert!(
            matches!(
                limiter.charge_at("principal", now),
                RateLimitDecision::Throttled { .. }
            ),
            "the burst must run out even though no attempt reported success"
        );
    }

    /// Throttling must expire on its own.
    ///
    /// A limiter that never refilled would turn one burst into a permanent
    /// lockout — the same class of unrecoverable state the admission reaper
    /// exists to prevent, reintroduced at the front door.
    #[test]
    fn a_throttled_principal_recovers_at_the_refill_rate() {
        // Each probe gets its own limiter: a rejected charge still advances the
        // bucket's clock, so reusing one would make the second assertion depend
        // on the first rather than on the rule under test.
        let exhausted = |start: Instant| {
            let limiter = AdmissionRateLimiter::with_burst(10);
            for _ in 0..ADMISSION_BURST as u32 {
                assert_eq!(
                    limiter.charge_at("principal", start),
                    RateLimitDecision::Allowed
                );
            }
            limiter
        };

        let start = Instant::now();
        let RateLimitDecision::Throttled { retry_after } =
            exhausted(start).charge_at("principal", start)
        else {
            panic!("the burst is spent");
        };

        // Just short of the advertised wait must still be refused, or
        // `Retry-After` is telling callers to come back too early and the
        // limiter answers a thundering herd with a second thundering herd.
        assert!(
            matches!(
                exhausted(start)
                    .charge_at("principal", start + retry_after - Duration::from_millis(1)),
                RateLimitDecision::Throttled { .. }
            ),
            "recovering early would make Retry-After a lie"
        );
        assert_eq!(
            exhausted(start).charge_at("principal", start + retry_after),
            RateLimitDecision::Allowed,
            "the advertised wait must actually be enough"
        );
    }

    /// One principal's flood must not touch anyone else's budget.
    ///
    /// A shared bucket would make the limiter a denial-of-service amplifier:
    /// one noisy caller would lock out every tenant on the same API replica,
    /// which is precisely the collateral damage the limit is meant to prevent.
    #[test]
    fn exhausting_one_principal_leaves_every_other_principal_untouched() {
        let limiter = AdmissionRateLimiter::with_burst(10);
        let now = Instant::now();
        for _ in 0..ADMISSION_BURST as u32 + 5 {
            let _ = limiter.charge_at("noisy", now);
        }
        assert_eq!(
            limiter.charge_at("quiet", now),
            RateLimitDecision::Allowed,
            "budgets are per principal, not global"
        );
    }

    /// Idle principals may be forgotten; active ones may not.
    ///
    /// Eviction is only sound because a refilled bucket and a new bucket are
    /// the same value. If a partly-spent bucket could be pruned, a caller could
    /// mint fresh burst on demand by cycling the table — the limiter's own
    /// bookkeeping becoming the bypass.
    #[test]
    fn eviction_can_only_drop_buckets_that_have_already_refilled() {
        let now = Instant::now();
        let mut spent = TokenBucket::fresh(now, 10.0);
        assert_eq!(spent.take(now), RateLimitDecision::Allowed);
        assert!(
            !spent.is_idle(now),
            "a bucket with budget outstanding must not be evictable"
        );

        let full_again = now + Duration::from_secs_f64(ADMISSION_BURST / ADMISSION_REFILL_PER_SEC);
        assert!(
            spent.refilled(full_again) >= ADMISSION_BURST,
            "a bucket left alone for a full refill window carries nothing to remember"
        );
    }

    /// A flood of unknown principals must not disable the limiter.
    ///
    /// The table is bounded, so something has to give when it fills. Handing
    /// out budget would let an attacker with many credentials switch the limit
    /// off for everyone by filling it — the failure mode has to be refusal.
    #[test]
    fn a_full_principal_table_refuses_rather_than_forgets() {
        let limiter = AdmissionRateLimiter::with_burst(10);
        let now = Instant::now();
        for principal in 0..MAX_TRACKED_PRINCIPALS {
            assert_eq!(
                limiter.charge_at(&format!("principal-{principal}"), now),
                RateLimitDecision::Allowed
            );
        }
        assert!(
            matches!(
                limiter.charge_at("one-too-many", now),
                RateLimitDecision::Throttled { .. }
            ),
            "a full table must refuse; evicting live buckets is the bypass"
        );

        // Once the flood has aged out, the table drains and normal service
        // resumes — the refusal above is backpressure, not a permanent wall.
        let drained = now + Duration::from_secs_f64(ADMISSION_BURST / ADMISSION_REFILL_PER_SEC);
        assert_eq!(
            limiter.charge_at("one-too-many", drained),
            RateLimitDecision::Allowed
        );
    }
}
