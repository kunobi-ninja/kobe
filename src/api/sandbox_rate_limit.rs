//! Per-principal rate limiting for the Sandbox admission path.
//!
//! ## Why this is not the concurrency limit
//!
//! `max_concurrent_leases` bounds how many sandboxes a principal may *hold*. It
//! says nothing about how fast they may *ask*, and refusing an attempt is not
//! free: by the time admission can answer "no", the request has already cost
//! the API server a `SandboxLease` CREATE, up to `max_concurrent_leases`
//! reservation CREATEs, and a fenced DELETE to undo them. A principal sitting
//! at their limit can therefore retry forever, spend none of their own quota,
//! and still saturate the API server that every unrelated principal shares.
//!
//! ## Why the budget is charged per attempt
//!
//! The budget is charged before that work is scheduled and is never refunded,
//! so a caller whose requests all fail is charged exactly like one whose
//! requests all succeed. Charging on success — or refunding on failure — would
//! leave the loop above completely unbounded, which is the specific evasion
//! this module exists to close. That is why the charge is the first statement
//! of the handler and not a decision taken at one of its exits: every exit
//! below it has already paid.
//!
//! A *throttled* unkeyed attempt is different, and costs nothing: it is refused
//! before any I/O. A keyed attempt may perform one exact-name GET so a caller
//! that lost an already-committed create response can recover that object; a
//! miss still performs no admission mutation and returns the same throttle.
//! Charging a refusal again would turn a bounded delay into permanent lockout
//! for a tight retry loop, which punishes bad retry code rather than bounding
//! load.
//!
//! ## Scope, stated narrowly
//!
//! This is a per-process limiter, so with `N` API replicas a principal's
//! effective ceiling is `N` times the numbers below. That is deliberate: a
//! cluster-wide limiter would need a write per *rejected* attempt, spending the
//! exact resource it is meant to protect. Bounding the blast radius by a
//! constant factor is the honest claim; a global rate guarantee is not.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Attempts a principal may make back-to-back from an idle start.
///
/// Sized for the legitimate shape of the workload: an agent runner opening a
/// handful of sandboxes at once must never see a 429, and no realistic caller
/// bursts past this without something being wrong — `max_concurrent_leases`
/// caps what they could usefully be holding anyway.
///
/// Crate-visible so the admission handler's own test can drive the boundary
/// through the real endpoint. A test that hard-coded `10` would keep passing if
/// this value moved, which is the one thing it must not do.
pub(crate) const ADMISSION_BURST: f64 = 10.0;

/// Sustained refill, in attempts per second, once the burst is spent.
///
/// One attempt every two seconds. Interactive use never notices; a retry loop
/// is cut from "as fast as the network allows" to a rate whose worst case is a
/// bounded, uninteresting trickle of apiserver writes.
const ADMISSION_REFILL_PER_SEC: f64 = 0.5;

/// Ceiling on distinct principals tracked at once.
///
/// The map only ever holds principals that attempted admission within the last
/// [`ADMISSION_BURST`] / [`ADMISSION_REFILL_PER_SEC`] seconds (anything older
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
/// A bucket that has refilled to [`ADMISSION_BURST`] is indistinguishable from
/// a bucket that has never been used, which is what makes eviction safe: the
/// limiter can forget an idle principal without ever giving them budget they
/// had not already earned back.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn fresh(now: Instant) -> Self {
        Self {
            tokens: ADMISSION_BURST,
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
        (self.tokens + elapsed * ADMISSION_REFILL_PER_SEC).min(ADMISSION_BURST)
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
            retry_after: Duration::from_secs_f64((1.0 - tokens) / ADMISSION_REFILL_PER_SEC),
        }
    }

    /// Whether this bucket now carries exactly what a new one would, and can
    /// therefore be dropped without changing any future decision.
    fn is_idle(&self, now: Instant) -> bool {
        self.refilled(now) >= ADMISSION_BURST
    }
}

/// Shared, per-process admission budget keyed by principal.
///
/// Mirrors the connect cache's shape — a `std::sync::Mutex` around a small map.
/// Entries are two words and every operation is a hash lookup, so a coarse lock
/// is cheaper here than anything asynchronous, and it is never held across an
/// `.await`.
#[derive(Clone, Default)]
pub struct AdmissionRateLimiter(Arc<Mutex<HashMap<String, TokenBucket>>>);

impl AdmissionRateLimiter {
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
                retry_after: Duration::from_secs_f64(1.0 / ADMISSION_REFILL_PER_SEC),
            };
        }

        let mut bucket = TokenBucket::fresh(now);
        let decision = bucket.take(now);
        buckets.insert(principal.to_string(), bucket);
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller who is refused must still be charged.
    ///
    /// If budget were spent only by attempts that end in success, a principal
    /// at their concurrency limit could retry forever: every attempt fails, so
    /// every attempt is free, while each one still costs the apiserver a lease
    /// CREATE plus reservation CREATEs plus a DELETE. The limiter has no view
    /// of the outcome by construction — this pins that it never grows one.
    #[test]
    fn budget_is_spent_by_the_attempt_not_by_its_outcome() {
        let limiter = AdmissionRateLimiter::default();
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
            let limiter = AdmissionRateLimiter::default();
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
        let limiter = AdmissionRateLimiter::default();
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
        let mut spent = TokenBucket::fresh(now);
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
        let limiter = AdmissionRateLimiter::default();
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
