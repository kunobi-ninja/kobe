//! Per-object retry backoff for reconcile failures, and the gate that keeps a
//! drift event from cancelling one.
//!
//! # Why a controller needs both halves
//!
//! `Action::requeue(d)` asks the scheduler to come back in `d`. It does not
//! promise that nothing else will. Every `reconcile_on` stream this operator
//! wires up — a bootstrap Job, a CIDRClaim, a backend StatefulSet, a bound
//! lease — can deliver a request for the same object sooner, and the scheduler
//! takes whichever instant arrives first. So on an object that keeps failing,
//! a delay returned from `error_policy` is advisory: a child churning once a
//! second turns a 5-minute backoff into a 1-second retry loop, and the
//! controller hammers the API server and the backend for as long as the
//! failure lasts.
//!
//! Suppressing the trigger is not possible — by the time a reconcile request
//! exists the scheduler has already accepted it. What is possible is to make
//! the reconcile cheap: [`FailureBackoff::defer`] answers, before any API call,
//! whether this wake is the retry the backoff was waiting for or a drift event
//! arriving early, and the caller returns the remaining time instead of doing
//! the work.
//!
//! # New intent still wins
//!
//! A backoff must not delay a spec change. Someone editing a broken object is
//! usually fixing it, and making them wait out a 5-minute backoff to find out
//! is the opposite of what the edit was for. `metadata.generation` is what
//! tells the two apart: Kubernetes bumps it on a spec write and never on a
//! status write, so a generation higher than the one recorded at failure time
//! is new intent, clears the backoff, and reconciles at once. A status write —
//! this controller's own, or another writer's — leaves it in place.
//!
//! A delete is the other thing that must never wait, and `generation` does not
//! see it: `deletionTimestamp` is metadata, so setting it bumps nothing. What
//! sits behind the gate is the finalizer, so deferring a delete leaves a
//! backend cluster running for minutes after its object was removed. `defer`
//! therefore reads the whole `ObjectMeta` rather than a generation a caller
//! could pass while forgetting the deletion.
//!
//! # Calling contract
//!
//! - `error_policy` calls [`record`](FailureBackoff::record) and requeues the
//!   delay it returns.
//! - The reconciler calls [`defer`](FailureBackoff::defer) first and returns
//!   `Action::requeue` of whatever it gets.
//! - Something calls [`forget`](FailureBackoff::forget) when the object
//!   reconciles successfully, so the next failure starts the series over, and
//!   a later object reusing the name does not inherit the old count.
//!   [`tracked`] wraps a reconciler to do it.
//!
//! Entries whose object is deleted mid-failure never reach `forget`, so
//! [`record`](FailureBackoff::record) also prunes anything untouched for far
//! longer than the cap. The map is bounded by what has failed recently rather
//! than by everything that has ever failed.

use kube::core::ObjectMeta;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// First retry after a failed reconcile. Doubles per consecutive failure.
pub(crate) const DEFAULT_BASE: Duration = Duration::from_secs(2);
/// Longest retry after repeated failed reconciles.
///
/// Only for a reconciler that owns no deadline. A reconciler that enforces one
/// — a creating-timeout, a provisioning deadline, a queue timeout — must pass a
/// cap it cannot overrun; see [`FailureBackoff::new`].
pub(crate) const DEFAULT_MAX: Duration = Duration::from_secs(300);

/// Cap for a reconciler that enforces a deadline on its own timer.
///
/// `lease.rs` states the rule this exists for: a timeout is a clock deadline,
/// so the backstop never sleeps past it. A failure backoff is another backstop,
/// and one that grows without regard for that deadline breaks the same
/// invariant — quietly, and only on objects that have already failed several
/// times in a row, which are exactly the ones a timeout is there to reclaim.
///
/// Escalation still buys most of what it is for: reaching this cap takes six
/// consecutive failures, by which point the retry rate is already 30x lower
/// than a flat 2s.
pub(crate) const DEADLINE_BOUND_MAX: Duration = Duration::from_secs(60);

/// How long an untouched entry survives, as a multiple of the cap. Anything
/// older belongs to an object that stopped being reconciled — deleted, or
/// moved to another operator — rather than one still backing off.
const PRUNE_AFTER: u32 = 4;

/// One object's failure history.
#[derive(Debug, Clone)]
struct Failure {
    /// Consecutive failed reconciles, 1-based.
    consecutive: u32,
    /// `metadata.generation` when the failure was recorded, when the object
    /// reports one. A higher generation later is new intent.
    generation: Option<i64>,
    /// Earliest instant a retry should do real work.
    next_attempt: Instant,
    /// Last time this entry was written, for pruning.
    touched: Instant,
}

/// Per-object reconcile-failure backoff, shared by a controller's reconciler
/// and its `error_policy` through the controller context.
#[derive(Debug)]
pub(crate) struct FailureBackoff {
    base: Duration,
    max: Duration,
    state: Mutex<HashMap<String, Failure>>,
}

impl FailureBackoff {
    /// A backoff doubling from `base`, capped at `max`.
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record a failure for `key` and return how long to wait before retrying.
    ///
    /// The object's `metadata.generation` is recorded with it, so that
    /// [`defer`](Self::defer) can recognize new intent later.
    pub(crate) fn record(&self, key: &str, meta: &ObjectMeta) -> Duration {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            // A poisoned lock means another thread panicked holding it. The
            // backoff is an optimization, not a correctness control, so fall
            // back to the base delay rather than propagating the panic into a
            // controller's error path.
            return self.base;
        };
        let consecutive = state
            .get(key)
            .map_or(1, |failure| failure.consecutive.saturating_add(1));
        let delay = self.delay(consecutive);
        state.insert(
            key.to_string(),
            Failure {
                consecutive,
                generation: meta.generation,
                next_attempt: now + delay,
                touched: now,
            },
        );
        prune(&mut state, now, self.max * PRUNE_AFTER);
        delay
    }

    /// How much longer `key` should wait, or `None` to reconcile now.
    ///
    /// `None` on a first failure-free object, on the retry the backoff was
    /// waiting for, on a generation higher than the one that failed, and on an
    /// object being deleted. `Some` only for a wake that arrived early on an
    /// object still backing off.
    ///
    /// It reads `meta` rather than taking the fields apart, so that no caller
    /// can pass the generation and forget the deletion.
    pub(crate) fn defer(&self, key: &str, meta: &ObjectMeta) -> Option<Duration> {
        // A delete is never deferred. `deletionTimestamp` is metadata, so it
        // does not bump `generation` and the check below would not see it —
        // and what waits behind this gate is the finalizer, which is what runs
        // `backend.delete()`. Holding that for up to the cap would leave a
        // backend cluster alive for minutes after its object was deleted, on
        // exactly the instances a pool recycles most: the failing ones.
        if meta.deletion_timestamp.is_some() {
            return None;
        }

        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        let failure = state.get(key)?;

        // New intent clears the backoff outright. `generation` is None on an
        // object that reports none, in which case there is nothing to compare
        // and the backoff stands.
        if let (Some(current), Some(failed_at)) = (meta.generation, failure.generation)
            && current > failed_at
        {
            state.remove(key);
            return None;
        }

        // The retry this backoff was waiting for. The entry stays: only a
        // success clears it, and this attempt may fail again.
        if failure.next_attempt <= now {
            return None;
        }

        Some(failure.next_attempt - now)
    }

    /// Forget `key`'s failure history, so its next failure starts over.
    pub(crate) fn forget(&self, key: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.remove(key);
        }
    }

    /// Delay before retry number `consecutive` (1-based): `base` doubled per
    /// earlier failure, capped at `max`.
    fn delay(&self, consecutive: u32) -> Duration {
        let doublings = consecutive.saturating_sub(1).min(16);
        self.base.saturating_mul(1 << doublings).min(self.max)
    }
}

impl Default for FailureBackoff {
    fn default() -> Self {
        Self::new(DEFAULT_BASE, DEFAULT_MAX)
    }
}

/// Drop entries untouched for longer than `ttl`.
fn prune(state: &mut HashMap<String, Failure>, now: Instant, ttl: Duration) {
    state.retain(|_, failure| now.duration_since(failure.touched) < ttl);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An object at `generation`, not being deleted.
    fn meta(generation: i64) -> ObjectMeta {
        ObjectMeta {
            generation: Some(generation),
            ..Default::default()
        }
    }

    /// An object that reports no generation at all.
    fn meta_ungenerated() -> ObjectMeta {
        ObjectMeta::default()
    }

    /// An object at `generation` with a deletionTimestamp.
    fn meta_deleting(generation: i64) -> ObjectMeta {
        ObjectMeta {
            generation: Some(generation),
            deletion_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            )),
            ..Default::default()
        }
    }

    #[test]
    fn delay_doubles_per_consecutive_failure_and_caps() {
        let backoff = FailureBackoff::new(Duration::from_secs(2), Duration::from_secs(300));

        assert_eq!(backoff.record("a", &meta(1)), Duration::from_secs(2));
        assert_eq!(backoff.record("a", &meta(1)), Duration::from_secs(4));
        assert_eq!(backoff.record("a", &meta(1)), Duration::from_secs(8));
        for _ in 0..20 {
            backoff.record("a", &meta(1));
        }
        assert_eq!(
            backoff.record("a", &meta(1)),
            Duration::from_secs(300),
            "the series must cap rather than overflow"
        );
    }

    /// A reconciler that enforces a deadline on its own timer must not sleep
    /// past it. Six failures reach the bound; nothing after that goes higher.
    #[test]
    fn the_deadline_bound_cap_is_reached_and_never_exceeded() {
        let backoff = FailureBackoff::new(DEFAULT_BASE, DEADLINE_BOUND_MAX);

        let series: Vec<Duration> = (0..6).map(|_| backoff.record("a", &meta(1))).collect();
        assert_eq!(
            series,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(32),
                DEADLINE_BOUND_MAX,
            ]
        );

        for _ in 0..10 {
            assert_eq!(
                backoff.record("a", &meta(1)),
                DEADLINE_BOUND_MAX,
                "a deadline-bound reconciler must never wait longer than its cap",
            );
        }
    }

    #[test]
    fn each_object_backs_off_on_its_own_count() {
        let backoff = FailureBackoff::default();

        backoff.record("a", &meta(1));
        backoff.record("a", &meta(1));

        assert_eq!(
            backoff.record("b", &meta(1)),
            DEFAULT_BASE,
            "a second object must start its own series"
        );
    }

    #[test]
    fn success_forgets_the_series() {
        let backoff = FailureBackoff::default();

        backoff.record("a", &meta(1));
        backoff.record("a", &meta(1));
        backoff.forget("a");

        assert_eq!(backoff.record("a", &meta(1)), DEFAULT_BASE);
    }

    #[test]
    fn an_object_with_no_failures_is_never_deferred() {
        let backoff = FailureBackoff::default();

        assert_eq!(backoff.defer("a", &meta(1)), None);
    }

    #[test]
    fn a_drift_wake_during_backoff_is_deferred() {
        let backoff = FailureBackoff::new(Duration::from_secs(60), DEFAULT_MAX);

        backoff.record("a", &meta(1));

        let remaining = backoff
            .defer("a", &meta(1))
            .expect("a wake inside the backoff window must be deferred");
        assert!(
            remaining <= Duration::from_secs(60) && remaining > Duration::from_secs(55),
            "deferral must report the time left, got {remaining:?}"
        );
    }

    #[test]
    fn new_intent_cuts_the_backoff() {
        // A base well under the cap, so a restarted series is distinguishable
        // from one that carried its count over.
        let backoff = FailureBackoff::new(Duration::from_secs(1), DEFAULT_MAX);

        assert_eq!(backoff.record("a", &meta(7)), Duration::from_secs(1));
        assert_eq!(backoff.record("a", &meta(7)), Duration::from_secs(2));

        assert_eq!(
            backoff.defer("a", &meta(8)),
            None,
            "a higher generation is a spec change and must not wait"
        );
        assert_eq!(
            backoff.record("a", &meta(8)),
            Duration::from_secs(1),
            "clearing the backoff also restarts the series"
        );
    }

    /// A delete must never wait out a backoff. `deletionTimestamp` bumps no
    /// generation, so nothing else in `defer` would notice it, and the
    /// finalizer that runs `backend.delete()` is what sits behind the gate.
    #[test]
    fn a_delete_is_never_deferred() {
        let backoff = FailureBackoff::new(Duration::from_secs(300), DEFAULT_MAX);

        backoff.record("a", &meta(7));
        assert!(
            backoff.defer("a", &meta(7)).is_some(),
            "precondition: this object is backing off",
        );

        assert_eq!(
            backoff.defer("a", &meta_deleting(7)),
            None,
            "a deleting object must reconcile at once, at the same generation",
        );
    }

    #[test]
    fn a_status_write_does_not_cut_the_backoff() {
        let backoff = FailureBackoff::new(Duration::from_secs(300), DEFAULT_MAX);

        backoff.record("a", &meta(7));

        assert!(
            backoff.defer("a", &meta(7)).is_some(),
            "an unchanged generation is a status write, not new intent"
        );
    }

    #[test]
    fn an_object_reporting_no_generation_still_backs_off() {
        let backoff = FailureBackoff::new(Duration::from_secs(300), DEFAULT_MAX);

        backoff.record("a", &meta_ungenerated());

        assert!(
            backoff.defer("a", &meta_ungenerated()).is_some(),
            "with nothing to compare, the backoff must stand rather than be cut"
        );
    }

    #[test]
    fn the_scheduled_retry_is_not_deferred() {
        let backoff = FailureBackoff::new(Duration::from_nanos(1), DEFAULT_MAX);

        backoff.record("a", &meta(1));
        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(
            backoff.defer("a", &meta(1)),
            None,
            "once the window has elapsed the retry must do real work"
        );
    }

    #[test]
    fn the_scheduled_retry_keeps_the_series_going() {
        let backoff = FailureBackoff::new(Duration::from_nanos(1), DEFAULT_MAX);

        backoff.record("a", &meta(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(backoff.defer("a", &meta(1)), None);

        assert_eq!(
            backoff.record("a", &meta(1)),
            Duration::from_nanos(2),
            "a deferral check must not reset the count; only success does"
        );
    }

    #[test]
    fn stale_entries_are_pruned() {
        let backoff = FailureBackoff::new(Duration::from_nanos(1), Duration::from_nanos(1));

        backoff.record("gone", &meta(1));
        std::thread::sleep(Duration::from_millis(5));
        backoff.record("live", &meta(1));

        let state = backoff.state.lock().expect("lock");
        assert!(
            !state.contains_key("gone"),
            "an entry untouched past the prune window must not outlive its object"
        );
        assert!(state.contains_key("live"));
    }
}
