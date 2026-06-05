//! Prometheus metrics for kobe.
//!
//! ## Naming convention
//!
//! - All series use the `kobe_*` prefix.
//! - Units are encoded in the suffix: `_seconds`, `_bytes`, `_total` for
//!   counters. Gauges have no unit suffix unless ambiguous.
//! - Label values for `reason` / `outcome` / `state` come from
//!   `&'static str` enums (see [`RecycleReason`], [`BootstrapFailureReason`],
//!   [`InstanceCreateOutcome`], …) so the operator never emits an
//!   uncontrolled string into the registry.
//! - High-cardinality identifiers (`instance_name`, `cluster_name`,
//!   `claim_name`) are NEVER labels. Use traces (`tracing::instrument`)
//!   when you need per-object detail; metrics roll up.
//!
//! ## What this module exposes
//!
//! Three groups, each in its own `# region`:
//!
//! 1. **Inventory + lifecycle (existing)** — counts and lease bind time
//!    that have been around since the operator's first version.
//! 2. **Phase 1: lifecycle durations (NEW)** — histograms for instance
//!    create, bootstrap, pool reconcile, IPAM bind. The smallest set
//!    that answers "is X slow?" without log diving.
//! 3. **Phase 2: lifecycle counters with reasons (NEW)** — counters
//!    keyed by typed reasons so an alert can fire on a specific
//!    failure class (e.g. `reason="kobestore_degraded"`) instead of
//!    the generic "something failed" bucket.
//! 4. **Phase 3: state gauges (NEW)** — kobestore healthy mirror,
//!    IPAM pool capacity/allocated, per-pool size dimensions. Snapshot
//!    of "where is kobe right now?" suitable for dashboards.

use std::sync::LazyLock;
use std::time::Instant;

use prometheus::{
    Encoder, HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder, register_histogram_vec,
    register_int_counter_vec, register_int_gauge_vec,
};

/// Pool state gauges — set at scrape time from shared pool state.
///
/// Labels: `profile` (e.g. "e2e-basic"), `state` (creating/ready/leased/unhealthy/recycling).
pub static POOL_CLUSTERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_clusters",
        "Number of clusters by profile and state",
        &["profile", "state"]
    )
    .unwrap()
});

/// Lease lifecycle counters.
///
/// Labels: `profile`, `event` (created_fast, created_queued, released, expired, extended).
pub static CLAIMS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_claims_total",
        "Claim lifecycle events",
        &["profile", "event"]
    )
    .unwrap()
});

/// Time to bind a lease (fast path only — slow path is asynchronous).
///
/// Labels: `profile`.
pub static CLAIM_BIND_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_claim_bind_duration_seconds",
        "Time to bind a claim to a vcluster (fast path)",
        &["profile"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .unwrap()
});

/// Pending leases per profile.
pub static QUEUE_DEPTH: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_queue_depth",
        "Number of pending claims per profile",
        &["profile"]
    )
    .unwrap()
});

/// Health check result counters.
///
/// Labels: `profile`, `result` (pass, fail).
pub static HEALTH_CHECKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_health_checks_total",
        "Health check results",
        &["profile", "result"]
    )
    .unwrap()
});

/// Reconciliation counters.
///
/// Labels: `controller` (profile, lease), `result` (ok, error).
pub static RECONCILIATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_reconciliations_total",
        "Reconciliation loop runs",
        &["controller", "result"]
    )
    .unwrap()
});

/// Cluster provisioning method counters.
///
/// Labels: `profile`, `method` (fresh, restore).
pub static PROVISION_METHOD: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_provision_method_total",
        "Cluster provisioning method used",
        &["profile", "method"]
    )
    .unwrap()
});

/// Golden backup creation attempt counters.
///
/// Labels: `profile`, `result` (ok, error).
pub static GOLDEN_BACKUP_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_golden_backup_total",
        "Golden backup creation attempts",
        &["profile", "result"]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Phase 1: lifecycle duration histograms
// ─────────────────────────────────────────────────────────────────────
//
// Buckets are tuned per-domain. Picking the wrong bucket set is a
// silent observability bug (P99 hits the +Inf bucket and you can't
// tell anymore), so each histogram lists its rationale inline.

/// Time from `ClusterInstance.phase=Creating` to either `Ready` or
/// `Failed`. The single most-asked question from operators when a
/// pool isn't filling.
///
/// Buckets cover 1s → 10min: most k3s/k0s come up in 30–90s, vkobe
/// in 10–30s; failures usually trip an internal timeout in 2–5min
/// (k0s kubeconfig wait, etc.). Anything past 600s is the "stuck
/// forever" tail and we don't need finer resolution there.
pub static INSTANCE_CREATE_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_instance_create_duration_seconds",
        "Time from ClusterInstance creation to Ready or Failed",
        &["profile", "backend", "outcome"],
        vec![1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0]
    )
    .unwrap()
});

/// Time from `ClusterInstance.status.activeBootstrap=X` becoming non-
/// empty to either `bootstrapped=true` or the bootstrap Job hitting
/// `BackoffLimitExceeded`. Bootstraps are heavier than create — a
/// `flux install` apply + verify on a fresh cluster is 1–5min in good
/// shape, longer when the guest cluster is slow.
///
/// Buckets cover 5s → 20min so we can tell apart "fast bootstrap",
/// "slow but successful", and "hit the install timeout".
///
/// **Currently registered but not observed**: needs a
/// `status.bootstrapStartedAt` field on `ClusterInstanceStatus` to
/// compute duration precisely; `state_since` is reused across many
/// transitions and gives a wrong answer. Tracked as follow-up —
/// declared now so alerts can reference it without churn.
pub static INSTANCE_BOOTSTRAP_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_instance_bootstrap_duration_seconds",
        "Time from bootstrap activation to bootstrapped=true or Failed",
        &["profile", "bootstrap", "outcome"],
        vec![5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0]
    )
    .unwrap()
});

/// Wall-clock of one full `reconcile_profile` invocation. Tail
/// indicates a profile that's spending too long listing instances /
/// resolving bootstraps / probing kobestore — useful when correlating
/// with apiserver latency spikes.
///
/// Buckets sub-second to 5s; reconciles past 5s usually mean a kube
/// API call timed out and we want the +Inf bucket to count those.
///
/// **Currently registered but not observed**: instrumenting
/// `reconcile_profile` cleanly requires either inner-function
/// extraction (function is ~250 lines, scope blew up) or a
/// procedural-macro wrapper. Tracked as follow-up — the metric is
/// declared so dashboards / alerts can reference it without churn
/// when the observer lands.
pub static POOL_RECONCILE_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_pool_reconcile_duration_seconds",
        "Time spent in one profile reconcile",
        &["profile", "outcome"],
        vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

/// Time from `CIDRClaim` first observed in `Pending` to `Bound` or
/// `Conflict`. The IPAM controller's reconcile is fast; this captures
/// the round-trip including any kube-apiserver latency.
pub static IPAM_BIND_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_ipam_bind_duration_seconds",
        "Time from CIDRClaim Pending to Bound or Conflict",
        &["outcome"],
        vec![0.05, 0.1, 0.5, 1.0, 5.0, 30.0]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Phase 2: lifecycle counters with typed reasons
// ─────────────────────────────────────────────────────────────────────

/// Why a `ClusterInstance` got recycled. Closed enum so a Prometheus
/// alert can fire on a specific class (e.g.
/// `reason="kobestore_degraded"`) instead of the catch-all bucket.
///
/// New variants need a new build. That's intentional: random strings
/// as labels are a cardinality bomb in disguise; this enum forces
/// explicit thought when introducing a new failure mode.
///
/// `#[allow(dead_code)]`: not every variant has a reachable emission
/// site yet — `HealthFailed`, `KobeStoreDegraded`, `IpamConflict`,
/// `Manual` will gain emitters in follow-up PRs as those code paths
/// adopt the typed-reason pattern. Declaring the full set up front
/// freezes the label-value vocabulary so dashboards / alerts can
/// reference all reasons stably.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum RecycleReason {
    /// `profile_spec_hash` differs — pool spec / render context /
    /// referenced bootstraps changed.
    SpecDrift,
    /// Bootstrap Job hit `BackoffLimitExceeded` or its pod exited
    /// non-zero.
    BootstrapFailed,
    /// Health probes failed N times in a row (config-driven threshold).
    HealthFailed,
    /// Lease released by user; pool policy may recycle on release.
    LeaseReleased,
    /// `KobeStore.status.conditions[Healthy]=False` — backend datastore
    /// degraded; profile controller halted creates and recycles
    /// pre-existing failed instances.
    KobeStoreDegraded,
    /// Associated `CIDRClaim` reached `Conflict` (requested CIDR
    /// already taken, or pool exhausted).
    IpamConflict,
    /// Operator deleted the `ClusterInstance` directly (kubectl
    /// delete, GC, etc.).
    Manual,
}

impl RecycleReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpecDrift => "spec_drift",
            Self::BootstrapFailed => "bootstrap_failed",
            Self::HealthFailed => "health_failed",
            Self::LeaseReleased => "lease_released",
            Self::KobeStoreDegraded => "kobestore_degraded",
            Self::IpamConflict => "ipam_conflict",
            Self::Manual => "manual",
        }
    }
}

/// Why a bootstrap Job failed. Smaller surface than recycle reasons
/// because we only see this for instances whose bootstrap actually
/// got attempted.
///
/// `#[allow(dead_code)]`: as with `RecycleReason`, the full set is
/// declared up front to stabilise the label vocabulary; classifying
/// `BackoffLimit` more finely (`ExitNonZero` vs `Timeout`, etc.)
/// requires reading the failed Job's pod's last-state which lands
/// in a follow-up.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum BootstrapFailureReason {
    /// Job's `backoffLimit` exhausted (the catch-all that everything
    /// becomes if not classified more specifically before the Job
    /// gives up).
    BackoffLimit,
    /// Bootstrap pod exited non-zero (e.g. `flux install` returned
    /// error). Distinct from BackoffLimit because we observed the
    /// exit before the Job declared failure.
    ExitNonZero,
    /// Bootstrap Job ran longer than its `activeDeadlineSeconds`.
    Timeout,
    /// Backend (`vkobe` apiserver, etc.) was unreachable when the
    /// Bootstrap pod tried to apply manifests.
    BackendUnavailable,
}

impl BootstrapFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackoffLimit => "backoff_limit",
            Self::ExitNonZero => "exit_nonzero",
            Self::Timeout => "timeout",
            Self::BackendUnavailable => "backend_unavailable",
        }
    }
}

/// Outcome of a `ClusterInstance` create attempt — terminal state of
/// the create-time path, not the long-running phase.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum InstanceCreateOutcome {
    /// Instance reached `phase=Ready`.
    Ready,
    /// Instance reached `phase=Failed`.
    Failed,
    /// Instance was recycled before reaching Ready (e.g. spec changed
    /// while it was still Creating).
    Recycled,
}

impl InstanceCreateOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Recycled => "recycled",
        }
    }
}

/// IPAM claim lifecycle outcomes for the counter axis.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum IpamClaimOutcome {
    Bound,
    Conflict,
    /// CIDRPool was deleted while the claim was Bound; the claim
    /// transitioned to `Lost` (only possible if we re-introduce
    /// `CIDRPool` as a CRD; today it's hardcoded so this is reserved).
    Lost,
}

impl IpamClaimOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Conflict => "conflict",
            Self::Lost => "lost",
        }
    }
}

/// Whether a claim came from the dynamic allocator or a static
/// reservation (no ownerReference, `requestedServiceCidr` set).
#[derive(Debug, Clone, Copy)]
pub enum IpamClaimKind {
    Dynamic,
    Reservation,
}

impl IpamClaimKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dynamic => "dynamic",
            Self::Reservation => "reservation",
        }
    }
}

/// `ClusterInstance` recycle counter, keyed by `RecycleReason`.
pub static INSTANCE_RECYCLES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_instance_recycles_total",
        "ClusterInstance recycle events by reason",
        &["profile", "reason"]
    )
    .unwrap()
});

/// Bootstrap Job failure counter. Distinct from
/// `INSTANCE_RECYCLES_TOTAL{reason=bootstrap_failed}` because not
/// every bootstrap failure causes a recycle (could be transient,
/// could be a Job retry within `backoffLimit`).
pub static BOOTSTRAP_FAILURES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_bootstrap_failures_total",
        "Bootstrap Job failure events by reason",
        &["profile", "bootstrap", "reason"]
    )
    .unwrap()
});

/// `ClusterInstance` create-attempt outcome counter. Pair with
/// `kobe_instance_create_duration_seconds` for "X% of creates went
/// fast" queries.
pub static INSTANCE_CREATES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_instance_creates_total",
        "ClusterInstance create-attempt outcomes",
        &["profile", "backend", "outcome"]
    )
    .unwrap()
});

/// `CIDRClaim` lifecycle outcome counter.
pub static IPAM_CLAIMS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_ipam_claims_total",
        "CIDRClaim lifecycle outcomes",
        &["outcome", "kind"]
    )
    .unwrap()
});

/// `KobeStore.status.conditions[Healthy]` transition counter. Useful
/// for "this store flapped 5 times in the last hour" alerts.
pub static KOBESTORE_CONDITION_TRANSITIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_kobestore_condition_transitions_total",
        "KobeStore Healthy condition transitions",
        &["store", "from", "to"]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Phase 3: state gauges (snapshot of "where is kobe right now")
// ─────────────────────────────────────────────────────────────────────

/// Mirror of `KobeStore.status.conditions[Healthy]`. `1` when status
/// is `True`, `0` for `False`, `-1` for `Unknown`. Gauge value is
/// preferred over a string label for dashboards (`min_over_time`,
/// `last_over_time` work natively).
///
/// Keyed on `store` only — NOT on the (mutable) condition reason. With a
/// `reason` label, recovery emits a new `{store, reason="Stable"}` series while
/// the prior `{store, reason="MemoryPressure"}=0` series lingers forever, so a
/// natural `kobe_kobestore_healthy{store="X"} == 0` alert keeps firing on the
/// stale child. The reason lives on the condition message instead.
pub static KOBESTORE_HEALTHY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_kobestore_healthy",
        "KobeStore Healthy condition: 1=True, 0=False, -1=Unknown",
        &["store"]
    )
    .unwrap()
});

/// Total slot capacity of the IPAM plan. Currently a constant
/// (`pool::cidr_alloc::ipam_plan().capacity()` = 128) but exposed as
/// a gauge so it works the day this becomes a runtime config.
pub static IPAM_POOL_CAPACITY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_ipam_pool_capacity",
        "Total slots in the IPAM plan",
        &[] as &[&str]
    )
    .unwrap()
});

/// Number of `CIDRClaim`s currently `Bound`. Pair with
/// `kobe_ipam_pool_capacity` for fill-ratio alerts.
///
/// **Currently registered but not observed**: needs a periodic gauge
/// sync against the live claim inventory. The IPAM controller's
/// per-claim reconciles increment counters but don't have visibility
/// into the global Bound count without an extra API call. Defer to a
/// follow-up that adds a periodic sync sweep (similar to
/// `sync_cluster_instance_statuses` in profile.rs).
pub static IPAM_POOL_ALLOCATED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_ipam_pool_allocated",
        "Number of currently-bound CIDRClaims",
        &[] as &[&str]
    )
    .unwrap()
});

/// Per-pool size dimensions. `dimension={min,max,desired,ready,creating,leased,unhealthy,recycling}`.
/// The `min` / `max` come from the spec; the rest are observed states.
/// Replaces the need for the existing `kobe_clusters{state}` to also
/// carry capacity bounds.
pub static POOL_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_pool_size",
        "Pool size by dimension (min, max, desired, or observed phase counts)",
        &["profile", "dimension"]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

/// RAII timer for histograms with a 3-axis `[label1, label2, outcome]`
/// shape. The outcome is decided at drop time via [`Timer::finish`];
/// dropping without calling `finish()` records `outcome="aborted"`
/// (the most common cause is a panic or `?` early-return through the
/// Timer's lifetime, which is exactly what we want to count).
///
/// Usage:
/// ```ignore
/// let timer = Timer::start(&INSTANCE_CREATE_DURATION,
///     [profile.as_str(), backend.as_str()]);
/// // ... do work ...
/// timer.finish(InstanceCreateOutcome::Ready.as_str());
/// ```
///
/// Currently unused — the in-tree call sites instrument by computing
/// elapsed-from-creation_timestamp at terminal transitions, which
/// works without RAII. `Timer` is kept for the upcoming
/// `POOL_RECONCILE_DURATION` instrumentation (where elapsed-from-
/// creation_timestamp doesn't apply because reconcile isn't an
/// object lifecycle).
#[allow(dead_code)]
pub struct Timer<'a, const N: usize> {
    histogram: &'a HistogramVec,
    base_labels: [&'a str; N],
    started: Instant,
    finished: bool,
}

#[allow(dead_code)]
impl<'a, const N: usize> Timer<'a, N> {
    pub fn start(histogram: &'a HistogramVec, base_labels: [&'a str; N]) -> Self {
        Self {
            histogram,
            base_labels,
            started: Instant::now(),
            finished: false,
        }
    }

    pub fn finish(mut self, outcome: &str) {
        self.observe(outcome);
        self.finished = true;
    }

    fn observe(&self, outcome: &str) {
        let mut labels: Vec<&str> = self.base_labels.to_vec();
        labels.push(outcome);
        let elapsed = self.started.elapsed().as_secs_f64();
        self.histogram.with_label_values(&labels).observe(elapsed);
    }
}

impl<const N: usize> Drop for Timer<'_, N> {
    fn drop(&mut self) {
        if !self.finished {
            self.observe("aborted");
        }
    }
}

/// Force all LazyLock statics to initialize, registering metrics
/// with the default Prometheus registry. Call once at startup.
pub fn init() {
    // Existing
    LazyLock::force(&POOL_CLUSTERS);
    LazyLock::force(&CLAIMS_TOTAL);
    LazyLock::force(&CLAIM_BIND_DURATION);
    LazyLock::force(&QUEUE_DEPTH);
    LazyLock::force(&HEALTH_CHECKS_TOTAL);
    LazyLock::force(&RECONCILIATIONS_TOTAL);
    LazyLock::force(&PROVISION_METHOD);
    LazyLock::force(&GOLDEN_BACKUP_TOTAL);
    // Phase 1
    LazyLock::force(&INSTANCE_CREATE_DURATION);
    LazyLock::force(&INSTANCE_BOOTSTRAP_DURATION);
    LazyLock::force(&POOL_RECONCILE_DURATION);
    LazyLock::force(&IPAM_BIND_DURATION);
    // Phase 2
    LazyLock::force(&INSTANCE_RECYCLES_TOTAL);
    LazyLock::force(&BOOTSTRAP_FAILURES_TOTAL);
    LazyLock::force(&INSTANCE_CREATES_TOTAL);
    LazyLock::force(&IPAM_CLAIMS_TOTAL);
    LazyLock::force(&KOBESTORE_CONDITION_TRANSITIONS_TOTAL);
    // Phase 3
    LazyLock::force(&KOBESTORE_HEALTHY);
    LazyLock::force(&IPAM_POOL_CAPACITY);
    LazyLock::force(&IPAM_POOL_ALLOCATED);
    LazyLock::force(&POOL_SIZE);
}

/// Encode all registered metrics in Prometheus text exposition format.
pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode metrics: {e}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!("Metrics output is not valid UTF-8: {e}");
        String::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: touch every metric so the Prometheus registry has something
    /// to emit. Gauges and counters only appear in gather() output after
    /// at least one observation.
    fn seed_metrics() {
        init();
        POOL_CLUSTERS.with_label_values(&["_test", "ready"]).set(0);
        CLAIMS_TOTAL
            .with_label_values(&["_test", "created_fast"])
            .inc();
        RECONCILIATIONS_TOTAL
            .with_label_values(&["_test", "ok"])
            .inc();
        PROVISION_METHOD
            .with_label_values(&["_test", "fresh"])
            .inc();
        GOLDEN_BACKUP_TOTAL
            .with_label_values(&["_test", "ok"])
            .inc();
    }

    /// Calling gather() after seeding metrics should return a non-empty
    /// string containing Prometheus text exposition output.
    #[test]
    fn test_gather_returns_string() {
        seed_metrics();
        let output = gather();
        assert!(
            !output.is_empty(),
            "gather() should return a non-empty string after seeding metrics"
        );
    }

    /// The gathered output must contain all key metric family names
    /// that the operator registers.
    #[test]
    fn test_gather_contains_expected_metrics() {
        seed_metrics();
        let output = gather();

        let expected = [
            "kobe_clusters",
            "kobe_claims_total",
            "kobe_reconciliations_total",
            "kobe_provision_method_total",
            "kobe_golden_backup_total",
        ];

        for metric in &expected {
            assert!(
                output.contains(metric),
                "gather() output should contain metric '{metric}'"
            );
        }
    }

    /// Incrementing a counter should cause the metric to appear
    /// in the gathered output with its label values.
    #[test]
    fn test_metric_increment() {
        init();

        CLAIMS_TOTAL
            .with_label_values(&["test-profile", "created_fast"])
            .inc();

        let output = gather();
        assert!(
            output.contains("kobe_claims_total"),
            "gather() should contain the kobe_claims_total metric after increment"
        );
        assert!(
            output.contains("test-profile"),
            "gather() should contain the label value 'test-profile' after increment"
        );
    }
}
