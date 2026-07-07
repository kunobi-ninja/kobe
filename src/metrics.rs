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

// ─────────────────────────────────────────────────────────────────────
// P0 observability: failure / health signals recent incidents proved
// invisible. Pure observability — no behavior change, just emission
// alongside existing control flow.
// ─────────────────────────────────────────────────────────────────────

/// Coarse classification of a pool's `last_failure_reason` text into a
/// bounded label vocabulary. The reason string itself is high-cardinality
/// (it embeds indexes, pool names, free-form guidance) so it can NEVER be a
/// label value; this enum maps it onto a fixed, alert-friendly set via simple
/// keyword matching in [`PoolFailureClass::from_reason`].
///
/// `#[allow(dead_code)]`: the full vocabulary is frozen up front so dashboards
/// / alerts can reference every class stably; not every variant is reachable
/// from the current single `last_failure_reason` text (today it's almost
/// always the generic "not reaching Ready" message → `Other`), but the
/// backend-create / delete / bootstrap / health / kobestore / ipam classes
/// gain emitters as those reason strings get richer.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolFailureClass {
    /// Backend resource create failed (StatefulSet / Service / etc.).
    BackendCreate,
    /// Backend resource delete / teardown failed (PDB 403, PVC reap, …).
    BackendDelete,
    /// Bootstrap Job failed.
    Bootstrap,
    /// Health probes failed.
    Health,
    /// Backend datastore (`KobeStore`) reported degraded.
    KobestoreDegraded,
    /// CIDR / IPAM allocation failure.
    Ipam,
    /// Pool wedged on capacity: the #191 scheduling-blocked (Unschedulable)
    /// backpressure is engaged — guest Pods can't be placed (issue #189).
    Capacity,
    /// Anything not matched by the keyword rules above.
    Other,
}

impl PoolFailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackendCreate => "backend_create",
            Self::BackendDelete => "backend_delete",
            Self::Bootstrap => "bootstrap",
            Self::Health => "health",
            Self::KobestoreDegraded => "kobestore_degraded",
            Self::Ipam => "ipam",
            Self::Capacity => "capacity",
            Self::Other => "other",
        }
    }

    /// Classify a free-form `last_failure_reason` string into a bounded class
    /// via lowercase substring/keyword matching. The raw string is NEVER used
    /// as a label — only the returned class's `as_str()` is.
    ///
    /// Order matters: delete-related keywords are checked before the generic
    /// "create" so a PDB delete 403 ("poddisruption") classifies as
    /// `BackendDelete` rather than falling through.
    ///
    /// NOTE: substring matching over free-form text is inherently unsound when
    /// that text embeds dynamic data (pool names, etc.), so live emitters set
    /// [`PoolFailureClass`] structurally at the failure site instead. This is
    /// retained only as a best-effort fallback for classifying *persisted*
    /// legacy reason strings (e.g. reading back an older status).
    #[allow(dead_code)]
    pub fn from_reason(reason: &str) -> Self {
        let r = reason.to_ascii_lowercase();
        if r.contains("delete") || r.contains("poddisruption") || r.contains("teardown") {
            Self::BackendDelete
        } else if r.contains("capacity")
            || r.contains("unschedulable")
            || r.contains("insufficient")
            || r.contains("scheduling blocked")
        {
            Self::Capacity
        } else if r.contains("bootstrap") {
            Self::Bootstrap
        } else if r.contains("health") {
            Self::Health
        } else if r.contains("kobestore") || r.contains("datastore") {
            Self::KobestoreDegraded
        } else if r.contains("cidr") || r.contains("ipam") {
            Self::Ipam
        } else if r.contains("create") || r.contains("statefulset") {
            Self::BackendCreate
        } else {
            Self::Other
        }
    }
}

/// Why a backend resource operation (create/delete) failed, classified from a
/// `kube::Error` into a bounded set so the operator never labels with a raw
/// kube error message. See [`classify_kube_error`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendOpErrorReason {
    /// 403 / Forbidden — missing RBAC grant (e.g. the PDB delete that 403'd
    /// in the incident because the operator lacked `policy/...` delete).
    Rbac,
    /// 404 / Not Found.
    NotFound,
    /// Request timed out / deadline exceeded.
    Timeout,
    /// 409 / Conflict.
    Conflict,
    /// Transport / connection / IO error reaching the apiserver.
    Io,
    /// Anything else.
    Other,
}

impl BackendOpErrorReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rbac => "rbac",
            Self::NotFound => "not_found",
            Self::Timeout => "timeout",
            Self::Conflict => "conflict",
            Self::Io => "io",
            Self::Other => "other",
        }
    }
}

/// Why an instance stuck in `Creating` got recycled.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckCreatingReason {
    /// The configured creating-timeout elapsed while still `Creating`.
    Timeout,
    /// Spec drifted while the instance was mid-`Creating` (stamped hash no
    /// longer matches the pool's current hash).
    Drift,
    /// The guest server/agent Pods can't be scheduled (Pending +
    /// `PodScheduled=False, reason=Unschedulable`, e.g. "Insufficient cpu").
    /// This is NOT a recycle reason — it labels the *backpressure* path where
    /// the instance is deliberately held (next_attempt_at extended) instead of
    /// being Deleted, because respawning would only create more unschedulable
    /// Pods.
    Unschedulable,
    /// The guest server/agent container is genuinely crashlooping
    /// (`CrashLoopBackOff`, or `restartCount >= 2` with a non-zero
    /// `lastState.terminated` exit). Unlike `Unschedulable` this DOES recycle
    /// on the existing creating-timeout (respawning a crashlooper is the
    /// established remediation, #197); the variant exists only to label the
    /// recycle so a crash-driven wedge is distinguishable from a plain timeout.
    CrashLooping,
}

impl StuckCreatingReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Drift => "drift",
            Self::Unschedulable => "unschedulable",
            Self::CrashLooping => "crashlooping",
        }
    }
}

/// Role of a guest-cluster pod, derived from its existing name/label shape so
/// OOM-kill counts stay bounded instead of carrying the raw pod name.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPodRole {
    /// k3s/k0s control-plane server (`*-server-N`).
    Server,
    /// k3s/k0s agent (`*-agent*`).
    Agent,
    /// kine shim (`*kine*`).
    Kine,
    /// Datastore pod (etcd / postgres / generic datastore).
    Datastore,
    /// Anything else.
    Other,
}

impl GuestPodRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Agent => "agent",
            Self::Kine => "kine",
            Self::Datastore => "datastore",
            Self::Other => "other",
        }
    }

    /// Derive the role from a pod name. StatefulSet server pods are
    /// `{cluster}-server-{ordinal}`; agent Deployment pods are
    /// `{cluster}-agent-{hash}-{hash}`; kine/datastore pods carry those
    /// substrings.
    pub fn from_pod_name(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.contains("kine") {
            Self::Kine
        } else if n.contains("-server-") || n.ends_with("-server") {
            Self::Server
        } else if n.contains("-agent-") || n.ends_with("-agent") || n.contains("-agent") {
            Self::Agent
        } else if n.contains("etcd") || n.contains("postgres") || n.contains("datastore") {
            Self::Datastore
        } else {
            Self::Other
        }
    }
}

/// Outcome of a connect-proxy request, classified at every return path so a
/// single low-cardinality counter (~7 series) makes rejections visible.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Request forwarded successfully (buffered response or upgrade tunnel
    /// handed off).
    Ok,
    /// No Bearer token presented.
    MissingToken,
    /// Token present but invalid / mismatched.
    InvalidToken,
    /// Lease object not found.
    LeaseNotFound,
    /// Lease exists but is not in the `Bound` phase.
    PhaseNotBound,
    /// Lease expired (TTL elapsed).
    Expired,
    /// Backend / infrastructure error (kube API, kubeconfig, transport, …).
    BackendError,
}

impl ConnectOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::MissingToken => "missing_token",
            Self::InvalidToken => "invalid_token",
            Self::LeaseNotFound => "lease_not_found",
            Self::PhaseNotBound => "phase_not_bound",
            Self::Expired => "expired",
            Self::BackendError => "backend_error",
        }
    }
}

/// Classify a `kube::Error` into a bounded [`BackendOpErrorReason`]. Maps HTTP
/// status codes (403→Rbac, 404→NotFound, 409→Conflict) and transport failures
/// (timeout/connect→Timeout/Io) onto the closed set; everything else is
/// `Other`. The raw error is logged at the call site, never used as a label.
pub fn classify_kube_error(e: &kube::Error) -> BackendOpErrorReason {
    match e {
        kube::Error::Api(ae) => match ae.code {
            403 => BackendOpErrorReason::Rbac,
            404 => BackendOpErrorReason::NotFound,
            409 => BackendOpErrorReason::Conflict,
            408 | 504 => BackendOpErrorReason::Timeout,
            _ => {
                // Some apiservers encode the reason in the message rather than
                // a distinct code; fall back to keyword matching but only over
                // the structured `reason`/`message` we already hold.
                let reason = ae.reason.to_ascii_lowercase();
                if reason.contains("forbidden") {
                    BackendOpErrorReason::Rbac
                } else if reason.contains("notfound") {
                    BackendOpErrorReason::NotFound
                } else if reason.contains("conflict") || reason.contains("alreadyexists") {
                    BackendOpErrorReason::Conflict
                } else if reason.contains("timeout") {
                    BackendOpErrorReason::Timeout
                } else {
                    BackendOpErrorReason::Other
                }
            }
        },
        // Transport / connection layer failures.
        kube::Error::HyperError(_) | kube::Error::Service(_) => BackendOpErrorReason::Io,
        kube::Error::Discovery(_) => BackendOpErrorReason::Other,
        other => {
            // `kube::Error` is non-exhaustive; classify by the rendered string
            // for the request/connect/timeout variants without matching every
            // arm.
            let s = other.to_string().to_ascii_lowercase();
            if s.contains("timeout") || s.contains("timed out") || s.contains("deadline") {
                BackendOpErrorReason::Timeout
            } else if s.contains("connect") || s.contains("connection") || s.contains("transport") {
                BackendOpErrorReason::Io
            } else {
                BackendOpErrorReason::Other
            }
        }
    }
}

/// Per-pool consecutive provision failures (gauge mirror of
/// `ClusterPool.status.consecutiveFailures`). A non-zero, rising value is the
/// "this pool can't fill" signal that incidents proved invisible.
pub static POOL_CONSECUTIVE_FAILURES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_pool_consecutive_failures",
        "Current consecutive provision failures per pool",
        &["profile"]
    )
    .unwrap()
});

/// Counts the EDGE where a pool's consecutive-failure count just increased,
/// keyed by the coarse [`PoolFailureClass`]. Counting only the edge (not every
/// steady-state reconcile) keeps this a "new failure started" signal rather
/// than a slowly-climbing counter that tracks reconcile frequency.
pub static POOL_FAILURE_REASON_CHANGES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_pool_failure_reason_changes_total",
        "Edges where a pool's consecutive-failure count increased, by failure class",
        &["profile", "failure_class"]
    )
    .unwrap()
});

/// Best-effort backend delete failures (PDB, PVC, …) that the teardown path
/// logs and continues past. The PDB 403 in the incident produced zero metrics;
/// this counter makes those silent-but-meaningful failures alertable.
pub static BACKEND_DELETE_FAILURES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_backend_delete_failures_total",
        "Best-effort backend resource delete failures by reason",
        &["backend", "reason"]
    )
    .unwrap()
});

/// Instances recycled because they were stuck in `Creating` past the
/// creating-timeout (or drifted mid-Creating).
pub static INSTANCE_STUCK_CREATING_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_instance_stuck_creating_total",
        "Instances recycled for being stuck in Creating, by reason",
        &["profile", "reason"]
    )
    .unwrap()
});

/// Guest-cluster pod OOM-kills observed by the KobeStore health controller.
/// Keyed by the bounded [`GuestPodRole`] so a server-vs-kine OOM is
/// distinguishable without per-pod cardinality.
pub static GUEST_POD_OOM_KILLS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_guest_pod_oom_kills_total",
        "Guest-cluster pod OOMKilled events by pod role",
        &["profile", "backend", "pod_role"]
    )
    .unwrap()
});

/// Guest-cluster server/agent Pods the host scheduler could not place
/// (Pending + `PodScheduled=False, reason=Unschedulable`, e.g. "Insufficient
/// cpu"). Incremented by the instance controller's `Creating` arm when its
/// scheduling-block detector fires, so a wedged pool surfaces as backpressure
/// instead of being silently churned by the creating-timeout recycle. Keyed by
/// the bounded [`GuestPodRole`] (and a `reason` label distinguishing the
/// condition-derived `Unschedulable` from an Event-derived `FailedScheduling`)
/// so cardinality stays a small, fixed product per pool.
pub static GUEST_POD_UNSCHEDULABLE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_guest_pod_unschedulable_total",
        "Guest-cluster server/agent Pods the host scheduler could not place, by pod role and reason",
        &["profile", "backend", "pod_role", "reason"]
    )
    .unwrap()
});

/// Guest-cluster server/agent Pods whose container is crashlooping
/// (`CrashLoopBackOff`, or a `restartCount >= 2` with a non-zero
/// `lastState.terminated` exit). Incremented by the instance controller's
/// `Creating` arm when its crashloop detector fires (#197), so an operator
/// sees "server-0 CrashLoopBackOff exit 2" on a dashboard instead of having to
/// run `kubectl logs`. Keyed by the bounded [`GuestPodRole`] plus the
/// `exit_code` as a string label (a small, fixed set in practice — k3s exits
/// with a handful of codes), so cardinality stays a bounded product per pool.
pub static GUEST_POD_CRASHLOOP_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_guest_pod_crashloop_total",
        "Guest-cluster server/agent Pods crashlooping, by pod role and exit code",
        &["profile", "backend", "pod_role", "exit_code"]
    )
    .unwrap()
});

/// Connect-proxy request outcomes, classified at every return path. Single
/// `outcome` label keeps cardinality at ~7 series; the per-lease detail lives
/// in traces / logs, not here.
pub static CONNECT_PROXY_REQUEST_OUTCOME_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_connect_proxy_request_outcome_total",
        "Connect-proxy request outcomes by classification",
        &["outcome"]
    )
    .unwrap()
});

/// Why a lease could not (yet) be satisfied — a bounded label vocabulary so a
/// hung `Pending` lease becomes alertable without high-cardinality strings.
/// Shared by the `create_lease` 503 pre-flight and the lease controller's
/// no-Ready-cluster branch so both classify identically.
///
/// `#[allow(dead_code)]`: the full set is frozen up front so dashboards / alerts
/// can reference every reason stably; not every variant is reachable from every
/// emission site (e.g. `Warming` is the create-path "healthy-but-empty" case,
/// which the controller branch never emits because it only runs once Pending).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseUnsatisfiableReason {
    /// Pool phase is `Failing` — sustained provision failures; this pool will
    /// not satisfy the lease without operator attention.
    PoolExhausted,
    /// Pool is in a backoff window (phase `Backoff`) with no schedulable
    /// headroom — capacity is blocked behind the retry timer.
    CapacityBlocked,
    /// Pool is otherwise unhealthy / degraded (no Ready clusters and not a
    /// clean warm-up case).
    Degraded,
    /// Healthy-but-empty warm pool: clusters are still coming up. Transient;
    /// the lease should bind shortly. (Returned as 202, not 503.)
    Warming,
}

impl LeaseUnsatisfiableReason {
    /// snake_case label for the `kobe_lease_unsatisfiable_total` metric.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PoolExhausted => "pool_exhausted",
            Self::CapacityBlocked => "capacity_blocked",
            Self::Degraded => "degraded",
            Self::Warming => "warming",
        }
    }

    /// PascalCase reason for a Kubernetes status `Condition` — K8s convention
    /// is PascalCase condition reasons, and it keeps the lease's `Satisfiable`
    /// reason consistent with its PascalCase `Bound` reason (the phase).
    pub const fn condition_reason(self) -> &'static str {
        match self {
            Self::PoolExhausted => "PoolExhausted",
            Self::CapacityBlocked => "CapacityBlocked",
            Self::Degraded => "Degraded",
            Self::Warming => "Warming",
        }
    }
}

/// A lease could not be satisfied at request time (503 pre-flight) or remained
/// unbound in the controller's no-Ready-cluster branch, keyed by the bounded
/// [`LeaseUnsatisfiableReason`]. Makes a pool that "can never satisfy a lease"
/// visible instead of leaving the lease hung in `Pending` forever.
pub static LEASE_UNSATISFIABLE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_lease_unsatisfiable_total",
        "Leases that could not be satisfied, by profile and reason",
        &["profile", "reason"]
    )
    .unwrap()
});

/// Successful authentications, by `provider` (AccessPolicy name) and `method`
/// ("oidc" / "token" via kunobi-auth's `AuthObserver`, or "ssh").
pub static AUTH_SUCCESS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_auth_success_total",
        "Successful authentications by provider and method",
        &["provider", "method"]
    )
    .unwrap()
});

/// Failed authentications, by `provider` (or "unknown" when not attributable)
/// and `reason`. `reason` is a bounded label from `AuthFailReason::label()`
/// (e.g. "expired", "audience_mismatch", "no_matching_provider", "token_rejected").
pub static AUTH_FAILURE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_auth_failure_total",
        "Failed authentications by provider and reason",
        &["provider", "reason"]
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

/// Effective CPU request (millicores) kobe stamps onto each guest pod
/// (k3s server + agent) for this pool — explicit `requests.cpu` or, when
/// absent, the `limits.cpu` the kubelet silently copies into the request.
/// Surfaces hidden over-reservation: `limits.cpu:"8"` with empty requests
/// reserves 8000m per pod (16 cores/cluster), invisible until the nodes
/// wedge (issue #189). 0 when the pool sets no CPU limit/request.
pub static POOL_EFFECTIVE_CPU_REQUEST_MILLICORES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_pool_effective_cpu_request_millicores",
        "Effective per-guest-pod CPU request (millicores), incl. the kubelet's silent limit→request copy",
        &["profile"]
    )
    .unwrap()
});

/// 1 when the pool has scheduling-blocked (capacity-starved) instances — the
/// #191 Unschedulable backpressure is engaged (guest Pods can't be placed,
/// so create/recycle is held instead of churning unschedulable members);
/// 0 otherwise (issue #189). Derived purely from the existing #191
/// scheduling-blocked state — observability only, never an admission gate.
pub static POOL_CAPACITY_BLOCKED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_pool_capacity_blocked",
        "1 when the pool has scheduling-blocked (capacity-starved) instances (#191 backpressure engaged), else 0",
        &["profile"]
    )
    .unwrap()
});

/// Effective memory request (bytes) kobe stamps onto each guest pod
/// (k3s server + agent) for this pool — explicit `requests.memory` or, when
/// absent, the `limits.memory` the kubelet silently copies into the request.
/// Sibling of `kobe_pool_effective_cpu_request_millicores`: surfaces hidden
/// over-reservation the same way, e.g. `limits.memory:"4Gi"` with empty
/// requests reserves 4Gi per pod (8Gi/cluster), invisible until the nodes
/// wedge (issue #189). 0 when the pool sets no memory limit/request.
pub static POOL_EFFECTIVE_MEMORY_REQUEST_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_pool_effective_memory_request_bytes",
        "Effective per-guest-pod memory request (bytes), incl. the kubelet's silent limit→request copy",
        &["profile"]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Lease timing: queue wait (Pending→terminal) + hold duration (Bound→terminal)
// ─────────────────────────────────────────────────────────────────────

/// Time a claim spent in `Pending` before reaching a terminal state, keyed by
/// `outcome` (`bound` | `expired` | `cancelled`). This is the *backlog /
/// exhaustion* view: the incident that motivated it (#189) had claims waiting
/// minutes for a full pool, and the ones that never bound left no duration
/// signal at all.
///
/// Deliberately distinct from [`CLAIM_BIND_DURATION`], which keeps sub-second
/// buckets as the fast-path bind SLI ("is binding instant?") and only records
/// successful binds. This histogram instead answers "how long do claims wait,
/// including the ones that time out or get cancelled?" — so its buckets span
/// 1s → 30min (pool `queue_timeout` is minutes-scale) and it carries the
/// terminal `outcome`. The overlap on `outcome="bound"` is intentional: the two
/// serve different questions (latency SLI vs saturation) and need different
/// bucketing.
pub static LEASE_QUEUE_WAIT_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_lease_queue_wait_seconds",
        "Time a claim spent Pending before reaching a terminal state, by outcome",
        &["profile", "outcome"],
        vec![1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0]
    )
    .unwrap()
});

/// Time a lease was held in `Bound` before its terminal transition, keyed by
/// `outcome` (`released` | `expired`). Hold-time × arrival-rate is what sizes a
/// warm pool — without it, right-sizing a pool after an exhaustion incident
/// (#189) is guesswork. Measured from `status.bound_at` to the release / TTL
/// expiry, co-located with the existing `kobe_claims_total{event}` emissions so
/// it counts the same transitions (the reaper backstop path is intentionally
/// not double-counted).
///
/// Buckets span 30s → 4h: the default lease TTL is 1h and leases extend up to a
/// policy `max_ttl` ceiling, so the tail past 1h captures extended holds.
pub static LEASE_HOLD_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_lease_hold_seconds",
        "Time a lease was held in Bound before release or expiry, by outcome",
        &["profile", "outcome"],
        vec![30.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// PKI: certificate expiry horizon
// ─────────────────────────────────────────────────────────────────────

/// Worst-case (minimum) seconds until certificate expiry across a pool's
/// instances, by `component` (`ca` | `apiserver` | `front_proxy_ca`). Sourced
/// from each instance's `{name}-certs` Secret — the kobe-managed PKI in
/// `pki.rs` — so it only populates for backends that use it (vcluster / vkobe);
/// k3s/k0s manage their own in-cluster PKI.
///
/// Rolled up per pool, NOT per cluster: cluster identity is high-cardinality and
/// never a label (module rule). The *minimum* horizon makes "some cluster in
/// this pool has a cert expiring soon" alertable; the specific cluster lives in
/// logs/traces. Goes negative once a cert is past `NotAfter`.
///
/// Note (#169): the kobe PKI currently sets no explicit validity (rcgen default
/// → effectively non-expiring), so today this surfaces that state rather than a
/// tight horizon; bounded validity + recycle-before-expiry is the tracked
/// follow-up. Emitting the gauge now means the alert/dashboard wiring is ready
/// the day validity becomes bounded.
pub static CERT_EXPIRY_SECONDS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kobe_cert_expiry_seconds",
        "Worst-case seconds until certificate expiry per pool, by component",
        &["profile", "component"]
    )
    .unwrap()
});

// ─────────────────────────────────────────────────────────────────────
// Connect proxy: request latency + per-lease cache effectiveness
// ─────────────────────────────────────────────────────────────────────

/// Wall-clock of one full `connect_proxy_inner` invocation, from entry to
/// completion (buffered response sent, or upgrade tunnel handed off).
///
/// Labels: `kind` (`buffered` | `upgrade`).
///
/// Buckets cover sub-ms → seconds: a cache-hit buffered GET against a warm
/// backend should land in the low-ms buckets, a cache-miss pays 3 serial
/// kube GETs + a fresh reqwest client build (tens of ms), and slow upstreams
/// / large bodies fill the tail. The point of this histogram is to make the
/// cache win (hit vs miss latency) measurable, so the fast buckets are dense.
pub static CONNECT_PROXY_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_connect_proxy_request_duration_seconds",
        "Time spent in one connect-proxy request",
        &["kind"],
        vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
        ]
    )
    .unwrap()
});

/// Per-lease connect-context cache outcome counter.
///
/// Labels: `result` (`hit` | `miss`). A `hit` skips token validation, the
/// lease GET, the kubeconfig Secret read, and the reqwest client build; a
/// `miss` runs the full path and repopulates the cache.
pub static CONNECT_PROXY_CACHE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_connect_proxy_cache_total",
        "Connect-proxy per-lease cache lookups by result",
        &["result"]
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

/// Seconds elapsed from an RFC3339 timestamp to now, or `None` if the string is
/// absent / unparseable. Clamps negatives to `0.0` so clock skew never records
/// a nonsensical negative duration into a lease-timing histogram.
pub fn elapsed_secs_since_rfc3339(ts: Option<&str>) -> Option<f64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts?).ok()?;
    let secs = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc)).num_milliseconds() as f64
        / 1000.0;
    Some(secs.max(0.0))
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
    LazyLock::force(&POOL_EFFECTIVE_CPU_REQUEST_MILLICORES);
    LazyLock::force(&POOL_CAPACITY_BLOCKED);
    LazyLock::force(&POOL_EFFECTIVE_MEMORY_REQUEST_BYTES);
    // Connect proxy
    LazyLock::force(&CONNECT_PROXY_REQUEST_DURATION);
    LazyLock::force(&CONNECT_PROXY_CACHE_TOTAL);
    // Lease timing
    LazyLock::force(&LEASE_QUEUE_WAIT_SECONDS);
    LazyLock::force(&LEASE_HOLD_SECONDS);
    // PKI
    LazyLock::force(&CERT_EXPIRY_SECONDS);
    // P0 observability
    LazyLock::force(&POOL_CONSECUTIVE_FAILURES);
    LazyLock::force(&POOL_FAILURE_REASON_CHANGES_TOTAL);
    LazyLock::force(&BACKEND_DELETE_FAILURES_TOTAL);
    LazyLock::force(&INSTANCE_STUCK_CREATING_TOTAL);
    LazyLock::force(&GUEST_POD_OOM_KILLS_TOTAL);
    LazyLock::force(&GUEST_POD_UNSCHEDULABLE_TOTAL);
    LazyLock::force(&GUEST_POD_CRASHLOOP_TOTAL);
    LazyLock::force(&CONNECT_PROXY_REQUEST_OUTCOME_TOTAL);
    // Auth
    LazyLock::force(&AUTH_SUCCESS_TOTAL);
    LazyLock::force(&AUTH_FAILURE_TOTAL);
    // Lease exhaustion (#189)
    LazyLock::force(&LEASE_UNSATISFIABLE_TOTAL);
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

    // ── P0 enum / classifier tests ────────────────────────────────────

    #[test]
    fn pool_failure_class_as_str() {
        assert_eq!(PoolFailureClass::BackendCreate.as_str(), "backend_create");
        assert_eq!(PoolFailureClass::BackendDelete.as_str(), "backend_delete");
        assert_eq!(PoolFailureClass::Bootstrap.as_str(), "bootstrap");
        assert_eq!(PoolFailureClass::Health.as_str(), "health");
        assert_eq!(
            PoolFailureClass::KobestoreDegraded.as_str(),
            "kobestore_degraded"
        );
        assert_eq!(PoolFailureClass::Ipam.as_str(), "ipam");
        assert_eq!(PoolFailureClass::Capacity.as_str(), "capacity");
        assert_eq!(PoolFailureClass::Other.as_str(), "other");
    }

    #[test]
    fn pool_failure_class_from_reason() {
        use PoolFailureClass as P;
        // delete-related keywords win over a co-occurring "create".
        assert_eq!(
            P::from_reason("best-effort PodDisruptionBudget delete failed"),
            P::BackendDelete
        );
        assert_eq!(
            P::from_reason("failed to delete server StatefulSet"),
            P::BackendDelete
        );
        assert_eq!(
            P::from_reason("bootstrap Job BackoffLimitExceeded"),
            P::Bootstrap
        );
        assert_eq!(P::from_reason("health probes failed 3 times"), P::Health);
        assert_eq!(
            P::from_reason("KobeStore degraded: MemoryPressure"),
            P::KobestoreDegraded
        );
        assert_eq!(
            P::from_reason("datastore unavailable"),
            P::KobestoreDegraded
        );
        assert_eq!(P::from_reason("CIDR pool exhausted"), P::Ipam);
        assert_eq!(P::from_reason("ipam conflict on claim"), P::Ipam);
        assert_eq!(
            P::from_reason("Failed to apply server StatefulSet"),
            P::BackendCreate
        );
        // Capacity wedge: the #191 scheduling-blocked reason wording (#189).
        assert_eq!(
            P::from_reason(
                "capacity-blocked: 2 instance(s) unschedulable; 2 instance(s) not \
                 reaching Ready (attempted up to index 3, highest Ready 1)"
            ),
            P::Capacity
        );
        assert_eq!(P::from_reason("Insufficient cpu"), P::Capacity);
        assert_eq!(
            P::from_reason("scheduling blocked: Unschedulable"),
            P::Capacity
        );
        // The generic backoff reason text → Other.
        assert_eq!(
            P::from_reason(
                "2 instance(s) not reaching Ready (attempted up to index 3, highest Ready 1)"
            ),
            P::Other
        );
    }

    #[test]
    fn backend_op_error_reason_as_str() {
        assert_eq!(BackendOpErrorReason::Rbac.as_str(), "rbac");
        assert_eq!(BackendOpErrorReason::NotFound.as_str(), "not_found");
        assert_eq!(BackendOpErrorReason::Timeout.as_str(), "timeout");
        assert_eq!(BackendOpErrorReason::Conflict.as_str(), "conflict");
        assert_eq!(BackendOpErrorReason::Io.as_str(), "io");
        assert_eq!(BackendOpErrorReason::Other.as_str(), "other");
    }

    fn api_error(code: u16, reason: &str) -> kube::Error {
        kube::Error::Api(
            kube::core::Status::failure(&format!("{reason} (code {code})"), reason)
                .with_code(code)
                .boxed(),
        )
    }

    #[test]
    fn classify_kube_error_by_code() {
        assert_eq!(
            classify_kube_error(&api_error(403, "Forbidden")),
            BackendOpErrorReason::Rbac
        );
        assert_eq!(
            classify_kube_error(&api_error(404, "NotFound")),
            BackendOpErrorReason::NotFound
        );
        assert_eq!(
            classify_kube_error(&api_error(409, "Conflict")),
            BackendOpErrorReason::Conflict
        );
        assert_eq!(
            classify_kube_error(&api_error(504, "Timeout")),
            BackendOpErrorReason::Timeout
        );
    }

    #[test]
    fn classify_kube_error_by_reason_fallback() {
        // Code 0 (unknown) but reason text carries the signal.
        assert_eq!(
            classify_kube_error(&api_error(0, "Forbidden")),
            BackendOpErrorReason::Rbac
        );
        assert_eq!(
            classify_kube_error(&api_error(0, "AlreadyExists")),
            BackendOpErrorReason::Conflict
        );
        assert_eq!(
            classify_kube_error(&api_error(0, "SomethingWeird")),
            BackendOpErrorReason::Other
        );
    }

    #[test]
    fn stuck_creating_reason_as_str() {
        assert_eq!(StuckCreatingReason::Timeout.as_str(), "timeout");
        assert_eq!(StuckCreatingReason::Drift.as_str(), "drift");
        assert_eq!(StuckCreatingReason::Unschedulable.as_str(), "unschedulable");
        assert_eq!(StuckCreatingReason::CrashLooping.as_str(), "crashlooping");
    }

    /// The Unschedulable counter must be registerable with its full 4-label
    /// set so an emission at the call site never panics on a label mismatch.
    #[test]
    fn guest_pod_unschedulable_total_accepts_labels() {
        init();
        GUEST_POD_UNSCHEDULABLE_TOTAL
            .with_label_values(&["_test", "k3s", "server", "Unschedulable"])
            .inc();
        let output = gather();
        assert!(
            output.contains("kobe_guest_pod_unschedulable_total"),
            "unschedulable counter must appear after an observation"
        );
    }

    /// The crashloop counter must be registerable with its full 4-label set
    /// (`profile, backend, pod_role, exit_code`) so an emission at the call
    /// site never panics on a label mismatch.
    #[test]
    fn guest_pod_crashloop_total_accepts_labels() {
        init();
        GUEST_POD_CRASHLOOP_TOTAL
            .with_label_values(&["_test", "k3s", "server", "2"])
            .inc();
        let output = gather();
        assert!(
            output.contains("kobe_guest_pod_crashloop_total"),
            "crashloop counter must appear after an observation"
        );
    }

    #[test]
    fn guest_pod_role_as_str() {
        assert_eq!(GuestPodRole::Server.as_str(), "server");
        assert_eq!(GuestPodRole::Agent.as_str(), "agent");
        assert_eq!(GuestPodRole::Kine.as_str(), "kine");
        assert_eq!(GuestPodRole::Datastore.as_str(), "datastore");
        assert_eq!(GuestPodRole::Other.as_str(), "other");
    }

    #[test]
    fn guest_pod_role_from_pod_name() {
        use GuestPodRole as R;
        assert_eq!(R::from_pod_name("pool-e2e-basic-0-server-0"), R::Server);
        assert_eq!(
            R::from_pod_name("pool-e2e-basic-0-agent-7d9c-abcde"),
            R::Agent
        );
        // kine takes priority even if other substrings are present.
        assert_eq!(R::from_pod_name("kobestore-kine-5f6c-xyz"), R::Kine);
        assert_eq!(R::from_pod_name("etcd-0"), R::Datastore);
        assert_eq!(R::from_pod_name("postgres-primary-0"), R::Datastore);
        assert_eq!(R::from_pod_name("some-random-pod"), R::Other);
    }

    #[test]
    fn lease_unsatisfiable_reason_as_str() {
        assert_eq!(
            LeaseUnsatisfiableReason::PoolExhausted.as_str(),
            "pool_exhausted"
        );
        assert_eq!(
            LeaseUnsatisfiableReason::CapacityBlocked.as_str(),
            "capacity_blocked"
        );
        assert_eq!(LeaseUnsatisfiableReason::Degraded.as_str(), "degraded");
        assert_eq!(LeaseUnsatisfiableReason::Warming.as_str(), "warming");
    }

    /// The lease-timing histograms must register with their full
    /// `[profile, outcome]` label set so an emission never panics on a mismatch.
    #[test]
    fn lease_timing_histograms_registerable() {
        init();
        LEASE_QUEUE_WAIT_SECONDS
            .with_label_values(&["_test", "bound"])
            .observe(1.5);
        LEASE_HOLD_SECONDS
            .with_label_values(&["_test", "released"])
            .observe(600.0);
        let output = gather();
        assert!(
            output.contains("kobe_lease_queue_wait_seconds"),
            "queue-wait histogram must appear after an observation"
        );
        assert!(
            output.contains("kobe_lease_hold_seconds"),
            "hold-duration histogram must appear after an observation"
        );
    }

    /// Elapsed helper: absent / unparseable → None; a past timestamp → positive;
    /// a future timestamp (clock skew) clamps to 0.0 rather than going negative.
    #[test]
    fn elapsed_secs_since_rfc3339_behaviour() {
        assert_eq!(elapsed_secs_since_rfc3339(None), None);
        assert_eq!(elapsed_secs_since_rfc3339(Some("not-a-timestamp")), None);

        let past = (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
        let elapsed = elapsed_secs_since_rfc3339(Some(&past)).expect("parseable past ts");
        assert!(
            (100.0..1000.0).contains(&elapsed),
            "≈120s expected, got {elapsed}"
        );

        let future = (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        assert_eq!(
            elapsed_secs_since_rfc3339(Some(&future)),
            Some(0.0),
            "future timestamp must clamp to 0.0"
        );
    }

    #[test]
    fn connect_outcome_as_str() {
        assert_eq!(ConnectOutcome::Ok.as_str(), "ok");
        assert_eq!(ConnectOutcome::MissingToken.as_str(), "missing_token");
        assert_eq!(ConnectOutcome::InvalidToken.as_str(), "invalid_token");
        assert_eq!(ConnectOutcome::LeaseNotFound.as_str(), "lease_not_found");
        assert_eq!(ConnectOutcome::PhaseNotBound.as_str(), "phase_not_bound");
        assert_eq!(ConnectOutcome::Expired.as_str(), "expired");
        assert_eq!(ConnectOutcome::BackendError.as_str(), "backend_error");
    }
}
