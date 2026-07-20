//! Pool-state evaluation: drift detection, state taxonomy, and
//! action emission.
//!
//! # Layers, in order of evaluation
//!
//! [`compute_pool_actions`] evaluates each layer in turn. Earlier
//! layers' decisions feed counters consumed by later layers.
//!
//! 1. **Unhealthy recycle** — broken instances always Deleted.
//!    Unbounded by policy; never violates a floor (broken instances
//!    contribute zero capacity).
//! 2. **Backoff early-return** — if `backoff_active`, drift recycle
//!    and scale-up are both suppressed. Stuck-Creating timeout still
//!    runs (it doesn't consume create budget).
//! 3. **Drifted Creating recycle** — Deleted immediately, no rate
//!    cap, no surge cost. They contribute zero ready capacity, so
//!    finishing them on the old version is wasted boot time.
//! 4. **Drifted Ready rolling recycle** — at most
//!    [`crate::crd::UpgradePolicy::max_recycling`] Deletes per
//!    reconcile, gated by `min_ready_during_upgrade`. The post-Delete
//!    total Ready must remain `>= floor`. Order: oldest
//!    `state_since` first.
//! 5. **Stuck Creating timeout** — Creating instances older than
//!    10min are Deleted (independent of drift; covers wedged
//!    bootstraps even when the hash matches).
//! 6. **Scale-up** — refill toward `min_ready` plus surge if drift
//!    remains. The surge target is `min_ready + min(max_surge,
//!    drift_in_flight)`; only fires when there's drift to absorb so
//!    a fresh pool boot doesn't overshoot.
//! 7. **Scale-down** — skipped while drift upgrade in progress;
//!    otherwise reaps idle Ready past `scale_down_after`.
//!
//! # Drift sources
//!
//! See [`profile_spec_hash`]. Three inputs flow into the hash; any
//! change flips it and makes existing instances drift-eligible:
//!
//! - User-visible `ClusterPool` spec (cluster config, addons,
//!   bootstrap *names*).
//! - [`RenderContext`] — operator-level config (e.g.
//!   `KOBE_SYNC_IMAGE`). Vkobe pools only.
//! - Resolved CONTENT of each referenced
//!   [`crate::crd::BootstrapConfig`] — editing the install manifest
//!   without renaming the bootstrap still triggers recycle.
//!
//! # Rolling-upgrade policy
//!
//! See [`crate::crd::UpgradePolicy`] for the user-facing knobs and
//! `docs/guides/upgrade-policy.md` for tuning guidance per pool
//! shape.

use std::collections::HashMap;

use crate::crd::ClusterPool;

/// Hash of the cluster spec at creation time, used to detect drift.
///
/// `String` (not `u64`/`i64`) because the value travels over JSON via the
/// `ClusterInstanceStatus.specHash` field, and Kubernetes' OpenAPI
/// structural schema validator parses numeric values through `float64`
/// internally — integers outside JSON's safe range (±2⁵³−1) lose precision,
/// gain a fractional component, and fail `type: integer` validation with
/// `Invalid value: "number": specHash in body must be of type integer`.
/// Encoding as a string sidesteps the issue entirely with no entropy loss,
/// matching the same pattern Kubernetes uses for `metadata.resourceVersion`
/// and other large-integer-like fields.
///
/// The format is fixed-width 16-character lowercase hex (a `u64` rendered
/// as `{:016x}`), so equality comparison works directly via `==`.
pub type SpecHash = String;

/// Operator-level context that affects rendered backend resources but
/// isn't part of the ClusterPool spec users write.
///
/// Anything in here is rolled into `profile_spec_hash`, so when the
/// operator is upgraded with a new value (`KOBE_SYNC_IMAGE` bump,
/// new defaults, …) existing pool members detect drift and recycle
/// automatically. Without this, a sidecar image change in the operator
/// Deployment env would land but every existing vkobe pool would keep
/// running its old sidecar binary indefinitely (k8s only triggers a
/// rollout when the *workload* spec changes, and the workload's image
/// is interpolated from the operator env at create time — invisible to
/// the workload's PodTemplate hash).
///
/// Backends that don't consume a particular field ignore it during
/// hashing, so unrelated pool members aren't churned by a config bump
/// that doesn't affect them (e.g. a `kobe-sync` image bump leaves k3s
/// and k0s pool spec hashes untouched).
#[derive(Debug, Clone)]
pub struct RenderContext {
    /// Image of the kobe-sync sidecar deployed inside vkobe pods. Read
    /// from the `KOBE_SYNC_IMAGE` env at operator startup. Only vkobe
    /// pools fold this into their spec hash.
    pub kobe_sync_image: String,
}

impl RenderContext {
    /// Read the operator-level config from environment at startup.
    pub fn from_env() -> Self {
        Self {
            kobe_sync_image: std::env::var("KOBE_SYNC_IMAGE")
                .unwrap_or_else(|_| "zondax/kobe-sync:unknown".to_string()),
        }
    }

    /// Build a context with a specific kobe-sync image. Used in tests
    /// and by callers that want to compare hashes against a known-good
    /// reference value.
    ///
    /// `#[allow(dead_code)]` shields the cross-binary visibility quirk:
    /// the `crdgen` binary imports this module to walk schemas but
    /// never instantiates `RenderContext`, so clippy flags this as
    /// dead from its perspective even though the operator binary and
    /// tests both call it.
    #[allow(dead_code)]
    pub fn with_kobe_sync_image(image: impl Into<String>) -> Self {
        Self {
            kobe_sync_image: image.into(),
        }
    }
}

/// Compute a hash of the profile's cluster-relevant fields.
///
/// Returns the hash as fixed-width hex so the value round-trips through
/// the apiserver as a string — see `SpecHash` doc for why this matters.
///
/// The hash folds in three sources:
///
/// 1. The user-visible ClusterPool spec (cluster config, addons,
///    bootstrap **references**, etc.).
/// 2. `RenderContext` — operator-level config that affects rendering
///    but isn't user-facing (e.g. the kobe-sync sidecar image).
/// 3. `bootstrap_specs` — the resolved CONTENT of each `BootstrapConfig`
///    referenced by the pool, keyed by name. The `spec.bootstraps` list
///    only carries names; the apply/install manifests live inside each
///    BootstrapConfig CR. Hashing only the names misses content changes
///    (user updates the flux install manifest, the bootstrap shell
///    script, etc.) — without folding the resolved spec into the hash,
///    such edits would silently apply to NEW pool members but never
///    recycle existing idle members. Caller resolves bootstrap CRs
///    once per reconcile and passes them in.
///
/// Together these define drift: any change to user spec, operator-level
/// config, or referenced BootstrapConfig content flips the hash, and
/// `compute_pool_actions` recycles unclaimed pool members on the next
/// reconcile. Leased members keep running; they'll get the fresh hash
/// when they're released and recycled.
pub fn profile_spec_hash(
    profile: &ClusterPool,
    render_ctx: &RenderContext,
    bootstrap_specs: &std::collections::BTreeMap<String, crate::crd::BootstrapConfigSpec>,
) -> SpecHash {
    use crate::crd::BackendType;
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Hash the fields that affect how a cluster is created
    profile.spec.cluster.version.hash(&mut hasher);
    profile.spec.cluster.servers.hash(&mut hasher);
    profile.spec.cluster.agents.hash(&mut hasher);
    profile.spec.cluster.server_args.hash(&mut hasher);
    // Taints affect kubelet registration args (k0s `--no-taints`/`--taints`
    // and k3s `--node-taint`) — a change must trigger pool recycling so
    // existing warm clusters pick up the new taint set rather than
    // continuing to serve under the previous configuration.
    format!("{:?}", profile.spec.cluster.taints).hash(&mut hasher);
    format!("{:?}", profile.spec.backend).hash(&mut hasher);
    format!("{:?}", profile.spec.addons).hash(&mut hasher);
    format!("{:?}", profile.spec.bootstraps).hash(&mut hasher);

    // Resolved bootstrap CONTENT for each name referenced in the pool.
    // Iterate the pool's reference list (not the resolved map) to keep
    // hash order deterministic w.r.t. the user-visible spec — a missing
    // resolution still flips the hash because we hash a sentinel.
    for bs_ref in &profile.spec.bootstraps {
        bs_ref.name.hash(&mut hasher);
        match bootstrap_specs.get(&bs_ref.name) {
            Some(spec) => {
                // Debug-format hashing matches the pattern used elsewhere
                // (taints, addons). Captures every Serialize-relevant
                // field of `BootstrapConfigSpec` without forcing all
                // nested types to derive `Hash`.
                format!("{spec:?}").hash(&mut hasher);
            }
            None => {
                // Reference a name we couldn't resolve (e.g. the CR was
                // deleted) — fold a stable sentinel so hash stability
                // doesn't depend on whether the lookup happened to
                // succeed at this exact reconcile.
                "<unresolved>".hash(&mut hasher);
            }
        }
    }

    // Operator-level config that ONLY affects vkobe-rendered resources
    // (the kobe-sync sidecar). Folding it in here means a sidecar image
    // bump in the operator Deployment env triggers drift on vkobe pools
    // and recycles their pool members; k3s/k0s/capi pools don't see
    // this bit so they aren't churned by an unrelated change.
    if profile.spec.backend.backend_type == BackendType::Vkobe {
        render_ctx.kobe_sync_image.hash(&mut hasher);
    }

    format!("{:016x}", hasher.finish())
}

/// Fully-populated rolling-upgrade policy values, as consumed by
/// [`compute_pool_actions`]. Every `Option` from
/// [`crate::crd::UpgradePolicy`] (or the absence of the whole struct
/// on a pool) is folded into a concrete value here so the algorithm
/// doesn't have to thread `Option` chains through the recycle logic.
///
/// This is the only place that knows the default values. Tests live
/// alongside `compute_pool_actions` and construct `ResolvedUpgradePolicy`
/// directly to pin algorithm invariants without coupling to the CRD
/// shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedUpgradePolicy {
    /// See [`crate::crd::UpgradePolicy::max_recycling`].
    pub max_recycling: u32,
    /// See [`crate::crd::UpgradePolicy::max_surge`].
    pub max_surge: u32,
    /// Floor on `ready_clean` during upgrade. Defaulted to `min_ready`
    /// (or `spec.size`) when [`crate::crd::UpgradePolicy::min_ready_during_upgrade`]
    /// is `None`.
    pub min_ready_during_upgrade: u32,
}

/// Resolve the rolling-upgrade policy for a profile, folding in
/// per-field and whole-struct defaults so the caller gets a
/// [`ResolvedUpgradePolicy`] with every field populated.
///
/// `min_ready` is the value used as the fallback floor when
/// [`crate::crd::UpgradePolicy::min_ready_during_upgrade`] is `None`.
/// Callers compute it once from `scaling.min_ready` (or `spec.size`)
/// and pass it through.
pub fn resolved_upgrade_policy(profile: &ClusterPool, min_ready: u32) -> ResolvedUpgradePolicy {
    match &profile.spec.upgrade_policy {
        Some(p) => ResolvedUpgradePolicy {
            max_recycling: p.max_recycling,
            max_surge: p.max_surge,
            min_ready_during_upgrade: p.min_ready_during_upgrade.unwrap_or(min_ready),
        },
        None => ResolvedUpgradePolicy {
            max_recycling: 1,
            max_surge: 1,
            min_ready_during_upgrade: min_ready,
        },
    }
}

/// Tracks the state of each cluster in a profile's pool.
#[derive(Debug, Clone, PartialEq)]
pub enum ClusterState {
    /// Being created, not yet ready.
    Creating,
    /// Ready and idle, available for claims.
    Ready,
    /// Bound to a claim.
    Leased,
    /// Failed health check, being recycled.
    Unhealthy,
    /// Being deleted and recreated.
    #[allow(dead_code)]
    Recycling,
}

/// Pool state for a single profile.
#[derive(Debug, Clone)]
pub struct PoolState {
    /// Map of cluster name → state.
    pub clusters: HashMap<String, ClusterEntry>,
}

#[derive(Debug, Clone)]
pub struct ClusterEntry {
    pub state: ClusterState,
    /// When this cluster became idle (for scale-down decisions).
    pub idle_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Consecutive health check failures.
    #[allow(dead_code)]
    pub health_failures: u32,
    /// When this entry was created/entered current state (for stuck-Creating timeout).
    pub state_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of the profile spec when this cluster was created.
    /// Used to detect spec drift and trigger recreation of unclaimed clusters.
    pub spec_hash: Option<SpecHash>,
    /// The instance controller flagged this Creating instance as
    /// scheduling-blocked (guest server/agent Pods Unschedulable, #189) via
    /// its `status.message` prefix. The stuck-Creating timeout (steps 2 & 5)
    /// must NOT Delete such an entry — recycling would just respawn Pods that
    /// still can't schedule. The profile controller engages backpressure
    /// (extends `next_attempt_at`) for it instead. Derived from the synced
    /// status message in `build_pool_state`; `false` for every other state.
    pub scheduling_blocked: bool,
    /// The instance controller flagged this Creating instance as crashlooping
    /// (guest server/agent container `CrashLoopBackOff`, #197) via its
    /// `status.message` marker. Purely observational: it does NOT suppress the
    /// stuck-Creating recycle (a crashlooper SHOULD be respawned). It only
    /// switches the recycle's [`crate::metrics::StuckCreatingReason`] label
    /// from `Timeout` to `CrashLooping` so the wedge is attributable. Derived
    /// from the synced status message in `build_pool_state`; `false` otherwise.
    pub crashlooping: bool,
    /// The crashlooping instance's `status.message` (e.g. `guest server pod
    /// CrashLoopBackOff: Error exit 2 (x6); last log: panic: ...`), carried so
    /// the pool's `lastFailureReason` can cite concrete evidence instead of
    /// only pointing at `kubectl`. `None` unless `crashlooping`.
    pub crash_message: Option<String>,
}

/// Decisions the pool manager emits after evaluating state.
#[derive(Debug, Clone)]
pub enum PoolAction {
    /// Create a new cluster with this name.
    Create(String),
    /// Delete this cluster (scale down or recycle).
    Delete(String),
    /// Mark this cluster as unhealthy for recycling.
    #[allow(dead_code)]
    MarkUnhealthy(String),
}

/// Compute the desired `PoolAction`s for one reconcile pass.
///
/// Pure: takes immutable state and `now`, returns a list of actions
/// the controller will issue. No I/O. The reconciler in
/// `controllers::profile` owns all side effects.
///
/// # Order of evaluation
///
/// Each step's outcome feeds the next via local counters, but each
/// step only inspects `state` and the running `actions` list — no
/// global state.
///
/// 1. **Unhealthy → `Delete`** (unbounded).
///    Broken instances contribute zero capacity; removing them is
///    pure win and never violates any floor. Not gated by
///    `max_recycling`, the failure backoff, or the upgrade policy.
///
/// 2. **Backoff early-return.**
///    If `backoff_active`, drift recycling and scale-up are both
///    suppressed (Deleting drifted Ready when we can't create the
///    replacement would just bleed capacity). Unhealthy `Delete`s
///    from step 1 still ship — they don't consume create budget.
///
/// 3. **Drifted Creating → `Delete` (immediate, unbounded).**
///    A Creating instance with a stamped `spec_hash != current_hash`
///    contributes zero ready capacity; letting it finish on the old
///    version just wastes the create cost. Skipped when the entry
///    has no stamped hash yet (initial-status patch race).
///
/// 4. **Drifted Ready → `Delete` (rolling, capped).**
///    At most `policy.max_recycling` per reconcile. Each Delete is
///    gated on the post-Delete `ready_clean` count still being
///    `>= policy.min_ready_during_upgrade`. Recycle order is
///    `state_since` ascending — the oldest Ready first. The required
///    `ready_clean` headroom is what `policy.max_surge` purchases via
///    the scale-up step below: surge runs FIRST in earlier reconciles,
///    landing fresh `ready_clean` instances that this step can then
///    recycle without dipping under the floor.
///
/// 5. **Stuck Creating timeout (configurable, default 10 min).**
///    `Delete` Creating instances whose `state_since` is older than
///    the timeout. Independent of drift — covers the case where a
///    Creating is *clean* (current hash) but the bootstrap is wedged.
///    Deduplicated against step 3 (no double-Delete).
///
/// 6. **Scale-up.**
///    Refill toward `min_ready`, plus up to `policy.max_surge` extras
///    when there is at least one drifted Ready remaining (the surge
///    only fires when there is drift to absorb; otherwise the warm
///    target stays at `min_ready` and a fresh pool boot doesn't
///    overshoot). Capped by `MAX_BURST` per reconcile and by
///    `max_clusters`. Also gated by `backoff_active`.
///
/// 7. **Scale-down.**
///    SKIPPED entirely while a drift upgrade is in progress (any
///    drifted Ready or drifted Creating remaining). Without this
///    gate, a fresh replacement that just landed would be reaped as
///    "excess idle past min_ready" the moment `ready_clean` exceeds
///    `min_ready` — destroying exactly the capacity the surge was
///    meant to provide. When no drift remains, scale-down resumes
///    its usual idle-trim behavior.
///
/// # Invariants pinned by tests
///
/// - Every reconcile preserves `ready_clean >= policy.min_ready_during_upgrade`
///   (modulo entry conditions where the floor was already violated).
/// - At most `policy.max_recycling` Deletes against drifted Ready
///   per call.
/// - Unhealthy Deletes are never bounded by `max_recycling`.
/// - Leased instances are never Deleted, regardless of drift.
/// - `backoff_active` suppresses drift recycle AND scale-up
///   symmetrically.
///
/// See [`UpgradePolicy`](crate::crd::UpgradePolicy) for the knobs and
/// `docs/guides/upgrade-policy.md` for the operator-facing tuning
/// guide.
/// Resolve the per-pool stuck-Creating timeout. Falls back to the
/// operator's pre-CRD default of 10 minutes when the field is missing
/// (no `scaling` block) or malformed (`parse_duration` returns None).
/// Logs a warning when the field is set but unparseable so typos
/// don't silently keep the default.
fn resolve_creating_timeout(profile: &crate::crd::ClusterPool) -> chrono::Duration {
    let default = chrono::Duration::minutes(10);
    let Some(scaling) = profile.spec.scaling.as_ref() else {
        return default;
    };
    match parse_duration(&scaling.creating_timeout) {
        Some(d) => d,
        None => {
            tracing::warn!(
                profile = %profile.metadata.name.as_deref().unwrap_or("?"),
                value = %scaling.creating_timeout,
                "ScalingConfig.creatingTimeout is unparseable; falling back to 10m default. \
                 Format: \"10m\", \"1h\", \"900s\"."
            );
            default
        }
    }
}

/// Grace before an *unstamped* (`spec_hash == None`) cluster is treated as
/// drift-eligible. Covers the brief create→`patch_status` round-trip where a
/// fresh cluster legitimately has no recorded hash yet (sub-second in practice);
/// 2 minutes is generous.
const UNSTAMPED_RECYCLE_GRACE: chrono::Duration = chrono::Duration::minutes(2);

/// Prefix the instance controller stamps on `ClusterInstance.status.message`
/// when it detects the guest server/agent Pods are Unschedulable (#189).
///
/// This is the cross-controller channel for the scheduling-block signal: the
/// instance controller (producer) holds the live backend handle to probe
/// Pods, while the pool manager (consumer) owns the stuck-Creating recycle
/// decision. Rather than widen the CRD with a new bool field, the manager
/// reads this prefix off the status message it already syncs into
/// `PoolState`; a Creating entry carrying it is held with backpressure
/// (next_attempt_at extended) instead of being Deleted — recycling would only
/// respawn Pods that still can't schedule (a thundering herd).
pub const SCHEDULING_BLOCKED_MESSAGE_PREFIX: &str = "scheduling blocked:";

/// Marker the instance controller embeds in `ClusterInstance.status.message`
/// when it detects the guest server/agent container is crashlooping (#197).
///
/// Same cross-controller channel as [`SCHEDULING_BLOCKED_MESSAGE_PREFIX`]: the
/// instance controller (producer) holds the live backend handle to probe the
/// Pods' `containerStatuses[]`, while the pool manager (consumer) labels the
/// stuck-Creating recycle. Matched as a substring (the human crash message is
/// `guest <role> pod CrashLoopBackOff: ...`, which carries this token
/// verbatim) so the message stays readable rather than being a coded prefix.
///
/// Unlike the scheduling-block prefix this does NOT change the recycle
/// decision — a crashlooping `Creating` still recycles on the creating-timeout
/// exactly as before; the marker only lets the manager emit
/// `kobe_instance_stuck_creating_total{reason="crashlooping"}` so the recycle
/// is attributable to a crash rather than a plain timeout (#197).
pub const CRASHLOOP_MESSAGE_MARKER: &str = "CrashLoopBackOff";

/// Whether a cluster entry should recycle for spec drift.
///
/// A *stamped* entry drifts when its hash differs from `current_hash`. An
/// *unstamped* entry (`spec_hash == None`) is a pre-provenance legacy cluster —
/// kobe < 0.12.2 never persisted the hash, so it can never be drift-detected and
/// would survive forever as a blind spot. Treat it as drift-eligible once it has
/// been in its current state longer than [`UNSTAMPED_RECYCLE_GRACE`], so future
/// upgrades clean it up automatically instead of requiring a manual delete. The
/// grace prevents a brand-new cluster (whose hash hasn't round-tripped yet) from
/// self-destructing. (Safe only now that the `spec_hash` field is protected from
/// Merge-Patch erasure — see #41 part A.)
fn entry_drift_eligible(
    spec_hash: Option<&SpecHash>,
    state_since: Option<chrono::DateTime<chrono::Utc>>,
    current_hash: &SpecHash,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match spec_hash {
        Some(h) => h != current_hash,
        None => state_since
            .map(|t| now - t >= UNSTAMPED_RECYCLE_GRACE)
            .unwrap_or(false),
    }
}

pub fn compute_pool_actions(
    profile: &ClusterPool,
    state: &PoolState,
    now: chrono::DateTime<chrono::Utc>,
    render_ctx: &RenderContext,
    bootstrap_specs: &std::collections::BTreeMap<String, crate::crd::BootstrapConfigSpec>,
) -> Vec<PoolAction> {
    let spec = &profile.spec;
    let mut actions = Vec::new();
    // Names already scheduled for Delete this reconcile, used to
    // suppress double-emits across the drift / stuck-Creating /
    // unhealthy paths.
    let mut deleting: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Profile name for P0 stuck-Creating observability labels (bounded:
    // one series per pool). Computed once so each emission site reuses it.
    let metric_profile = profile.metadata.name.clone().unwrap_or_default();

    // === 1. Unhealthy: always Delete (unbounded). ===
    for (name, entry) in &state.clusters {
        if entry.state == ClusterState::Unhealthy {
            actions.push(PoolAction::Delete(name.clone()));
            deleting.insert(name.clone());
        }
    }

    // Determine the warm-target ceiling now so the policy resolver and
    // the rest of the function share the same `min_ready`.
    let (min_ready, max_clusters, _scale_up_threshold, scale_down_after) =
        if let Some(scaling) = &spec.scaling {
            (
                scaling.min_ready,
                scaling.max_clusters,
                scaling.scale_up_threshold,
                parse_duration(&scaling.scale_down_after),
            )
        } else {
            // Fixed pool: size is both min and max ready.
            (spec.size, spec.size + 10, 0, None) // no scale-down for fixed pools
        };

    let current_hash = profile_spec_hash(profile, render_ctx, bootstrap_specs);
    let counts = count_states(state, Some(&current_hash));
    let total =
        counts.creating + counts.ready + counts.leased + counts.unhealthy + counts.recycling;
    let policy = resolved_upgrade_policy(profile, min_ready);

    // === 2. Backoff early-return for drift recycle and scale-up. ===
    //
    // If the pool's create-attempts are in their backoff window, the
    // replacement we'd Create after a drift Delete won't actually
    // be Created (the scale-up gate also reads `backoff_active`).
    // Recycling without create capacity would just bleed `ready_clean`
    // — break out and wait for the window to elapse.
    //
    // Unhealthy Deletes (step 1) and stuck-Creating Deletes (step 5)
    // still happen — they don't consume create budget and shouldn't
    // be held hostage by a transient backoff.
    if backoff_active(profile, now) {
        // Stuck-Creating timeout still applies during backoff —
        // a Creating that's been Creating past the pool's
        // creating_timeout (default 10m) is wedged independently
        // of any provision-failure counter.
        let creating_timeout = resolve_creating_timeout(profile);
        for (name, entry) in &state.clusters {
            // #189: a scheduling-blocked Creating is backpressure, not a
            // wedge to recycle — Deleting it just respawns Unschedulable
            // Pods. Hold it (the profile controller has already extended
            // next_attempt_at, which is exactly the backoff window we're in).
            if entry.scheduling_blocked {
                continue;
            }
            if entry.state == ClusterState::Creating
                && !deleting.contains(name)
                && let Some(since) = entry.state_since
                && now - since > creating_timeout
            {
                emit_stuck_creating(&metric_profile, stuck_creating_reason(entry));
                actions.push(PoolAction::Delete(name.clone()));
                deleting.insert(name.clone());
            }
        }
        return actions;
    }

    // === 3. Drifted Creating → Delete immediately (unbounded). ===
    //
    // No surge cost: a Creating instance is not part of `ready_clean`,
    // so deleting it never violates the floor. Only a *stamped*, drifted
    // Creating recycles here; an UNSTAMPED Creating is the brief
    // create→patch_status round-trip window (the hash hasn't round-tripped
    // into our local `PoolState` yet) and is governed by the stuck-Creating
    // timeout (step 5), not the unstamped-legacy rule — which applies to
    // Ready clusters only.
    for (name, entry) in &state.clusters {
        if entry.state == ClusterState::Creating
            && !deleting.contains(name)
            && let Some(stamped) = &entry.spec_hash
            && stamped != &current_hash
        {
            tracing::info!(
                cluster = %name,
                "Drifted Creating: recycling without waiting for timeout"
            );
            emit_stuck_creating(&metric_profile, crate::metrics::StuckCreatingReason::Drift);
            actions.push(PoolAction::Delete(name.clone()));
            deleting.insert(name.clone());
        }
    }

    // === 4. Drifted Ready: rolling recycle, capped + floor-protected. ===
    //
    // Sort by `state_since` ascending so the longest-Ready stale
    // instance recycles first. The fallback by name keeps ordering
    // deterministic across reconciles when timestamps are missing
    // or equal — important because tests depend on it and the
    // controller calls this function multiple times per upgrade.
    let mut drifted_ready: Vec<(&String, &ClusterEntry)> = state
        .clusters
        .iter()
        .filter(|(name, e)| {
            e.state == ClusterState::Ready
                && !deleting.contains(*name)
                && entry_drift_eligible(e.spec_hash.as_ref(), e.state_since, &current_hash, now)
        })
        .collect();
    drifted_ready.sort_by(|a, b| {
        a.1.state_since
            .cmp(&b.1.state_since)
            .then_with(|| a.0.cmp(b.0))
    });

    // The floor protects total Ready capacity (clean + drifted),
    // matching k8s Deployment's `maxUnavailable` convention. A
    // drifted Ready still serves claims — what the user is paying
    // attention to is "how many clusters are available right now,"
    // not "how many are on the latest version." Counting against
    // `ready_clean` would deadlock size-2 pools where `max_surge=1`
    // can only land 1 clean replacement before the next reconcile,
    // making the floor unreachable.
    //
    // Invariant: after this Delete lands, total Ready is still
    // `>= policy.min_ready_during_upgrade`. The surge in step 6
    // restores capacity on subsequent reconciles when this loop
    // breaks early.
    //
    // `.take(max_recycling)` caps the per-reconcile rate; the floor
    // check inside the loop handles the early-break case.
    let mut remaining_ready = counts.ready;
    for (name, _entry) in drifted_ready.iter().take(policy.max_recycling as usize) {
        if remaining_ready <= policy.min_ready_during_upgrade {
            // Floor would be violated. Wait for the surge create
            // (step 6) to land on a future reconcile and bump
            // total Ready before recycling another one.
            tracing::debug!(
                cluster = %name,
                ready = remaining_ready,
                floor = policy.min_ready_during_upgrade,
                "Holding drift recycle: floor would be violated"
            );
            break;
        }
        tracing::info!(
            cluster = %name,
            "Drifted Ready: rolling recycle"
        );
        actions.push(PoolAction::Delete((*name).clone()));
        deleting.insert((*name).clone());
        remaining_ready -= 1;
    }

    // === 5. Stuck Creating timeout. ===
    let creating_timeout = resolve_creating_timeout(profile);
    for (name, entry) in &state.clusters {
        // #189: scheduling-blocked Creating instances are held (backpressure),
        // never recycled by the timeout — see step 2 for the rationale. The
        // backoff (next_attempt_at) drives the eventual retry once the host
        // cluster has capacity again.
        if entry.scheduling_blocked {
            continue;
        }
        if entry.state == ClusterState::Creating
            && !deleting.contains(name)
            && let Some(since) = entry.state_since
            && now - since > creating_timeout
        {
            emit_stuck_creating(&metric_profile, stuck_creating_reason(entry));
            actions.push(PoolAction::Delete(name.clone()));
            deleting.insert(name.clone());
        }
    }

    // === 6. Scale-up: warm target + surge if drift remains. ===
    //
    // Surge only fires when there's drift to absorb. A fresh pool
    // boot (no drift) refills exactly to `min_ready`, never above —
    // so existing tests for clean pools see byte-identical behavior.
    let drift_in_flight = counts.ready_drifted; // not creating_drifted —
    // those got Deleted in step 3 so they're already accounted for in
    // the deficit calculation.
    let warm_target = if drift_in_flight > 0 {
        min_ready + policy.max_surge.min(drift_in_flight)
    } else {
        min_ready
    };

    if counts.ready + counts.creating < warm_target && total < max_clusters {
        let deficit = warm_target.saturating_sub(counts.ready + counts.creating);
        let room = max_clusters.saturating_sub(total);
        let to_create = deficit.min(room).min(MAX_BURST);

        let profile_name = profile.metadata.name.clone().unwrap_or_default();
        let max_index = max_existing_index(state, &profile_name);

        for i in 0..to_create {
            let name = generate_cluster_name(&profile_name, max_index + 1 + i);
            actions.push(PoolAction::Create(name));
        }
    }

    // === 7. Scale-down: skip while upgrading. ===
    //
    // `drift_in_flight > 0` (Ready drift) OR `creating_drifted > 0`
    // (which we already Deleted but might re-appear if the controller
    // hasn't applied yet) means the pool is mid-upgrade. Reaping a
    // fresh replacement as "excess idle" would undo the surge.
    let upgrade_in_progress = drift_in_flight > 0 || counts.creating_drifted > 0;
    if !upgrade_in_progress && let Some(idle_max) = scale_down_after {
        let mut idle_candidates: Vec<(&String, &ClusterEntry)> = state
            .clusters
            .iter()
            .filter(|(name, e)| e.state == ClusterState::Ready && !deleting.contains(*name))
            .collect();
        idle_candidates.sort_by_key(|(_, e)| e.idle_since);

        let excess = counts.ready.saturating_sub(min_ready);
        let mut deleted_excess = 0u32;
        for (name, entry) in idle_candidates {
            if deleted_excess >= excess {
                break;
            }
            if let Some(idle_since) = entry.idle_since
                && now - idle_since > idle_max
            {
                actions.push(PoolAction::Delete(name.clone()));
                deleted_excess += 1;
            }
        }
    }

    actions
}

/// Emit `kobe_instance_stuck_creating_total{profile, reason}` when a Creating
/// instance is recycled for being wedged (timeout elapsed or drift mid-create).
/// `compute_pool_actions` is pure aside from this counter bump; the recycle
/// decision itself is unchanged.
fn emit_stuck_creating(profile: &str, reason: crate::metrics::StuckCreatingReason) {
    crate::metrics::INSTANCE_STUCK_CREATING_TOTAL
        .with_label_values(&[profile, reason.as_str()])
        .inc();
}

/// Pick the [`crate::metrics::StuckCreatingReason`] for a timed-out Creating
/// recycle. A crashlooping entry (flagged via its `status.message` marker, see
/// [`CRASHLOOP_MESSAGE_MARKER`]) is labelled `CrashLooping`; otherwise it's a
/// plain `Timeout`. This is label-only — the recycle decision (the `Delete`)
/// is identical in both cases (#197).
fn stuck_creating_reason(entry: &ClusterEntry) -> crate::metrics::StuckCreatingReason {
    if entry.crashlooping {
        crate::metrics::StuckCreatingReason::CrashLooping
    } else {
        crate::metrics::StuckCreatingReason::Timeout
    }
}

/// Maximum clusters to create in a single reconciliation pass.
const MAX_BURST: u32 = 2;

// --- Failure backoff ---
//
// When a pool's provision attempts consistently fail to reach `Ready`, the
// pool manager should stop hammering the API with new `Create` actions and
// let the backoff window elapse. Defaults tuned so a chronically broken
// pool still retries roughly every 2 min at steady state — fast enough to
// recover promptly once the operator fixes the config, slow enough to
// avoid a create/recycle loop.

/// Default base delay between provision attempts after the first failure.
pub const DEFAULT_BACKOFF_BASE: chrono::Duration = chrono::Duration::seconds(5);
/// Default exponential multiplier.
pub const DEFAULT_BACKOFF_MULTIPLIER: u32 = 2;
/// Default upper bound for the backoff delay.
pub const DEFAULT_BACKOFF_MAX: chrono::Duration = chrono::Duration::seconds(120);

/// Resolve the effective backoff config for a pool, falling back to defaults
/// for any field the spec did not set.
pub fn resolved_backoff(profile: &ClusterPool) -> (chrono::Duration, u32, chrono::Duration) {
    let cfg = profile
        .spec
        .scaling
        .as_ref()
        .and_then(|s| s.failure_backoff.as_ref());

    let base = cfg
        .and_then(|c| parse_duration(&c.base))
        .unwrap_or(DEFAULT_BACKOFF_BASE);
    let multiplier = cfg
        .map(|c| c.multiplier)
        .filter(|m| *m >= 1)
        .unwrap_or(DEFAULT_BACKOFF_MULTIPLIER);
    let max = cfg
        .and_then(|c| parse_duration(&c.max))
        .unwrap_or(DEFAULT_BACKOFF_MAX);
    (base, multiplier, max)
}

/// Compute the backoff delay for a pool with N consecutive failures using
/// the profile's resolved config.
///
/// Default schedule (base=5s, multiplier=2, max=120s):
///   n=1 →  5s,  n=2 → 10s,  n=3 → 20s,  n=4 → 40s,
///   n=5 → 80s,  n=6+ → 120s (capped).
///
/// Returns `None` when `consecutive_failures == 0` (no backoff applies).
pub fn backoff_delay_for(
    profile: &ClusterPool,
    consecutive_failures: u32,
) -> Option<chrono::Duration> {
    if consecutive_failures == 0 {
        return None;
    }
    let (base, multiplier, max) = resolved_backoff(profile);
    // 2^(n-1), saturating against u32 overflow at n >= 32.
    let shift = consecutive_failures.saturating_sub(1).min(31);
    let factor = (multiplier as u64).saturating_pow(shift);
    let secs = base
        .num_seconds()
        .saturating_mul(factor as i64)
        .min(max.num_seconds());
    Some(chrono::Duration::seconds(secs))
}

/// Back-compat thin wrapper used by tests that do not need per-pool config.
#[cfg(test)]
pub fn backoff_delay(consecutive_failures: u32) -> Option<chrono::Duration> {
    // Evaluates defaults by constructing a fresh profile.
    let profile = ClusterPool {
        metadata: Default::default(),
        spec: crate::crd::ClusterPoolSpec {
            size: 0,
            ttl: String::new(),
            backend: Default::default(),
            cluster: crate::crd::ClusterConfig {
                version: String::new(),
                servers: 1,
                agents: None,
                server_args: vec![],
                persistence: None,
                expose: None,
                taints: None,
                ..Default::default()
            },
            addons: vec![],
            bootstraps: vec![],
            resources: None,
            health_check: None,
            readiness_gates: vec![],
            scaling: None,
            upgrade_policy: None,
            diagnostics: None,
            snapshot: None,
        },
        status: None,
    };
    backoff_delay_for(&profile, consecutive_failures)
}

/// True if the pool's `status.nextAttemptAt` is in the future and scale-up
/// should be suppressed until then.
fn backoff_active(profile: &ClusterPool, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(status) = profile.status.as_ref() else {
        return false;
    };
    let Some(next) = status.next_attempt_at.as_deref() else {
        return false;
    };
    match chrono::DateTime::parse_from_rfc3339(next) {
        Ok(next_at) => now < next_at.with_timezone(&chrono::Utc),
        // Fail CLOSED (#166): a malformed `nextAttemptAt` must not silently
        // disable backoff. Failing open let a pool whose status got corrupted
        // keep creating at full speed (and compounds with any concurrency-cap
        // race). Treat an unparseable timestamp as "backoff active" — suppress
        // scale-up until the reconciler rewrites a valid value next cycle.
        Err(e) => {
            tracing::warn!(
                pool = profile.metadata.name.as_deref().unwrap_or("<unknown>"),
                next_attempt_at = next,
                error = %e,
                "malformed status.nextAttemptAt; failing closed (suppressing scale-up) until rewritten"
            );
            true
        }
    }
}

/// Threshold of consecutive failures beyond which a pool is considered
/// `Failing` (sustained, operator attention needed) rather than merely
/// `Backoff` (transient rate-limit).
pub const FAILING_THRESHOLD: u32 = 3;

/// Compute the high-level `ClusterPoolPhase` for the pool given its current
/// counts, backoff state, and config.
///
/// Ordering of checks matters: `Failing` takes precedence over `Backoff`,
/// since a sustained failure is the stronger signal even when a backoff
/// window is active.
pub fn compute_pool_phase(
    profile: &ClusterPool,
    counts: &StateCounts,
    consecutive_failures: u32,
    next_attempt_at: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::crd::ClusterPoolPhase {
    use crate::crd::ClusterPoolPhase;

    let min_ready = profile
        .spec
        .scaling
        .as_ref()
        .map(|s| s.min_ready)
        .unwrap_or(profile.spec.size);

    // Sustained failure beats transient backoff beats everything else.
    if consecutive_failures >= FAILING_THRESHOLD {
        return ClusterPoolPhase::Failing;
    }

    // Active backoff window: waiting for retry.
    if consecutive_failures > 0
        && let Some(ts) = next_attempt_at
        && let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts)
        && now < t.with_timezone(&chrono::Utc)
    {
        return ClusterPoolPhase::Backoff;
    }

    // Fully empty with scale-to-zero intent → Idle.
    if counts.ready == 0
        && counts.leased == 0
        && counts.creating == 0
        && counts.recycling == 0
        && counts.unhealthy == 0
        && min_ready == 0
    {
        return ClusterPoolPhase::Idle;
    }

    // Cooling: above target AND actively shrinking. Catches idle-reap
    // from `scaleDownAfter`. Leases recycling while at-or-below target
    // stays Healthy / Warming.
    if counts.ready > min_ready && counts.recycling > 0 {
        return ClusterPoolPhase::ScalingDown;
    }

    // At or above target and serving / holding steady.
    if counts.ready >= min_ready.max(1) || counts.leased > 0 {
        return ClusterPoolPhase::Healthy;
    }

    // Below target, creating now or about to, no failures.
    ClusterPoolPhase::ScalingUp
}

/// Find the highest existing cluster index for a profile.
///
/// Parses names like `pool-{profile}-{index}` and returns the max index,
/// or 0 if no clusters exist. This prevents name collisions when there
/// are gaps in the index sequence (e.g., 0, 2 → next should be 3, not 2).
fn max_existing_index(state: &PoolState, profile_name: &str) -> u32 {
    let prefix = format!("pool-{profile_name}-");
    state
        .clusters
        .keys()
        .filter_map(|name| {
            name.strip_prefix(&prefix)
                .and_then(|suffix| suffix.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0)
}

/// Tally of cluster states for a pool, with optional drift partitioning.
///
/// The base counters (`creating`, `ready`, `leased`, `unhealthy`,
/// `recycling`) always sum to the pool size. The hash-aware buckets
/// (`ready_clean` / `ready_drifted`, `creating_clean` / `creating_drifted`,
/// `leased_drifted`) are populated only when [`count_states`] is called
/// with a `current_hash` argument; otherwise they remain 0 and callers
/// that don't reason about drift can ignore them.
///
/// **Invariants** (when `current_hash` was provided):
/// - `ready_clean + ready_drifted == ready`
/// - `creating_clean + creating_drifted == creating`
/// - `leased_drifted <= leased` (the unidrifted Leased count isn't
///   tracked because the rolling-upgrade algorithm never acts on it —
///   Leased instances are only recycled post-release).
///
/// An entry whose `spec_hash` is `None` (initial-status patch race) is
/// counted as **clean**, not drifted: pretending an unstamped instance
/// is drift-eligible would loop the recycler against the still-running
/// patch in `ensure_cluster_instance`.
#[derive(Debug, Default)]
pub struct StateCounts {
    pub creating: u32,
    pub ready: u32,
    pub leased: u32,
    pub unhealthy: u32,
    pub recycling: u32,
    /// Ready instances whose `spec_hash` matches `current_hash`. Zero
    /// when `count_states` was called without a `current_hash`.
    pub ready_clean: u32,
    /// Ready instances whose `spec_hash` is set and differs from
    /// `current_hash`. Zero when `count_states` was called without a
    /// `current_hash`. Entries with `spec_hash == None` count as clean.
    pub ready_drifted: u32,
    /// Creating instances whose `spec_hash` matches `current_hash`.
    pub creating_clean: u32,
    /// Creating instances whose `spec_hash` is set and differs from
    /// `current_hash`. Used by the rolling-upgrade algorithm to recycle
    /// drifted Creating instances immediately (they contribute zero
    /// capacity, so deleting them doesn't violate any floor).
    pub creating_drifted: u32,
    /// Leased instances whose `spec_hash` is set and differs from
    /// `current_hash`. Informational — never acted upon directly,
    /// since Leased instances are only recycled after release.
    pub leased_drifted: u32,
}

/// Tally a pool's cluster states.
///
/// When `current_hash` is `Some(h)`, also partitions Ready / Creating /
/// Leased into drift-aware buckets (see [`StateCounts`] for the
/// invariants). When `None`, the drift fields remain 0 and the
/// behavior is identical to a pre-rolling-upgrade caller — useful for
/// call sites (like `compute_pool_phase`) that only need the base
/// state taxonomy.
pub fn count_states(state: &PoolState, current_hash: Option<&SpecHash>) -> StateCounts {
    let mut c = StateCounts::default();
    for entry in state.clusters.values() {
        match entry.state {
            ClusterState::Creating => c.creating += 1,
            ClusterState::Ready => c.ready += 1,
            ClusterState::Leased => c.leased += 1,
            ClusterState::Unhealthy => c.unhealthy += 1,
            ClusterState::Recycling => c.recycling += 1,
        }
        // Only an entry with both a `current_hash` to compare against
        // AND its own stamped hash can drift. Unstamped entries
        // (`spec_hash == None`) count as clean — see type-level doc.
        if let (Some(curr), Some(entry_hash)) = (current_hash, &entry.spec_hash) {
            let drifted = entry_hash != curr;
            match (&entry.state, drifted) {
                (ClusterState::Ready, true) => c.ready_drifted += 1,
                (ClusterState::Ready, false) => c.ready_clean += 1,
                (ClusterState::Creating, true) => c.creating_drifted += 1,
                (ClusterState::Creating, false) => c.creating_clean += 1,
                (ClusterState::Leased, true) => c.leased_drifted += 1,
                _ => {}
            }
        } else if current_hash.is_some() {
            // current_hash provided but entry unstamped → clean bucket.
            // Keeps `ready_clean + ready_drifted == ready` invariant.
            match entry.state {
                ClusterState::Ready => c.ready_clean += 1,
                ClusterState::Creating => c.creating_clean += 1,
                _ => {}
            }
        }
    }
    c
}

/// Validate that a name is a valid Kubernetes DNS label (RFC 1123).
///
/// Must match: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` (2-63 chars)
/// or a single alphanumeric char. This prevents names like `--set`
/// from being misinterpreted as CLI flags by helm/kubectl.
pub fn is_valid_k8s_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Generate a deterministic cluster name for a profile.
///
/// Logs a warning if the profile name produces an invalid K8s name.
/// This indicates a bug in profile validation upstream.
pub fn generate_cluster_name(profile_name: &str, index: u32) -> String {
    let name = format!("pool-{profile_name}-{index}");
    if !is_valid_k8s_name(&name) {
        tracing::warn!(name = %name, "Generated cluster name failed K8s DNS label validation");
    }
    name
}

/// Parse a duration string like "30m", "1h", "2h30m" into a chrono::Duration.
///
/// Returns None for empty strings, invalid formats, and values exceeding 1 year.
pub fn parse_duration(s: &str) -> Option<chrono::Duration> {
    const MAX_SECONDS: i64 = 365 * 24 * 3600; // 1 year

    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let mut total_seconds: i64 = 0;
    let mut current_num = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let n: i64 = current_num.parse().ok()?;
            current_num.clear();
            let secs = match ch {
                'h' => n.checked_mul(3600)?,
                'm' => n.checked_mul(60)?,
                's' => n,
                _ => return None,
            };
            total_seconds = total_seconds.checked_add(secs)?;
            if total_seconds > MAX_SECONDS {
                return None;
            }
        }
    }

    // Reject trailing digits without a unit (e.g. "1h30" should fail, use "1h30m")
    if !current_num.is_empty() {
        return None;
    }

    if total_seconds > 0 {
        chrono::Duration::try_seconds(total_seconds)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default `RenderContext` for autoscaling tests that don't care
    /// about the kobe-sync sidecar image (i.e. anything not asserting
    /// vkobe-specific drift behaviour). Keeping the value stable
    /// across tests keeps unrelated hashes pinned in test fixtures.
    fn test_render_ctx() -> RenderContext {
        RenderContext::with_kobe_sync_image("zondax/kobe-sync:test")
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30m"), Some(chrono::Duration::seconds(1800)));
        assert_eq!(parse_duration("1h"), Some(chrono::Duration::seconds(3600)));
        assert_eq!(
            parse_duration("2h30m"),
            Some(chrono::Duration::seconds(9000))
        );
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn test_parse_duration_rejects_overflow() {
        // Values exceeding 1 year are rejected
        assert_eq!(parse_duration("9000h"), None);
        assert_eq!(parse_duration("600000m"), None);
        // Just under the limit is fine (8760h = 1 year)
        assert!(parse_duration("8760h").is_some());
        // Invalid unit characters
        assert_eq!(parse_duration("5d"), None);
    }

    #[test]
    fn test_parse_duration_rejects_trailing_digits() {
        // "1h30" should fail — ambiguous, use "1h30m"
        assert_eq!(parse_duration("1h30"), None);
        // Bare number with no unit
        assert_eq!(parse_duration("10"), None);
        // Mixed valid then trailing
        assert_eq!(parse_duration("1m5"), None);
    }

    #[test]
    fn test_max_existing_index() {
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Ready));
        clusters.insert("pool-test-5".into(), make_entry(ClusterState::Leased));
        clusters.insert("pool-test-2".into(), make_entry(ClusterState::Creating));
        let state = PoolState { clusters };

        assert_eq!(max_existing_index(&state, "test"), 5);
    }

    #[test]
    fn test_max_existing_index_empty() {
        let state = PoolState {
            clusters: HashMap::new(),
        };
        assert_eq!(max_existing_index(&state, "test"), 0);
    }

    #[test]
    fn test_count_states() {
        let mut clusters = HashMap::new();
        clusters.insert(
            "a".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "b".into(),
            ClusterEntry {
                state: ClusterState::Leased,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "c".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );

        let state = PoolState { clusters };
        let counts = count_states(&state, None);

        assert_eq!(counts.ready, 1);
        assert_eq!(counts.leased, 1);
        assert_eq!(counts.creating, 1);
        // Without a current_hash, drift buckets stay at 0.
        assert_eq!(counts.ready_clean, 0);
        assert_eq!(counts.ready_drifted, 0);
    }

    /// `count_states` with a `current_hash` partitions Ready/Creating
    /// into clean vs drifted, preserving `clean + drifted == total`.
    /// Entries without a stamped `spec_hash` count as clean to avoid
    /// looping the recycler against the initial-status patch race.
    #[test]
    fn count_states_partitions_ready_into_clean_and_drifted_by_hash() {
        let current = "cccc111122223333".to_string();
        let mut clusters = HashMap::new();
        clusters.insert(
            "ready-clean".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: Some(current.clone()),
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "ready-drifted".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: Some("ddddffffffffffff".to_string()),
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "ready-unstamped".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "creating-drifted".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: Some("ddddffffffffffff".to_string()),
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let counts = count_states(&state, Some(&current));

        assert_eq!(counts.ready, 3);
        assert_eq!(counts.ready_clean, 2, "stamped-clean + unstamped");
        assert_eq!(counts.ready_drifted, 1);
        assert_eq!(
            counts.ready_clean + counts.ready_drifted,
            counts.ready,
            "clean + drifted must sum to ready"
        );
        assert_eq!(counts.creating, 1);
        assert_eq!(counts.creating_drifted, 1);
        assert_eq!(counts.creating_clean, 0);
    }

    // --- K8s name validation ---

    #[test]
    fn test_valid_k8s_names() {
        assert!(is_valid_k8s_name("a"));
        assert!(is_valid_k8s_name("abc"));
        assert!(is_valid_k8s_name("my-app"));
        assert!(is_valid_k8s_name("pool-e2e-basic-0"));
        assert!(is_valid_k8s_name("a1b2c3"));
        assert!(is_valid_k8s_name("0abc"));
    }

    #[test]
    fn test_invalid_k8s_names() {
        assert!(!is_valid_k8s_name("")); // empty
        assert!(!is_valid_k8s_name("-abc")); // starts with hyphen
        assert!(!is_valid_k8s_name("abc-")); // ends with hyphen
        assert!(!is_valid_k8s_name("--set")); // CLI flag injection
        assert!(!is_valid_k8s_name("ABC")); // uppercase
        assert!(!is_valid_k8s_name("my_app")); // underscore
        assert!(!is_valid_k8s_name("my.app")); // dot
        assert!(!is_valid_k8s_name(&"a".repeat(64))); // too long (>63)
    }

    #[test]
    fn test_k8s_name_boundary_lengths() {
        // Exactly 63 chars — maximum valid length
        assert!(is_valid_k8s_name(&"a".repeat(63)));
        // Single char — valid
        assert!(is_valid_k8s_name("x"));
    }

    // --- Name generation ---

    #[test]
    fn test_generate_cluster_name() {
        assert_eq!(generate_cluster_name("e2e-basic", 0), "pool-e2e-basic-0");
        assert_eq!(generate_cluster_name("e2e-basic", 5), "pool-e2e-basic-5");
        assert_eq!(generate_cluster_name("dev", 10), "pool-dev-10");
    }

    #[test]
    fn test_generate_cluster_name_is_valid_k8s() {
        let name = generate_cluster_name("e2e-basic", 42);
        assert!(is_valid_k8s_name(&name));
    }

    // --- Autoscaling: compute_pool_actions ---

    fn make_profile(
        size: u32,
        scaling: Option<crate::crd::ScalingConfig>,
    ) -> crate::crd::ClusterPool {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        crate::crd::ClusterPool {
            metadata: ObjectMeta {
                name: Some("test-profile".to_string()),
                ..Default::default()
            },
            spec: crate::crd::ClusterPoolSpec {
                size,
                ttl: "1h".to_string(),
                backend: Default::default(),
                cluster: crate::crd::ClusterConfig {
                    version: "v1.31.3+k3s1".to_string(),
                    servers: 1,
                    agents: None,
                    server_args: vec![],
                    persistence: None,
                    expose: None,
                    taints: None,
                    ..Default::default()
                },
                addons: vec![],
                bootstraps: vec![],
                resources: None,
                health_check: None,
                readiness_gates: vec![],
                scaling,
                upgrade_policy: None,
                diagnostics: None,
                snapshot: None,
            },
            status: None,
        }
    }

    fn make_entry(state: ClusterState) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: None,
            health_failures: 0,
            state_since: None,
            spec_hash: None,
            scheduling_blocked: false,
            crashlooping: false,
            crash_message: None,
        }
    }

    #[test]
    fn test_scale_up_when_pool_empty() {
        let profile = make_profile(
            3,
            Some(crate::crd::ScalingConfig {
                min_ready: 3,
                max_clusters: 10,
                scale_up_threshold: 1,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        // Should create up to MAX_BURST (2) clusters
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().all(|a| matches!(a, PoolAction::Create(_))));

        // Names should start from index 1 (max_existing=0, so 0+1=1)
        if let PoolAction::Create(ref name) = actions[0] {
            assert!(name.starts_with("pool-test-profile-"));
        }
    }

    #[test]
    fn test_no_scale_up_when_enough_ready() {
        let profile = make_profile(
            2,
            Some(crate::crd::ScalingConfig {
                min_ready: 2,
                max_clusters: 10,
                scale_up_threshold: 1,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Ready));
        clusters.insert("pool-test-1".into(), make_entry(ClusterState::Ready));
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        assert!(actions.is_empty());
    }

    #[test]
    fn test_scale_up_when_warm_pool_drops_below_min_ready() {
        let profile = make_profile(
            2,
            Some(crate::crd::ScalingConfig {
                min_ready: 2,
                max_clusters: 8,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Ready));
        clusters.insert("pool-test-1".into(), make_entry(ClusterState::Leased));
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(creates.len(), 1);
    }

    #[test]
    fn test_no_scale_up_when_at_max() {
        let profile = make_profile(
            3,
            Some(crate::crd::ScalingConfig {
                min_ready: 3,
                max_clusters: 2,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Leased));
        clusters.insert("pool-test-1".into(), make_entry(ClusterState::Leased));
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        // At max_clusters=2 with 2 leased, no room to create
        assert!(actions.is_empty());
    }

    #[test]
    fn test_scale_down_idle_clusters() {
        let profile = make_profile(
            1,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();
        let long_ago = now - chrono::Duration::hours(1);
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-0".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(long_ago),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(long_ago),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        // 2 ready, min_ready=1, one idle >30m → delete 1
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn test_no_scale_down_when_recently_idle() {
        let profile = make_profile(
            1,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();
        let just_now = now - chrono::Duration::minutes(5);
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-0".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(just_now),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(just_now),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        // Both idle only 5m, threshold is 30m — no deletes
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 0);
    }

    #[test]
    fn test_spec_drift_triggers_recreation_of_unclaimed_clusters() {
        // Drift detection still triggers Delete for unclaimed (Ready)
        // members and leaves Leased alone — that invariant predates
        // the rolling-upgrade policy. With the new policy in place,
        // we explicitly set `min_ready_during_upgrade = 0` so this
        // test keeps pinning the basic drift signal without being
        // bottlenecked by the default floor (= size = 2). The
        // floor's behavior is pinned by separate rolling-upgrade
        // tests (see `rolling_drift_holds_recycle_when_floor_would_be_violated`).
        let mut profile = make_profile(2, None);
        profile.spec.upgrade_policy = Some(crate::crd::UpgradePolicy {
            max_recycling: 1,
            max_surge: 1,
            min_ready_during_upgrade: Some(0),
        });
        let stale_hash = format!(
            "{}-stale",
            profile_spec_hash(&profile, &test_render_ctx(), &Default::default())
        );

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(chrono::Utc::now()),
                health_failures: 0,
                state_since: None,
                spec_hash: Some(stale_hash.clone()), // stale
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            ClusterEntry {
                state: ClusterState::Leased,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: Some(stale_hash.clone()), // stale but leased
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        // Only the Ready (unclaimed) cluster should be deleted.
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 1);
        if let PoolAction::Delete(name) = &deletes[0] {
            assert_eq!(name, "pool-test-profile-1");
        }
    }

    /// Regression for the prod incident where a kobe-sync sidecar
    /// image bump in the operator Deployment landed but vkobe pool
    /// members never recycled — they kept running the OLD sidecar
    /// binary indefinitely because the user-visible pool spec hadn't
    /// changed. Bumping `RenderContext.kobe_sync_image` MUST flip the
    /// hash for vkobe pools so existing idle members get recycled.
    #[test]
    fn vkobe_pool_recycles_when_kobe_sync_image_changes() {
        let mut profile = make_profile(2, None);
        // Force backend to vkobe so the sidecar image affects rendering.
        profile.spec.backend.backend_type = crate::crd::BackendType::Vkobe;

        let old_ctx = RenderContext::with_kobe_sync_image("zondax/kobe-sync:v0.9.0");
        let new_ctx = RenderContext::with_kobe_sync_image("zondax/kobe-sync:v0.12.3");
        let bs = std::collections::BTreeMap::new();

        let old_hash = profile_spec_hash(&profile, &old_ctx, &bs);
        let new_hash = profile_spec_hash(&profile, &new_ctx, &bs);
        assert_ne!(
            old_hash, new_hash,
            "vkobe pool must recompute its spec hash when KOBE_SYNC_IMAGE changes"
        );
    }

    /// Same scenario, but for a k3s pool — a kobe-sync image bump
    /// MUST NOT churn k3s pool members because the sidecar isn't part
    /// of their rendered resources. Otherwise every operator upgrade
    /// would needlessly recycle every pool member of every backend.
    #[test]
    fn k3s_pool_not_recycled_by_kobe_sync_image_change() {
        let profile = make_profile(2, None); // default backend is k3s
        assert_eq!(
            profile.spec.backend.backend_type,
            crate::crd::BackendType::K3s
        );
        let old_ctx = RenderContext::with_kobe_sync_image("zondax/kobe-sync:v0.9.0");
        let new_ctx = RenderContext::with_kobe_sync_image("zondax/kobe-sync:v0.12.3");
        let bs = std::collections::BTreeMap::new();

        assert_eq!(
            profile_spec_hash(&profile, &old_ctx, &bs),
            profile_spec_hash(&profile, &new_ctx, &bs),
            "k3s pool spec hash must NOT depend on the kobe-sync sidecar image"
        );
    }

    /// Editing the CONTENT of a referenced BootstrapConfig (not just
    /// its name) must flip the hash so existing pool members pick up
    /// the new manifests on the next reconcile. Without this, a user
    /// updating the flux install would silently apply only to NEW
    /// members and leave existing idle ones running the old logic.
    /// Editing the CONTENT of a referenced BootstrapConfig (not just
    /// its name) must flip the hash so existing pool members pick up
    /// the new manifests on the next reconcile. Without this, a user
    /// updating the flux install would silently apply only to NEW
    /// members and leave existing idle ones running the old logic.
    #[test]
    fn pool_recycles_when_referenced_bootstrap_content_changes() {
        use crate::crd::{BootstrapConfigSpec, BootstrapRef};
        use std::collections::BTreeMap;
        let mut profile = make_profile(2, None);
        profile.spec.bootstraps = vec![BootstrapRef {
            name: "flux".to_string(),
            ..Default::default()
        }];

        let mut bs_v1 = BTreeMap::new();
        bs_v1.insert(
            "flux".to_string(),
            BootstrapConfigSpec {
                files: {
                    let mut f = BTreeMap::new();
                    f.insert(
                        "00-namespace.yaml".to_string(),
                        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system\n"
                            .to_string(),
                    );
                    f
                },
                job: None,
            },
        );

        let mut bs_v2 = BTreeMap::new();
        bs_v2.insert(
            "flux".to_string(),
            BootstrapConfigSpec {
                files: {
                    let mut f = BTreeMap::new();
                    // Same key, edited manifest body — content drift only.
                    f.insert(
                        "00-namespace.yaml".to_string(),
                        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system-v2\n"
                            .to_string(),
                    );
                    f
                },
                job: None,
            },
        );

        let ctx = test_render_ctx();
        let h1 = profile_spec_hash(&profile, &ctx, &bs_v1);
        let h2 = profile_spec_hash(&profile, &ctx, &bs_v2);
        assert_ne!(
            h1, h2,
            "editing a referenced BootstrapConfig's content must flip the pool hash"
        );
    }

    /// A pool with NO bootstraps must not be sensitive to the
    /// bootstrap_specs map at all — passing different maps gives the
    /// same hash because the iteration in `profile_spec_hash` is keyed
    /// off the pool's own reference list.
    #[test]
    fn pool_without_bootstraps_ignores_bootstrap_specs() {
        use crate::crd::BootstrapConfigSpec;
        use std::collections::BTreeMap;
        let profile = make_profile(2, None);
        assert!(profile.spec.bootstraps.is_empty());

        let ctx = test_render_ctx();
        let mut bs_a = BTreeMap::new();
        bs_a.insert(
            "irrelevant".to_string(),
            BootstrapConfigSpec {
                files: BTreeMap::new(),
                job: None,
            },
        );

        assert_eq!(
            profile_spec_hash(&profile, &ctx, &Default::default()),
            profile_spec_hash(&profile, &ctx, &bs_a),
            "pool with no bootstraps must not be affected by unrelated entries in the resolved map"
        );
    }

    #[test]
    fn entry_drift_eligible_recycles_unstamped_ready_after_grace() {
        let now = chrono::Utc::now();
        let current: SpecHash = "current-hash".to_string();

        // Stamped + matching → not eligible.
        assert!(!entry_drift_eligible(
            Some(&current),
            Some(now),
            &current,
            now
        ));
        // Stamped + differing → eligible (normal drift).
        let old: SpecHash = "old-hash".to_string();
        assert!(entry_drift_eligible(Some(&old), Some(now), &current, now));
        // Unstamped + fresh (within grace) → NOT eligible: this is the
        // create→patch_status round-trip window, not a legacy cluster.
        assert!(!entry_drift_eligible(
            None,
            Some(now - chrono::Duration::minutes(1)),
            &current,
            now,
        ));
        // Unstamped + older than the grace → eligible: a pre-provenance legacy
        // cluster that would otherwise survive forever as a drift blind spot.
        assert!(entry_drift_eligible(
            None,
            Some(now - chrono::Duration::minutes(5)),
            &current,
            now,
        ));
        // Unstamped + no timestamp → not eligible (can't establish age).
        assert!(!entry_drift_eligible(None, None, &current, now));
    }

    #[test]
    fn test_no_drift_when_spec_hash_matches() {
        let profile = make_profile(2, None);
        let current_hash = profile_spec_hash(&profile, &test_render_ctx(), &Default::default());

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(chrono::Utc::now()),
                health_failures: 0,
                state_since: None,
                spec_hash: Some(current_hash),
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );

        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 0);
    }

    // --- Failure backoff ---

    #[test]
    fn test_backoff_delay_default_schedule() {
        // defaults: base=5s, x2, cap=2m
        assert_eq!(backoff_delay(0), None);
        assert_eq!(backoff_delay(1), Some(chrono::Duration::seconds(5)));
        assert_eq!(backoff_delay(2), Some(chrono::Duration::seconds(10)));
        assert_eq!(backoff_delay(3), Some(chrono::Duration::seconds(20)));
        assert_eq!(backoff_delay(4), Some(chrono::Duration::seconds(40)));
        assert_eq!(backoff_delay(5), Some(chrono::Duration::seconds(80)));
        // capped at 120s from n=6 onward
        assert_eq!(backoff_delay(6), Some(chrono::Duration::seconds(120)));
        assert_eq!(backoff_delay(10), Some(chrono::Duration::seconds(120)));
        // saturation at large N
        assert_eq!(
            backoff_delay(u32::MAX),
            Some(chrono::Duration::seconds(120))
        );
    }

    #[test]
    fn test_backoff_delay_honors_per_pool_config() {
        let mut p = make_profile(
            0,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 3,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: Some(crate::crd::FailureBackoffConfig {
                    base: "2s".to_string(),
                    multiplier: 3,
                    max: "30s".to_string(),
                }),
            }),
        );
        p.status = None;
        // base=2s, x3, cap=30s → 2s, 6s, 18s, 30s (cap), 30s, ...
        assert_eq!(backoff_delay_for(&p, 1), Some(chrono::Duration::seconds(2)));
        assert_eq!(backoff_delay_for(&p, 2), Some(chrono::Duration::seconds(6)));
        assert_eq!(
            backoff_delay_for(&p, 3),
            Some(chrono::Duration::seconds(18))
        );
        assert_eq!(
            backoff_delay_for(&p, 4),
            Some(chrono::Duration::seconds(30))
        );
        assert_eq!(
            backoff_delay_for(&p, 99),
            Some(chrono::Duration::seconds(30))
        );
    }

    #[test]
    fn test_backoff_delay_falls_back_to_defaults_when_fields_invalid() {
        let mut p = make_profile(
            0,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 3,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: Some(crate::crd::FailureBackoffConfig {
                    base: "not-a-duration".to_string(),
                    multiplier: 0, // invalid — zero disables, fallback
                    max: "garbage".to_string(),
                }),
            }),
        );
        p.status = None;
        // All three fields unparseable/invalid → full defaults (5s, x2, 120s cap)
        assert_eq!(backoff_delay_for(&p, 1), Some(chrono::Duration::seconds(5)));
        assert_eq!(
            backoff_delay_for(&p, 10),
            Some(chrono::Duration::seconds(120))
        );
    }

    fn make_profile_with_backoff(
        min_ready: u32,
        max_clusters: u32,
        consecutive_failures: u32,
        next_attempt_at: Option<String>,
    ) -> crate::crd::ClusterPool {
        let mut p = make_profile(
            0,
            Some(crate::crd::ScalingConfig {
                min_ready,
                max_clusters,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        p.status = Some(crate::crd::ClusterPoolStatus {
            consecutive_failures,
            next_attempt_at,
            ..Default::default()
        });
        p
    }

    #[test]
    fn test_scale_up_blocked_when_backoff_window_is_open() {
        let future = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        let profile = make_profile_with_backoff(1, 3, 2, Some(future));
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(creates.len(), 0, "backoff window should suppress Create");
    }

    #[test]
    fn test_scale_up_resumes_after_backoff_window_elapses() {
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let profile = make_profile_with_backoff(1, 3, 2, Some(past));
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(creates.len(), 1, "elapsed window should permit Create");
    }

    #[test]
    fn test_backoff_fails_closed_on_malformed_next_attempt_at() {
        // #166: a malformed `status.nextAttemptAt` must FAIL CLOSED (suppress
        // scale-up), not fail open. Failing open let a pool whose status got
        // corrupted keep creating at full speed.
        let profile = make_profile_with_backoff(1, 3, 2, Some("not-a-timestamp".to_string()));
        assert!(
            backoff_active(&profile, chrono::Utc::now()),
            "malformed nextAttemptAt must be treated as backoff-active (fail closed)"
        );
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(
            creates.len(),
            0,
            "malformed backoff state must suppress Create (fail closed)"
        );
    }

    #[test]
    fn test_scale_up_proceeds_when_no_backoff_state() {
        let profile = make_profile_with_backoff(1, 3, 0, None);
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(creates.len(), 1);
    }

    // --- Pool phase ---

    fn counts(ready: u32, leased: u32, creating: u32, recycling: u32) -> StateCounts {
        StateCounts {
            ready,
            leased,
            creating,
            recycling,
            unhealthy: 0,
            // `compute_pool_phase` doesn't read drift fields, so leave
            // them at the Default zeros.
            ..StateCounts::default()
        }
    }

    fn profile_with_min_ready(min_ready: u32) -> crate::crd::ClusterPool {
        make_profile(
            0,
            Some(crate::crd::ScalingConfig {
                min_ready,
                max_clusters: 8,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        )
    }

    #[test]
    fn test_phase_healthy_when_at_target() {
        let p = profile_with_min_ready(2);
        let phase = compute_pool_phase(&p, &counts(2, 0, 0, 0), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Healthy);
    }

    #[test]
    fn test_phase_healthy_when_serving_below_target() {
        let p = profile_with_min_ready(2);
        // ready=0 but leased=1 — pool is working even if warm buffer is empty.
        let phase = compute_pool_phase(&p, &counts(0, 1, 0, 0), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Healthy);
    }

    #[test]
    fn test_phase_warming_when_creating() {
        let p = profile_with_min_ready(2);
        let phase = compute_pool_phase(&p, &counts(0, 0, 1, 0), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::ScalingUp);
    }

    #[test]
    fn test_phase_warming_on_first_arrival() {
        let p = profile_with_min_ready(1);
        // Nothing yet, no failures, minReady > 0.
        let phase = compute_pool_phase(&p, &counts(0, 0, 0, 0), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::ScalingUp);
    }

    #[test]
    fn test_phase_idle_when_scale_to_zero_steady() {
        let p = profile_with_min_ready(0);
        let phase = compute_pool_phase(&p, &counts(0, 0, 0, 0), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Idle);
    }

    #[test]
    fn test_phase_cooling_when_above_target_and_recycling() {
        let p = profile_with_min_ready(1);
        // 3 ready, 1 being recycled (scale-down reaping an idle one).
        let phase = compute_pool_phase(&p, &counts(3, 0, 0, 1), 0, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::ScalingDown);
    }

    #[test]
    fn test_phase_backoff_when_in_wait_window() {
        let p = profile_with_min_ready(1);
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(60)).to_rfc3339();
        let phase = compute_pool_phase(&p, &counts(0, 0, 0, 0), 1, Some(&future), now);
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Backoff);
    }

    #[test]
    fn test_phase_failing_after_sustained_failures() {
        let p = profile_with_min_ready(1);
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(60)).to_rfc3339();
        // 3 failures beats backoff window check.
        let phase = compute_pool_phase(&p, &counts(0, 0, 0, 0), 3, Some(&future), now);
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Failing);
    }

    #[test]
    fn test_phase_healthy_beats_stale_failure_counter() {
        // Counter says 5 failures, but there's a ready cluster → healthy wins.
        // (compute_backoff_state should have reset the counter; this test
        // guards the ordering if that logic ever breaks.)
        let p = profile_with_min_ready(1);
        // Note: with current ordering, Failing beats Healthy when counter >= 3.
        // That's intentional — a stale counter is a bug in compute_backoff_state,
        // not something phase computation should paper over. Document the ordering.
        let phase = compute_pool_phase(&p, &counts(1, 0, 0, 0), 5, None, chrono::Utc::now());
        assert_eq!(phase, crate::crd::ClusterPoolPhase::Failing);
    }

    // --- Rolling-upgrade policy: algorithm invariants ---
    //
    // Each test pins one invariant of the rolling-recycle algorithm
    // implemented in `compute_pool_actions`. Test names mirror the
    // invariant per AGENTS.md "Pin invariants with tests; the test
    // name should mirror the invariant."

    /// Helper: build a profile with `size` and an explicit upgrade
    /// policy. The policy is `Some` even when fields are at their
    /// default values so tests don't depend on the inheritance
    /// behavior of `resolved_upgrade_policy` (separately tested).
    fn make_profile_with_upgrade(
        size: u32,
        max_recycling: u32,
        max_surge: u32,
        min_ready_during_upgrade: Option<u32>,
    ) -> crate::crd::ClusterPool {
        let mut p = make_profile(size, None);
        p.spec.upgrade_policy = Some(crate::crd::UpgradePolicy {
            max_recycling,
            max_surge,
            min_ready_during_upgrade,
        });
        p
    }

    /// Helper: stamp an entry with a stale or current hash relative to
    /// `profile`. `state_since` is set so the recycle ordering test
    /// gets a deterministic order.
    fn drifted_entry(state: ClusterState, age_seconds: i64) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: Some(chrono::Utc::now()),
            health_failures: 0,
            state_since: Some(chrono::Utc::now() - chrono::Duration::seconds(age_seconds)),
            spec_hash: Some("ddddffffffffffff".to_string()), // never matches the real current hash
            scheduling_blocked: false,
            crashlooping: false,
            crash_message: None,
        }
    }

    fn clean_entry(state: ClusterState, current_hash: SpecHash) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: Some(chrono::Utc::now()),
            health_failures: 0,
            state_since: Some(chrono::Utc::now()),
            spec_hash: Some(current_hash),
            scheduling_blocked: false,
            crashlooping: false,
            crash_message: None,
        }
    }

    /// Pool with 4 drifted Ready, `max_recycling=1`, floor=2:
    /// exactly 1 Delete per reconcile (the rate cap), with surge to
    /// keep capacity above the floor. Bypasses scale-up's MAX_BURST
    /// in this single-step assertion by checking just the Delete count.
    #[test]
    fn rolling_drift_recycles_one_at_a_time_when_max_recycling_is_one() {
        let profile = make_profile_with_upgrade(4, 1, 1, Some(2));
        let mut clusters = HashMap::new();
        for i in 1..=4 {
            clusters.insert(
                format!("pool-test-profile-{i}"),
                drifted_entry(ClusterState::Ready, i * 100),
            );
        }
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );

        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(
            deletes.len(),
            1,
            "max_recycling=1 caps drift recycle to exactly 1 Delete per reconcile"
        );
    }

    /// Pool of size=2, 1 clean Ready + 1 drifted Ready, floor=2.
    /// Even though `max_recycling=1` would allow a Delete, the floor
    /// check holds it back: post-Delete total Ready would be 1, below
    /// the floor of 2. Surge fires instead.
    #[test]
    fn rolling_drift_holds_recycle_when_floor_would_be_violated() {
        let profile = make_profile_with_upgrade(2, 1, 1, Some(2));
        let current = profile_spec_hash(&profile, &test_render_ctx(), &Default::default());
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            clean_entry(ClusterState::Ready, current),
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            drifted_entry(ClusterState::Ready, 200),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();
        assert_eq!(
            deletes.len(),
            0,
            "floor=2 with ready=2 forbids any Delete on this reconcile"
        );
        assert_eq!(
            creates.len(),
            1,
            "surge fires to grow ready toward warm_target=3 so a future reconcile can recycle"
        );
    }

    /// Size=1 fixed pool, the only Ready is drifted. Two-step
    /// upgrade: T0 surges (Create only, no Delete) so capacity
    /// doesn't dip below 1; T1 (after the surge becomes Ready)
    /// recycles the drifted original.
    #[test]
    fn size_one_pool_with_surge_one_upgrades_with_zero_downtime() {
        let profile = make_profile_with_upgrade(1, 1, 1, None); // floor defaults to size=1
        let current = profile_spec_hash(&profile, &test_render_ctx(), &Default::default());

        // T0: 1 drifted Ready, no clean.
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Ready, 100),
        );
        let actions_t0 = compute_pool_actions(
            &profile,
            &PoolState {
                clusters: clusters.clone(),
            },
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        assert_eq!(
            actions_t0
                .iter()
                .filter(|a| matches!(a, PoolAction::Delete(_)))
                .count(),
            0,
            "T0: no Delete — original drifted Ready is the only available capacity"
        );
        assert_eq!(
            actions_t0
                .iter()
                .filter(|a| matches!(a, PoolAction::Create(_)))
                .count(),
            1,
            "T0: surge Create lands the replacement before recycling the original"
        );

        // T1 simulation: surge produced "pool-test-profile-2" Ready.
        // Original (drifted) is still Ready.
        clusters.insert(
            "pool-test-profile-2".into(),
            clean_entry(ClusterState::Ready, current),
        );
        let actions_t1 = compute_pool_actions(
            &profile,
            &PoolState { clusters },
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes_t1: Vec<_> = actions_t1
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes_t1,
            vec!["pool-test-profile-1"],
            "T1: original drifted Ready is recycled now that ready=2 satisfies floor=1 post-Delete"
        );
        assert_eq!(
            actions_t1
                .iter()
                .filter(|a| matches!(a, PoolAction::Create(_)))
                .count(),
            0,
            "T1: no further Creates — already at warm_target=2"
        );
    }

    /// A drifted Creating instance contributes zero capacity. The
    /// algorithm Deletes it immediately, regardless of the floor or
    /// `max_recycling` budget — letting it finish on the old version
    /// just wastes the create cost.
    #[test]
    fn drifted_creating_instances_are_recycled_immediately_without_surge_cost() {
        let profile = make_profile_with_upgrade(2, 1, 1, Some(2));
        let mut clusters = HashMap::new();
        // No Ready instances — only a drifted Creating.
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Creating, 50),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes,
            vec!["pool-test-profile-1"],
            "drifted Creating Deleted on this reconcile, not after the 10min timeout"
        );
        // It was NOT counted toward `max_recycling=1`, but the budget
        // is still 1 here because there are no drifted Ready candidates.
    }

    /// Unhealthy instances are recycled aggressively without
    /// consuming the `max_recycling` budget — they're broken anyway,
    /// so removing them is pure win and never violates a floor.
    #[test]
    fn unhealthy_instances_recycle_without_consuming_max_recycling_budget() {
        let profile = make_profile_with_upgrade(4, 1, 1, Some(1));
        let mut clusters = HashMap::new();
        // 1 Unhealthy + 3 drifted Ready.
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Unhealthy, 400),
        );
        for i in 2..=4 {
            clusters.insert(
                format!("pool-test-profile-{i}"),
                drifted_entry(ClusterState::Ready, i * 100),
            );
        }
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes.len(),
            2,
            "Unhealthy + 1 drifted Ready (1× max_recycling) — Unhealthy doesn't consume the budget"
        );
        assert!(
            deletes.contains(&"pool-test-profile-1".to_string()),
            "Unhealthy was Deleted"
        );
    }

    /// When multiple drifted Ready exist with different `state_since`
    /// timestamps, the oldest goes first. This is what the operator
    /// expects intuitively — the longest-stale instance rotates out
    /// before fresher ones — and what tests of cluster behavior over
    /// multiple reconciles depend on.
    #[test]
    fn oldest_drifted_ready_is_recycled_first() {
        let profile = make_profile_with_upgrade(3, 1, 1, Some(0)); // floor=0 so we just observe ordering
        let mut clusters = HashMap::new();
        // Ages: -1 = 1000s ago, -2 = 100s, -3 = 10s.
        // Oldest is "-1" (state_since farthest in the past).
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Ready, 1000),
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            drifted_entry(ClusterState::Ready, 100),
        );
        clusters.insert(
            "pool-test-profile-3".into(),
            drifted_entry(ClusterState::Ready, 10),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes,
            vec!["pool-test-profile-1"],
            "oldest state_since (1000s ago) recycles first"
        );
    }

    /// Scale-down is gated on `drift_in_flight == 0`. While even a
    /// single drifted Ready remains, we must not reap fresh
    /// replacements as "excess idle past min_ready" — that would
    /// undo the surge.
    #[test]
    fn scale_down_is_skipped_while_drift_upgrade_is_in_progress() {
        // Scaling pool: min_ready=2, max_clusters=8, scale_down_after=1m.
        let mut profile = make_profile(
            0,
            Some(crate::crd::ScalingConfig {
                min_ready: 2,
                max_clusters: 8,
                scale_up_threshold: 0,
                scale_down_after: "1m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        profile.spec.upgrade_policy = Some(crate::crd::UpgradePolicy {
            max_recycling: 1,
            max_surge: 1,
            min_ready_during_upgrade: Some(2),
        });
        let current = profile_spec_hash(&profile, &test_render_ctx(), &Default::default());

        // 3 Ready: 1 drifted + 2 clean. Above min_ready=2 with one
        // long-idle clean cluster — would normally scale-down.
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Ready, 200),
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(chrono::Utc::now() - chrono::Duration::minutes(10)),
                health_failures: 0,
                state_since: Some(chrono::Utc::now() - chrono::Duration::minutes(10)),
                spec_hash: Some(current.clone()),
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-profile-3".into(),
            clean_entry(ClusterState::Ready, current),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        // pool-test-profile-1 (drifted) is a candidate for drift recycle,
        // but neither -2 nor -3 (clean, idle, above min_ready) should
        // be Deleted as scale-down — that's gated.
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !deletes.contains(&"pool-test-profile-2".to_string())
                && !deletes.contains(&"pool-test-profile-3".to_string()),
            "scale-down gated while drift upgrade in progress: deletes={deletes:?}"
        );
    }

    // --- Rolling-upgrade policy: edge cases ---

    /// Leased instances are never Deleted, regardless of drift.
    /// They might be drifted (`leased_drifted` informational), but
    /// the recycle path only acts on Ready/Creating. Post-release
    /// recycling (in the lease controller) puts the instance back
    /// into Ready, where the next reconcile picks it up via the
    /// Ready drift path.
    #[test]
    fn leased_instances_are_never_recycled_for_drift() {
        let profile = make_profile_with_upgrade(2, 2, 2, Some(0));
        let mut clusters = HashMap::new();
        // 2 Leased + 0 Ready, all drifted.
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Leased, 100),
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            drifted_entry(ClusterState::Leased, 200),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(
            deletes.len(),
            0,
            "Leased instances are never Deleted by drift recycle: {actions:?}"
        );
    }

    /// When the pool's failure backoff window is open, drift recycle
    /// AND scale-up are both suppressed: Deleting a drifted Ready we
    /// can't replace would just bleed available capacity. Unhealthy
    /// recycle still ships (it doesn't consume create budget).
    #[test]
    fn backoff_window_suppresses_drift_recycling_and_surge() {
        // Build a pool whose status indicates an active backoff window.
        let mut profile = make_profile_with_upgrade(2, 1, 1, Some(0));
        profile.status = Some(crate::crd::ClusterPoolStatus {
            phase: Some(crate::crd::ClusterPoolPhase::Backoff),
            consecutive_failures: 2,
            // ~10s into the future so `now < t` and backoff_active is true.
            next_attempt_at: Some(
                (chrono::Utc::now() + chrono::Duration::seconds(10)).to_rfc3339(),
            ),
            ..Default::default()
        });

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Ready, 100),
        );
        // Plus an Unhealthy to confirm it still recycles.
        clusters.insert(
            "pool-test-profile-2".into(),
            drifted_entry(ClusterState::Unhealthy, 200),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );

        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        let creates: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Create(_)))
            .collect();

        assert_eq!(
            deletes,
            vec!["pool-test-profile-2".to_string()],
            "Unhealthy still ships during backoff; drift recycle suppressed"
        );
        assert_eq!(
            creates.len(),
            0,
            "Scale-up suppressed during backoff (matches existing scale-up gate)"
        );
    }

    /// Setting `max_recycling=0` is the documented kill switch:
    /// drift detection still runs (logs, future metric increments)
    /// but no Deletes ship for drift. Unhealthy recycling continues
    /// independent of this knob — it's not part of the upgrade
    /// pipeline.
    #[test]
    fn max_recycling_zero_pauses_drift_upgrade_but_not_unhealthy_recycle() {
        let profile = make_profile_with_upgrade(3, 0, 1, Some(0));
        let mut clusters = HashMap::new();
        // 1 Unhealthy + 2 drifted Ready.
        clusters.insert(
            "pool-test-profile-1".into(),
            drifted_entry(ClusterState::Unhealthy, 300),
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            drifted_entry(ClusterState::Ready, 200),
        );
        clusters.insert(
            "pool-test-profile-3".into(),
            drifted_entry(ClusterState::Ready, 100),
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            chrono::Utc::now(),
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes,
            vec!["pool-test-profile-1".to_string()],
            "Only the Unhealthy is recycled when max_recycling=0"
        );
    }

    // --- ResolvedUpgradePolicy ---

    /// When a pool has no `upgrade_policy` field set, the resolver
    /// produces the conservative defaults (`maxRecycling=1, maxSurge=1,
    /// minReadyDuringUpgrade=min_ready`) so existing pools get rolling
    /// behavior automatically without a CR edit.
    #[test]
    fn resolved_upgrade_policy_falls_back_to_conservative_defaults_when_unset() {
        let profile = make_profile(2, None); // fixed pool, size=2
        let resolved = resolved_upgrade_policy(&profile, /* min_ready = */ 2);
        assert_eq!(resolved.max_recycling, 1);
        assert_eq!(resolved.max_surge, 1);
        assert_eq!(
            resolved.min_ready_during_upgrade, 2,
            "absent UpgradePolicy uses min_ready as the floor"
        );
    }

    /// When `min_ready_during_upgrade` is left out of an explicit
    /// `UpgradePolicy`, the resolver fills it from the caller-provided
    /// `min_ready` rather than 0, so an operator who sets only the
    /// rate knobs still gets capacity preserved during upgrade.
    #[test]
    fn resolved_upgrade_policy_inherits_min_ready_when_floor_field_omitted() {
        let mut profile = make_profile(4, None);
        profile.spec.upgrade_policy = Some(crate::crd::UpgradePolicy {
            max_recycling: 2,
            max_surge: 2,
            min_ready_during_upgrade: None,
        });
        let resolved = resolved_upgrade_policy(&profile, /* min_ready = */ 4);
        assert_eq!(resolved.max_recycling, 2);
        assert_eq!(resolved.max_surge, 2);
        assert_eq!(resolved.min_ready_during_upgrade, 4);
    }

    /// An explicit `min_ready_during_upgrade: Some(0)` is honored —
    /// this is the documented "recycle without a floor" mode for
    /// pools that can tolerate brief downtime.
    #[test]
    fn resolved_upgrade_policy_honors_explicit_zero_floor() {
        let mut profile = make_profile(2, None);
        profile.spec.upgrade_policy = Some(crate::crd::UpgradePolicy {
            max_recycling: 1,
            max_surge: 1,
            min_ready_during_upgrade: Some(0),
        });
        let resolved = resolved_upgrade_policy(&profile, /* min_ready = */ 2);
        assert_eq!(resolved.min_ready_during_upgrade, 0);
    }

    #[test]
    fn stuck_creating_timeout_is_configurable_via_scaling() {
        // Pool sets creating_timeout = 20m. An instance Creating for 15m
        // should NOT be deleted (under the new ceiling), but one for
        // 25m should be.
        let profile = make_profile(
            6,
            Some(crate::crd::ScalingConfig {
                min_ready: 6,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "20m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-young".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(15)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-profile-old".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(25)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !deletes.contains(&"pool-test-profile-young".to_string()),
            "instance Creating for 15min should NOT be deleted with creating_timeout=20m; deletes={deletes:?}"
        );
        assert!(
            deletes.contains(&"pool-test-profile-old".to_string()),
            "instance Creating for 25min should be deleted with creating_timeout=20m; deletes={deletes:?}"
        );
    }

    #[test]
    fn stuck_creating_timeout_falls_back_to_10m_on_garbage() {
        // Garbage value -> parse fails -> default 10m applies.
        let profile = make_profile(
            6,
            Some(crate::crd::ScalingConfig {
                min_ready: 6,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "not-a-duration".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-12m".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(12)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            deletes.contains(&"pool-test-profile-12m".to_string()),
            "instance Creating for 12min should be deleted because garbage falls back to 10m default; deletes={deletes:?}"
        );
    }

    /// #189: a scheduling-blocked Creating instance must NOT be recycled by the
    /// stuck-Creating timeout, no matter how long it's been Creating —
    /// respawning would just create more Unschedulable Pods. A *clean*
    /// (not-blocked) sibling past the timeout still gets Deleted, proving the
    /// guard is scoped to the blocked entry only.
    #[test]
    fn scheduling_blocked_creating_is_not_recycled_by_timeout() {
        let profile = make_profile(
            6,
            Some(crate::crd::ScalingConfig {
                min_ready: 6,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();

        let mut clusters = HashMap::new();
        // Blocked for 30m (well past 10m) — must be HELD, not Deleted.
        clusters.insert(
            "pool-test-profile-blocked".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(30)),
                spec_hash: None,
                scheduling_blocked: true,
                crashlooping: false,
                crash_message: None,
            },
        );
        // Clean, equally-old Creating — the control: it MUST be Deleted.
        clusters.insert(
            "pool-test-profile-clean".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(30)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !deletes.contains(&"pool-test-profile-blocked".to_string()),
            "scheduling-blocked Creating must NOT be recycled by the timeout; deletes={deletes:?}"
        );
        assert!(
            deletes.contains(&"pool-test-profile-clean".to_string()),
            "a clean Creating past the timeout must still be recycled; deletes={deletes:?}"
        );
    }

    /// #197: `stuck_creating_reason` labels a crashlooping entry `CrashLooping`
    /// and a plain one `Timeout`.
    #[test]
    fn stuck_creating_reason_labels_crashloop() {
        let mut crashing = make_entry(ClusterState::Creating);
        crashing.crashlooping = true;
        assert_eq!(
            stuck_creating_reason(&crashing),
            crate::metrics::StuckCreatingReason::CrashLooping
        );

        let plain = make_entry(ClusterState::Creating);
        assert_eq!(
            stuck_creating_reason(&plain),
            crate::metrics::StuckCreatingReason::Timeout
        );
    }

    /// #197 (control flow unchanged): a CRASHLOOPING Creating past the
    /// creating-timeout MUST still be recycled — unlike scheduling-blocked, the
    /// crashloop flag is observability-only and does NOT suppress the Delete.
    #[test]
    fn crashlooping_creating_is_still_recycled_by_timeout() {
        let profile = make_profile(
            6,
            Some(crate::crd::ScalingConfig {
                min_ready: 6,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();

        let mut clusters = HashMap::new();
        // Crashlooping for 30m (well past 10m) — MUST still be Deleted, exactly
        // like a plain stuck Creating.
        clusters.insert(
            "pool-test-profile-crashing".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(30)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: true,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            deletes.contains(&"pool-test-profile-crashing".to_string()),
            "a crashlooping Creating past the timeout MUST still be recycled (observability-only flag); deletes={deletes:?}"
        );
    }

    /// Same guard, but inside the `backoff_active` early-return path (step 2):
    /// a scheduling-blocked Creating is still held while the pool is in its
    /// backoff window, while a clean one past the timeout is still Deleted.
    #[test]
    fn scheduling_blocked_creating_held_during_backoff() {
        let mut profile = make_profile(
            6,
            Some(crate::crd::ScalingConfig {
                min_ready: 6,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
                creating_timeout: "10m".to_string(),
                failure_backoff: None,
            }),
        );
        let now = chrono::Utc::now();
        // Put the pool inside an active backoff window.
        profile.status = Some(crate::crd::ClusterPoolStatus {
            next_attempt_at: Some((now + chrono::Duration::minutes(1)).to_rfc3339()),
            consecutive_failures: 1,
            ..Default::default()
        });

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-blocked".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(30)),
                spec_hash: None,
                scheduling_blocked: true,
                crashlooping: false,
                crash_message: None,
            },
        );
        clusters.insert(
            "pool-test-profile-clean".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: Some(now - chrono::Duration::minutes(30)),
                spec_hash: None,
                scheduling_blocked: false,
                crashlooping: false,
                crash_message: None,
            },
        );
        let state = PoolState { clusters };
        let actions = compute_pool_actions(
            &profile,
            &state,
            now,
            &test_render_ctx(),
            &Default::default(),
        );
        let deletes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                PoolAction::Delete(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !deletes.contains(&"pool-test-profile-blocked".to_string()),
            "scheduling-blocked Creating must be held even during backoff; deletes={deletes:?}"
        );
        assert!(
            deletes.contains(&"pool-test-profile-clean".to_string()),
            "a clean stuck Creating is still recycled during backoff; deletes={deletes:?}"
        );
    }
}
