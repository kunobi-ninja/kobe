//! Management-cluster placement for Sandbox pools and leases (#73).
//!
//! #71 supplied the projection — [`build_sandbox_template`],
//! [`build_sandbox_warm_pool`], [`build_sandbox_claim`] — and the pure
//! lifecycle transitions. This module is the loop that drives them: it
//! reconciles each `SandboxPool` into controller-owned upstream objects, and
//! each admitted `SandboxLease` into exactly one `SandboxClaim`.
//!
//! # What a caller cannot reach
//!
//! Callers select a `SandboxPool` and nothing else. Every upstream object here
//! is built from the administrator-owned pool spec, named by the controller,
//! and owner-referenced to its Kobe parent. There is no path from lease intent
//! to a Pod spec, a RuntimeClass, a namespace, or a host mount.
//!
//! # Admission is a precondition, not a formality
//!
//! Only leases annotated `admitted` are placed. A `pending` lease may exist
//! before its quota reservation committed, so acting on one would place work
//! that admission never authorised — the reason that annotation exists.

use std::sync::Arc;

use futures::StreamExt;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams,
    PropagationPolicy,
};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::sandbox::{
    SANDBOX_ADMISSION_ADMITTED, SANDBOX_ADMISSION_ANNOTATION,
    SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION,
};
use crate::crd::{SandboxLease, SandboxPlacement, SandboxPool};
use crate::sandbox::{
    AGENT_SANDBOX_API_VERSION, SANDBOX_CLAIM_KIND, SANDBOX_TEMPLATE_KIND, SANDBOX_WARM_POOL_KIND,
    build_sandbox_claim, build_sandbox_template, build_sandbox_warm_pool,
};

/// Shared state for the Sandbox placement controllers.
pub struct SandboxContext {
    pub client: Client,
    /// Operator-owned namespace the upstream objects live in. Never
    /// caller-selectable: a lease that could choose its namespace could place
    /// work next to somebody else's.
    pub namespace: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxPlacementError {
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
    #[error(transparent)]
    Mapping(#[from] crate::sandbox::SandboxMappingError),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    ChildPlacement(#[from] crate::controllers::sandbox_child::ChildPlacementError),
}

impl SandboxPlacementError {
    /// Bounded reason code for logs and metrics, so a child composition failure
    /// is countable by cause rather than only by message.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Kubernetes(_) => "kubernetes",
            Self::Mapping(_) => "mapping",
            Self::Invalid(_) => "invalid",
            Self::ChildPlacement(error) => error.reason_code(),
        }
    }
}

/// Names are derived, never taken from caller input, so one pool's objects can
/// never collide with or impersonate another's.
fn template_name(pool: &str) -> String {
    format!("kobe-{pool}")
}
fn warm_pool_name(pool: &str) -> String {
    format!("kobe-{pool}")
}
fn claim_name(lease: &str) -> String {
    format!("kobe-{lease}")
}

/// The upstream API resources this controller writes.
///
/// Built by hand rather than discovered: the version is pinned so an
/// incompatible runtime is refused at startup (#72) rather than silently
/// written to here.
fn upstream_resource(kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: "extensions.agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: AGENT_SANDBOX_API_VERSION.into(),
        kind: kind.into(),
        plural: plural.into(),
    }
}

/// Server-side apply, so a drifted upstream object is corrected rather than
/// duplicated, and two replicas reconciling the same pool converge instead of
/// fighting.
async fn apply_upstream(
    client: &Client,
    namespace: &str,
    resource: &ApiResource,
    object: &DynamicObject,
) -> Result<DynamicObject, kube::Error> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, resource);
    api.patch(
        &object.name_any(),
        &PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY).force(),
        &Patch::Apply(object),
    )
    .await
}

/// Apply one pool's `SandboxTemplate` and `SandboxWarmPool` into a cluster.
///
/// Shared by management placement and by child composition, so the two cannot
/// drift into projecting a pool differently — #76 asks for equivalent
/// semantics across placements, and equivalence built from one code path is
/// the only kind that stays true.
///
/// `owner` is `None` in a child cluster, and that is not an oversight: an owner
/// reference names an object *in the same cluster*, so a reference to a
/// management-cluster `SandboxPool` would name nothing there and Kubernetes
/// garbage collection would delete the template immediately. A child cluster's
/// objects are bounded by the cluster's own lifetime instead — it is torn down
/// whole.
async fn ensure_upstream_pool_objects(
    client: &Client,
    namespace: &str,
    pool_name: &str,
    spec: &crate::crd::SandboxPoolSpec,
    owner: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
) -> Result<(), SandboxPlacementError> {
    let template = build_sandbox_template(&template_name(pool_name), namespace, spec, owner)?;
    apply_upstream(
        client,
        namespace,
        &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
        &template,
    )
    .await?;

    let warm_pool = build_sandbox_warm_pool(
        &warm_pool_name(pool_name),
        namespace,
        &template_name(pool_name),
        spec.warm_capacity,
        owner,
    )?;
    apply_upstream(
        client,
        namespace,
        &upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
        &warm_pool,
    )
    .await?;
    Ok(())
}

/// Reconcile one `SandboxPool` into its controller-owned upstream objects.
///
/// Child-placement pools are skipped entirely: composing a child cluster is
/// #74's job, and reconciling their template here would create management-
/// cluster capacity for a pool that must never serve from the management
/// cluster.
pub async fn reconcile_pool(
    pool: Arc<SandboxPool>,
    ctx: Arc<SandboxContext>,
) -> Result<Action, SandboxPlacementError> {
    let name = pool.name_any();
    if !matches!(pool.spec.placement, SandboxPlacement::Management {}) {
        debug!(pool = %name, "not a management-placement pool; skipping");
        return Ok(Action::await_change());
    }

    let owner = pool.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxPool {name} has no UID to own its objects"))
    })?;

    ensure_upstream_pool_objects(
        &ctx.client,
        &ctx.namespace,
        &name,
        &pool.spec,
        // Owner-referenced here, where the parent SandboxPool actually exists.
        Some(&owner),
    )
    .await?;

    debug!(pool = %name, "reconciled upstream template and warm pool");
    Ok(Action::requeue(std::time::Duration::from_secs(120)))
}

/// Reconcile one admitted `SandboxLease` into exactly one `SandboxClaim`.
///
/// Creation is `create`-then-tolerate-409 rather than apply: exactly one claim
/// per lease is the invariant, and a create that loses the race has already
/// been satisfied by whoever won it.
pub async fn reconcile_lease(
    lease: Arc<SandboxLease>,
    ctx: Arc<SandboxContext>,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();

    // Placement acts only on admitted leases. A `pending` lease may exist
    // before its quota reservation committed; placing one would create work
    // admission never authorised.
    if lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        != Some(SANDBOX_ADMISSION_ADMITTED)
    {
        debug!(lease = %name, "not admitted; placement declines");
        return Ok(Action::await_change());
    }

    // Teardown is evaluated BEFORE the pool is resolved, and deliberately so.
    // Release must work when the pool was edited or deleted outright — those
    // are exactly the situations that strand capacity — so it must not sit
    // behind a fence that a missing pool would fail.
    if let Some(reason) = release_reason(&lease) {
        return drive_release(&lease, &ctx, reason).await;
    }

    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pool = pools.get(&lease.spec.pool_ref.name).await?;

    // The reference carries UID and generation precisely because a name is not
    // an identity. Between admission and here the pool can be deleted and
    // recreated, or edited — and admission decided quota, placement and image
    // against the spec it actually saw. Placing against anything else runs the
    // caller's workload under configuration nobody admitted them to.
    if pool.uid().as_deref() != Some(lease.spec.pool_ref.uid.as_str()) {
        return Err(SandboxPlacementError::Invalid(format!(
            "lease {name} was admitted against SandboxPool uid {} but {} now has uid {}",
            lease.spec.pool_ref.uid,
            lease.spec.pool_ref.name,
            pool.uid().unwrap_or_else(|| "<none>".into())
        )));
    }
    if pool.metadata.generation.unwrap_or_default() != lease.spec.pool_ref.generation {
        return Err(SandboxPlacementError::Invalid(format!(
            "lease {name} was admitted against SandboxPool generation {} but {} is now generation {}",
            lease.spec.pool_ref.generation,
            lease.spec.pool_ref.name,
            pool.metadata.generation.unwrap_or_default()
        )));
    }

    // Where this lease's Sandbox actually runs. Management placement uses the
    // operator's own cluster; child placement composes an exclusive one, which
    // may not be ready yet — in which case there is nothing to place into.
    let target = match &pool.spec.placement {
        SandboxPlacement::Management {} => Target {
            client: ctx.client.clone(),
            namespace: ctx.namespace.clone(),
            // The parent SandboxPool and SandboxLease live in this cluster, so
            // upstream objects can be owned by them.
            owned: true,
        },
        SandboxPlacement::ChildCluster { cluster_pool_ref } => {
            match compose_child_target(&lease, &pool, cluster_pool_ref, &ctx).await? {
                ChildTarget::Ready(target) => target,
                ChildTarget::Pending(action) => return Ok(action),
            }
        }
    };

    let owner = lease.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxLease {name} has no UID to own its claim"))
    })?;
    let claim = build_sandbox_claim(
        &claim_name(&name),
        &target.namespace,
        &warm_pool_name(&pool.name_any()),
        // See `ensure_upstream_pool_objects`: an owner reference names an
        // object in the SAME cluster, so in a child it would name nothing and
        // the claim would be garbage-collected on sight.
        target.owned.then_some(&owner),
    );

    let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
    let claims: Api<DynamicObject> =
        Api::namespaced_with(target.client.clone(), &target.namespace, &resource);
    match claims.create(&PostParams::default(), &claim).await {
        Ok(_) => info!(lease = %name, "created upstream SandboxClaim"),
        // Already placed. One claim per lease is the invariant, and this
        // reconcile simply lost the race to satisfy it.
        Err(kube::Error::Api(error)) if error.code == 409 => {
            debug!(lease = %name, "claim already exists")
        }
        Err(error) => return Err(error.into()),
    }

    // The claim exists. Everything below turns "an object was created" into a
    // lease that is actually usable and actually bounded.
    let claim = claims.get(&claim_name(&name)).await?;
    if !upstream_claim_is_ready(&claim) {
        debug!(lease = %name, "claim not Ready yet; TTL clock has not started");
        return Ok(Action::requeue(std::time::Duration::from_secs(10)));
    }

    // Upstream `Ready` is a statement about the container, not the agent inside
    // it. A Pod whose entrypoint crash-looped, whose weights failed to mount,
    // or whose agent is wedged on a lock satisfies it — and believing it starts
    // a paid runtime TTL on a Sandbox that cannot serve. The pool's own canary
    // asks the workload directly.
    //
    // The pass is recorded on the lease before anything else, and a recorded
    // pass is not re-run. Re-executing an administrator's command inside a live
    // tenant workload on every requeue is not a health check — it is a repeated
    // side effect on somebody else's Sandbox — and a controller that restarted
    // between the canary and the Ready write must not run it a second time.
    let status = lease.status.clone().unwrap_or_default();
    if !canary_already_passed(&status) {
        let outcome = crate::controllers::sandbox_canary::evaluate_readiness_canary(
            &target.client,
            &target.namespace,
            &claim,
            &pool.spec.template.default_container,
            &pool.spec.readiness.canary,
        )
        .await;
        if !outcome.is_pass() {
            // Not ready, and deliberately not an error either way: a failing
            // canary is a Sandbox that has not come up yet, and an unrunnable
            // one is no evidence at all. The provisioning deadline already
            // bounds how long this may repeat, so a Sandbox that never passes
            // ends as an expiry rather than as a lease that hangs.
            debug!(
                lease = %name,
                outcome = outcome.reason_code(),
                "readiness canary did not pass; TTL clock has not started"
            );
            return Ok(Action::requeue(std::time::Duration::from_secs(10)));
        }
        patch_lease_status(
            &ctx,
            &name,
            &serde_json::json!({
                "conditions": with_condition(
                    &lease,
                    READINESS_CANARY_CONDITION,
                    crate::crd::SandboxConditionStatus::True,
                    "CanaryPassed",
                    "Pool readiness canary exited zero inside the Sandbox",
                ),
            }),
        )
        .await?;
        debug!(lease = %name, "readiness canary passed");
    }

    // Runtime TTL starts HERE, at observed readiness — not when the request
    // arrived. A caller must not be billed for however long placement and
    // provisioning took, which is the whole reason the provisioning deadline
    // is a separate bound.
    let runtime_ttl = crate::pool::parse_duration(&lease.spec.ttl).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("lease {name} has an invalid TTL"))
    })?;
    let observed_generation = lease.metadata.generation.unwrap_or_default();
    // An already-Ready lease reuses its PERSISTED readiness instant. Passing a
    // fresh `now()` on every requeue would make the transition non-idempotent:
    // it would be refused as a changed timestamp forever, and the backstop
    // below would stop being re-asserted.
    let ready_at = persisted_ready_at(&status).unwrap_or_else(chrono::Utc::now);
    let resource_version = claim.resource_version().unwrap_or_default();

    let next_status = match crate::sandbox::mark_sandbox_ready(
        &status,
        observed_generation,
        ready_at,
        runtime_ttl,
    ) {
        Ok(next) => next,
        // The Sandbox came up, but too late to be worth anything. Leaving
        // it running with no expiry is the unbounded-workload case this
        // whole path exists to prevent, so shut it down upstream NOW and
        // move the lease to Releasing rather than requeue forever.
        Err(crate::sandbox::SandboxLifecycleError::ProvisioningDeadlineElapsed) => {
            warn!(lease = %name, "provisioning deadline elapsed; releasing");
            stamp_upstream_shutdown(
                &claims,
                &claim_name(&name),
                &resource_version,
                chrono::Utc::now(),
            )
            .await?;
            let phase = crate::sandbox::transition_sandbox_phase(
                status.phase,
                crate::crd::SandboxLeasePhase::Releasing,
                false,
            )
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
            patch_lease_status(
                &ctx,
                &name,
                &serde_json::json!({ "phase": phase, "message": "provisioning deadline elapsed" }),
            )
            .await?;
            return Ok(Action::await_change());
        }
        Err(error) => {
            debug!(lease = %name, error = %error, "readiness transition declined");
            return Ok(Action::requeue(std::time::Duration::from_secs(30)));
        }
    };

    // Stamp the upstream absolute shutdown time as a BACKSTOP. If Kobe stops
    // reconciling — crash, upgrade, lost credentials — the upstream controller
    // still tears the Sandbox down at the deadline rather than leaving a
    // tenant workload running indefinitely. `DeleteForeground` so the
    // dependents go with it.
    //
    // A missing or unparseable expiry is a HARD failure, not a skipped step:
    // marking the lease Ready without the backstop is exactly the unbounded
    // case, and it would be invisible until someone went looking.
    let expires_at = next_status
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "lease {name} became Ready without a parseable expiry; refusing to place it unbounded"
            ))
        })?;
    stamp_upstream_shutdown(
        &claims,
        &claim_name(&name),
        &resource_version,
        expires_at.with_timezone(&chrono::Utc),
    )
    .await?;

    // Only now is the lease Ready: the Sandbox exists, and its shutdown is
    // bounded even if this controller never runs again.
    patch_lease_status(&ctx, &name, &serde_json::json!(next_status)).await?;
    info!(lease = %name, "Sandbox lease Ready; runtime TTL started");

    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// Why a lease is being torn down, if it is.
///
/// Recorded on the lease so an operator reading a `Released` object can tell a
/// caller who asked from a lease that simply ran out — they mean different
/// things when someone is reconstructing what happened to a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseReason {
    /// The caller asked. The API records intent as an annotation and never
    /// touches status; turning that intent into teardown is this controller's
    /// job, and until it runs the capacity is still held.
    Requested,
    /// The runtime TTL elapsed. The upstream `shutdownTime` backstop removes
    /// the Sandbox itself, but nothing upstream knows about Kobe's quota
    /// reservations — an expiry that only fired upstream would leak a slot
    /// per lease, forever.
    Expired,
    /// Teardown was already under way and has not been proven complete.
    InProgress,
}

impl ReleaseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "ReleaseRequested",
            Self::Expired => "TtlElapsed",
            Self::InProgress => "TeardownInProgress",
        }
    }

    /// The terminal phase a verified teardown reaches.
    ///
    /// `Released` and `Expired` are both clean, but they are not
    /// interchangeable: billing, quota reporting and support all care whether
    /// a caller gave capacity back or had it taken.
    fn terminal_phase(self) -> crate::crd::SandboxLeasePhase {
        match self {
            Self::Expired => crate::crd::SandboxLeasePhase::Expired,
            _ => crate::crd::SandboxLeasePhase::Released,
        }
    }
}

/// Whether this lease should be torn down rather than placed.
fn release_reason(lease: &SandboxLease) -> Option<ReleaseReason> {
    let status = lease.status.clone().unwrap_or_default();
    match status.phase {
        // Terminal. Re-running teardown here would be a no-op at best and, if
        // the name were later reused, would act on somebody else's footprint.
        crate::crd::SandboxLeasePhase::Released
        | crate::crd::SandboxLeasePhase::Expired
        | crate::crd::SandboxLeasePhase::Quarantined => return None,
        // Already releasing: teardown was interrupted and is not proven done.
        crate::crd::SandboxLeasePhase::Releasing => return Some(ReleaseReason::InProgress),
        _ => {}
    }

    if lease
        .annotations()
        .contains_key(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
    {
        return Some(ReleaseReason::Requested);
    }

    // An unparseable expiry is NOT treated as expired. Deleting a live
    // workload because a timestamp failed to parse is the more damaging
    // reading of the same uncertainty; the lease stays put and stays visible.
    let expires_at = status
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())?;
    (chrono::Utc::now() >= expires_at).then_some(ReleaseReason::Expired)
}

/// Tear one lease down and give its capacity back — but only against proof.
///
/// The order is the point. The upstream claim is deleted, its absence is
/// *verified*, and only then are the quota and alias reservations released.
/// Releasing reservations first would let the freed slot be handed to the next
/// caller while the previous Sandbox was still running, which is precisely the
/// over-subscription the ledger exists to prevent.
///
/// Uncertainty quarantines rather than releases. A lease whose teardown cannot
/// be verified keeps consuming its slot: under-counting capacity is recoverable
/// by an operator, silently double-booking a Sandbox host is not.
async fn drive_release(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    use crate::crd::SandboxLeasePhase;

    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();

    // Make the intent visible in status first. Until the phase moves, capacity
    // accounting and the API both still read this as a live lease, and a
    // teardown that crashed midway would look like one too.
    if status.phase != SandboxLeasePhase::Releasing {
        let phase = crate::sandbox::transition_sandbox_phase(
            status.phase,
            SandboxLeasePhase::Releasing,
            false,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        patch_lease_status(
            ctx,
            &name,
            &serde_json::json!({ "phase": phase, "message": reason.as_str() }),
        )
        .await?;
        info!(lease = %name, reason = reason.as_str(), "releasing Sandbox lease");
    }

    // A child-placed lease is torn down by destroying its cluster, not by
    // deleting a claim from here.
    //
    // This is not an optimisation. The claim lives in the child cluster, so
    // deleting it against the management cluster would 404 — and a 404 is
    // exactly what this path treats as proof of absence. The quota slot would
    // be handed to the next caller while the previous tenant's Sandbox was
    // still running in a cluster nobody had touched.
    if is_child_placed(&status) {
        return release_child_composition(lease, ctx, reason).await;
    }

    let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
    let claims: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &resource);
    let claim = claim_name(&name);

    // Foreground propagation: the claim must not report gone while the Sandbox
    // it owns is still running, because that reported absence is what releases
    // the caller's quota slot.
    let delete = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..Default::default()
    };
    match claims.delete(&claim, &delete).await {
        Ok(_) => {}
        Err(kube::Error::Api(error)) if error.code == 404 => {}
        // Cannot even ask for deletion. Retry — this is not yet evidence of
        // anything, and quarantining on a transient error would strand
        // capacity that is fine.
        Err(error) => {
            warn!(lease = %name, error = %error, "could not delete upstream claim");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }
    }

    // Only a 404 proves absence. A successful DELETE means "accepted", and a
    // claim mid-foreground-deletion is still very much there.
    match claim_absence(&claims, &claim).await {
        ClaimAbsence::Verified => {}
        // Not gone yet. Foreground deletion takes as long as the Sandbox takes
        // to stop, and "still deleting" is a normal state, not a fault. The
        // lease stays in Releasing and keeps holding its slot meanwhile.
        ClaimAbsence::StillPresent => {
            debug!(lease = %name, "upstream claim still present; waiting for teardown");
            return Ok(Action::requeue(std::time::Duration::from_secs(10)));
        }
        // We are not permitted to look, and retrying will not grant the
        // permission. This is durable uncertainty.
        ClaimAbsence::Unverifiable => {
            return quarantine_lease(lease, ctx, "claim_absence_unverifiable").await;
        }
    }

    // The footprint is gone. Now, and only now, the slot goes back.
    finish_release(lease, ctx, reason).await
}

/// Release the admission reservations and reach the terminal phase.
///
/// Only ever called once the footprint has been *proven* absent — by the claim
/// for management placement, by the child cluster for a composition. Both
/// placements share this tail so their release semantics cannot drift apart,
/// which is the equivalence #76 sets out to prove.
async fn finish_release(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    use crate::crd::SandboxLeasePhase;

    let name = lease.name_any();
    let uid = lease
        .uid()
        .ok_or_else(|| SandboxPlacementError::Invalid(format!("lease {name} has no UID")))?;
    let reservations: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    if let Err(error) =
        crate::api::sandbox::release_reservations_for_lease(&reservations, &uid).await
    {
        // The Sandbox is gone but the slot is still booked. Retry rather than
        // finish: a lease marked terminal with a live reservation leaks that
        // slot with nothing left to reconcile it.
        warn!(lease = %name, error = %error, "could not release admission reservations");
        return Ok(Action::requeue(std::time::Duration::from_secs(15)));
    }

    let terminal = crate::sandbox::transition_sandbox_phase(
        SandboxLeasePhase::Releasing,
        reason.terminal_phase(),
        true,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    patch_lease_status(
        ctx,
        &name,
        &serde_json::json!({
            "phase": terminal,
            "conditions": with_cleanup_condition(
                lease,
                crate::crd::SandboxConditionStatus::True,
                "TeardownVerified",
                "Lease-owned footprint observed absent and reservations released",
            ),
        }),
    )
    .await?;
    info!(lease = %name, phase = %terminal, "Sandbox lease teardown verified");
    Ok(Action::await_change())
}

/// Whether this lease's Sandbox runs in a composed child cluster.
///
/// Read from the *resolved* placement recorded on status rather than from the
/// pool spec, because teardown must remain correct when the pool was since
/// edited or deleted — the question is where this lease was actually placed,
/// not where a pool of that name would place a lease today.
fn is_child_placed(status: &crate::crd::SandboxLeaseStatus) -> bool {
    matches!(
        status.placement,
        Some(crate::crd::ResolvedSandboxPlacement::ChildCluster { .. })
    )
}

/// Tear down a child composition by destroying its cluster.
///
/// The internal `ClusterLease` was created with `CleanupMode::VerifiedDestroy`,
/// so releasing it is what puts #80's machinery to work: the cluster's
/// footprint must be observed gone before its capacity returns to the
/// `ClusterPool`. Destroying the cluster destroys the Sandbox inside it, which
/// is why this replaces — rather than accompanies — the claim delete.
///
/// The quota slot is released only once the internal lease is observed absent.
/// Anything less would return capacity while a tenant's cluster was still
/// running.
async fn release_child_composition(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();

    // Act on the exact recorded identity. A same-named ClusterLease composed
    // for a later Sandbox is somebody else's cluster, and deleting it would
    // destroy a running tenant's work.
    let Some(recorded) = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
    else {
        // Nothing was ever composed — the lease was released before it got a
        // cluster. There is no footprint to prove absent.
        debug!(lease = %name, "no child composition recorded; nothing to destroy");
        return finish_release(lease, ctx, reason).await;
    };

    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match internal.get(&recorded.name).await {
        Ok(current) if current.uid().as_deref() == Some(recorded.uid.as_str()) => {
            let delete = DeleteParams {
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(recorded.uid.clone()),
                    resource_version: None,
                }),
                ..Default::default()
            };
            match internal.delete(&recorded.name, &delete).await {
                Ok(_) => {}
                // 404 or 409: ours is not there, which is the goal. Either way
                // the check below is what decides, not this call.
                Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
                Err(error) => {
                    warn!(lease = %name, error = %error, "could not release child cluster lease");
                    return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                }
            }
            // Destroying a cluster is not instantaneous, and #80 will not let
            // its capacity return until the footprint is proven gone. Wait.
            debug!(lease = %name, "child cluster still being destroyed");
            Ok(Action::requeue(std::time::Duration::from_secs(30)))
        }
        // Gone, or replaced by a different object under the same name. Either
        // way THIS lease's cluster is not there.
        Ok(_) => finish_release(lease, ctx, reason).await,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            finish_release(lease, ctx, reason).await
        }
        // Cannot tell whether the tenant's cluster is still running.
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            quarantine_lease(lease, ctx, "child_absence_unverifiable").await
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "could not check child cluster lease");
            Ok(Action::requeue(std::time::Duration::from_secs(15)))
        }
    }
}

/// What one absence check established.
///
/// Three outcomes, not two, because "still there" and "cannot tell" call for
/// opposite responses: the first is a normal step in a deletion that is still
/// running, the second means the evidence will never arrive. Collapsing them
/// would either quarantine every healthy teardown or release capacity on the
/// strength of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimAbsence {
    /// Observed absent. The only outcome that releases capacity.
    Verified,
    /// Still responding — including mid-deletion, with a `deletionTimestamp`.
    StillPresent,
    /// The question could not be answered and retrying will not change that.
    Unverifiable,
}

/// Whether the upstream claim is provably gone.
///
/// Absence is proven by a 404 and nothing else. Reading "I could not check" as
/// "it is gone" is how a live Sandbox's capacity gets handed to somebody else.
async fn claim_absence(claims: &Api<DynamicObject>, claim: &str) -> ClaimAbsence {
    match claims.get(claim).await {
        Ok(_) => ClaimAbsence::StillPresent,
        Err(kube::Error::Api(error)) if error.code == 404 => ClaimAbsence::Verified,
        // Not permitted to look. Retrying will not grant the permission, so
        // this is durable uncertainty rather than a transient failure.
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            ClaimAbsence::Unverifiable
        }
        // Anything else — a 500, a timeout, a torn connection — may well clear
        // on its own. Treat it as "not yet" and come back; the lease keeps
        // holding its capacity in the meantime, so waiting costs correctness
        // nothing.
        Err(_) => ClaimAbsence::StillPresent,
    }
}

/// Hold a lease whose teardown could not be proven.
///
/// `Quarantined` still consumes capacity, on purpose: an operator can see and
/// reconcile an under-counted pool, but nobody can see a Sandbox that was
/// quietly double-booked.
async fn quarantine_lease(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: &str,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let phase = crate::sandbox::transition_sandbox_phase(
        lease
            .status
            .as_ref()
            .map(|status| status.phase)
            .unwrap_or_default(),
        crate::crd::SandboxLeasePhase::Quarantined,
        false,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    patch_lease_status(
        ctx,
        &name,
        &serde_json::json!({
            "phase": phase,
            "conditions": with_cleanup_condition(
                lease,
                crate::crd::SandboxConditionStatus::False,
                reason,
                "Teardown could not be verified; capacity is withheld",
            ),
        }),
    )
    .await?;
    warn!(lease = %name, reason, "Sandbox lease quarantined; capacity withheld");
    Ok(Action::requeue(std::time::Duration::from_secs(300)))
}

const CLEANUP_VERIFIED_CONDITION: &str = "CleanupVerified";
/// Durable record that the pool's canary already ran and passed.
///
/// Durable rather than in-memory because the alternative is running an
/// administrator's command inside a live tenant workload again after every
/// controller restart.
const READINESS_CANARY_CONDITION: &str = "ReadinessCanary";

/// Whether the readiness canary has already been observed to pass.
fn canary_already_passed(status: &crate::crd::SandboxLeaseStatus) -> bool {
    status.conditions.iter().any(|condition| {
        condition.condition_type == READINESS_CANARY_CONDITION
            && condition.status == crate::crd::SandboxConditionStatus::True
    })
}

fn with_cleanup_condition(
    lease: &SandboxLease,
    status: crate::crd::SandboxConditionStatus,
    reason: &str,
    message: &str,
) -> Vec<crate::crd::SandboxCondition> {
    with_condition(lease, CLEANUP_VERIFIED_CONDITION, status, reason, message)
}

/// Build the whole condition list, with one condition upserted into it.
///
/// The full list is rebuilt because the status patch is a JSON merge patch,
/// which REPLACES an array rather than merging it: sending one condition alone
/// would silently drop every other condition on the lease.
///
/// `lastTransitionTime` moves only when the status actually changes, per the
/// Kubernetes convention — a timestamp that advanced on every requeue would
/// make a condition that has been stable for an hour look like it just
/// flipped.
fn with_condition(
    lease: &SandboxLease,
    condition_type: &str,
    status: crate::crd::SandboxConditionStatus,
    reason: &str,
    message: &str,
) -> Vec<crate::crd::SandboxCondition> {
    let existing = lease
        .status
        .as_ref()
        .map(|status| status.conditions.clone())
        .unwrap_or_default();
    let previous = existing
        .iter()
        .find(|condition| condition.condition_type == condition_type);
    let last_transition_time = match previous {
        Some(previous) if previous.status == status => previous.last_transition_time.clone(),
        _ => Some(chrono::Utc::now().to_rfc3339()),
    };

    let mut conditions: Vec<_> = existing
        .into_iter()
        .filter(|condition| condition.condition_type != condition_type)
        .collect();
    conditions.push(crate::crd::SandboxCondition {
        condition_type: condition_type.to_string(),
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: lease.metadata.generation,
        last_transition_time,
    });
    conditions
}

/// Where one lease's Sandbox is placed.
struct Target {
    client: Client,
    namespace: String,
    /// Whether upstream objects here may carry an owner reference to their
    /// Kobe parent. True only in the management cluster, where that parent
    /// exists — see [`ensure_upstream_pool_objects`].
    owned: bool,
}

/// A child cluster is either usable now, or it is not there yet.
enum ChildTarget {
    Ready(Target),
    /// Composition is in progress; the action says when to look again.
    Pending(Action),
}

/// Acquire — or resume — the exclusive child cluster this lease runs in.
///
/// Every refusal happens before a cluster is allocated. A composition that
/// cannot be completed is worth nothing to the caller and expensive to
/// everyone else: an abandoned child cluster is a whole cluster's capacity.
async fn compose_child_target(
    lease: &SandboxLease,
    pool: &SandboxPool,
    cluster_pool_ref: &str,
    ctx: &SandboxContext,
) -> Result<ChildTarget, SandboxPlacementError> {
    use crate::controllers::sandbox_child as child;

    let name = lease.name_any();
    let cluster_pools: Api<crate::crd::ClusterPool> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let cluster_pool = cluster_pools.get(cluster_pool_ref).await?;

    // Backend capability first: a pool that cannot prove teardown must never
    // back an exclusive tenant cluster, and finding that out after allocating
    // one helps nobody.
    child::child_pool_is_eligible(&pool.name_any(), &cluster_pool)?;

    let runtime_ttl = crate::pool::parse_duration(&lease.spec.ttl)
        .and_then(|ttl| ttl.to_std().ok())
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!("lease {name} has an invalid TTL"))
        })?;
    let lifetime = child::child_lifetime_fits(&cluster_pool, pool, runtime_ttl)?;

    // Create-or-adopt, keyed on a derived name, so a restarted controller
    // resumes the same cluster instead of allocating a second one.
    let internal_name = child::internal_lease_name(&name);
    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let internal_lease = match internal.get(&internal_name).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            let composed = child::build_internal_cluster_lease(lease, cluster_pool_ref, lifetime)
                .ok_or_else(|| {
                SandboxPlacementError::Invalid(format!("lease {name} has no UID to own a child"))
            })?;
            match internal.create(&PostParams::default(), &composed).await {
                Ok(created) => {
                    info!(lease = %name, cluster_lease = %internal_name, "composed child cluster lease");
                    created
                }
                // Lost the race; the winner's object is the one to use.
                Err(kube::Error::Api(error)) if error.code == 409 => {
                    internal.get(&internal_name).await?
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };

    // Adoption is fenced. A same-named object this lease does not own is
    // somebody else's cluster, and placing a tenant's Sandbox into it would be
    // the worst possible outcome of a name collision.
    let owned_by_this_lease = internal_lease
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| Some(owner.uid.as_str()) == lease.uid().as_deref())
        });
    if !owned_by_this_lease {
        return Err(SandboxPlacementError::Invalid(format!(
            "ClusterLease {internal_name} exists but is not owned by SandboxLease {name}"
        )));
    }

    let internal_uid = internal_lease
        .uid()
        .ok_or_else(|| SandboxPlacementError::Invalid("child lease has no UID".into()))?;

    // Resolve the exact reciprocal binding rather than trusting `clusterName`.
    // A name alone can be reused; the binding is what pins the instance this
    // lease was actually given.
    let binding = match crate::lease_binding::resolve_lease_binding(
        &ctx.client,
        &ctx.namespace,
        &internal_name,
        &internal_uid,
        crate::lease_binding::BindingResolveMode::Access,
    )
    .await
    {
        Ok(binding) => binding,
        // Still queuing for capacity. Normal, and not an error.
        Err(error) => {
            debug!(lease = %name, error = %error, "child cluster not bound yet");
            return Ok(ChildTarget::Pending(Action::requeue(
                std::time::Duration::from_secs(15),
            )));
        }
    };

    // Record what was composed before using it. Teardown has to be able to name
    // the exact instance it must prove absent, and provenance written only
    // after a successful placement would be missing in precisely the case that
    // matters — a crash partway through.
    let provenance = child::child_provenance(
        &ctx.namespace,
        &binding.lease,
        &binding.binding.instance.name,
        &binding.binding.instance.uid,
        Some(binding.binding.instance.observed_generation),
    );
    patch_lease_status(
        ctx,
        &name,
        &serde_json::json!({
            "placement": crate::crd::ResolvedSandboxPlacement::ChildCluster {
                cluster_pool: crate::crd::SandboxObjectReference {
                    api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                    kind: "ClusterPool".into(),
                    namespace: Some(ctx.namespace.clone()),
                    name: cluster_pool.name_any(),
                    uid: cluster_pool.uid().unwrap_or_default(),
                    generation: cluster_pool.metadata.generation,
                },
            },
            "target": provenance,
        }),
    )
    .await?;

    // The kubeconfig is read into memory and never leaves it: not into status,
    // not into an API response, not into a log line. It is cluster-admin on a
    // cluster the caller must not be able to reach.
    let kubeconfig = crate::backend::read_kubeconfig_secret(
        &ctx.client,
        &binding.binding.instance.name,
        &ctx.namespace,
    )
    .await
    // The error is swallowed on purpose: a kubeconfig read failure can carry
    // the secret's own contents in its context, and this value reaches status.
    .map_err(|_| child::ChildPlacementError::ChildUnreachable {
        cluster: binding.binding.instance.name.clone(),
    })?;
    let child_client = crate::backend::virtual_client_from_kubeconfig(&kubeconfig)
        .await
        .map_err(|_| child::ChildPlacementError::ChildUnreachable {
            cluster: binding.binding.instance.name.clone(),
        })?;

    // Kobe validates the child runtime; it does not install it. Installing
    // cluster-scoped CRDs, RBAC and a webhook with cluster-admin is one of the
    // effects paused on #72, and a controller must not perform under a
    // different issue number what it was told to hold.
    child::validate_child_runtime(&child_client, &binding.binding.instance.name).await?;

    // The pool's template and warm pool have to exist inside the child; nothing
    // else reconciles them there.
    ensure_upstream_pool_objects(
        &child_client,
        CHILD_SANDBOX_NAMESPACE,
        &pool.name_any(),
        &pool.spec,
        None,
    )
    .await?;

    Ok(ChildTarget::Ready(Target {
        client: child_client,
        namespace: CHILD_SANDBOX_NAMESPACE.to_string(),
        owned: false,
    }))
}

/// Namespace inside a child cluster that holds its Sandbox objects.
///
/// Fixed, and never derived from anything a caller supplies. The child cluster
/// is exclusive to one lease, so there is nothing to disambiguate — and a
/// caller-influenced namespace would be a way to reach objects the composition
/// did not create.
const CHILD_SANDBOX_NAMESPACE: &str = "kobe-sandbox";

/// The readiness instant already persisted on a Ready lease, if any.
fn persisted_ready_at(
    status: &crate::crd::SandboxLeaseStatus,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if status.phase != crate::crd::SandboxLeasePhase::Ready {
        return None;
    }
    status
        .ready_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}

/// Write the upstream absolute shutdown time and `DeleteForeground` policy.
///
/// Fenced on `resourceVersion`: a claim that changed underneath this reconcile
/// may no longer be the one whose readiness was observed, and stamping a
/// shutdown time onto the wrong generation is how a live Sandbox gets torn
/// down early.
async fn stamp_upstream_shutdown(
    claims: &Api<DynamicObject>,
    claim: &str,
    resource_version: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), SandboxPlacementError> {
    let patch = crate::sandbox::build_sandbox_claim_lifecycle_patch(resource_version, at)?;
    claims
        .patch(claim, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

async fn patch_lease_status(
    ctx: &SandboxContext,
    lease: &str,
    status: &serde_json::Value,
) -> Result<(), SandboxPlacementError> {
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    leases
        .patch_status(
            lease,
            &PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY),
            &Patch::Merge(&serde_json::json!({ "status": status })),
        )
        .await?;
    Ok(())
}

/// Whether the upstream claim reports a Ready condition.
///
/// Pure and defensive: an unparseable or absent status is NOT ready. Treating
/// "cannot tell" as ready would start the TTL clock on a Sandbox that may never
/// serve, and hand the caller a lease that expires without ever working.
fn upstream_claim_is_ready(claim: &DynamicObject) -> bool {
    claim
        .data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(|conditions| conditions.as_array())
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                    && condition.get("status").and_then(|s| s.as_str()) == Some("True")
            })
        })
}

fn pool_error_policy(
    _pool: Arc<SandboxPool>,
    error: &SandboxPlacementError,
    _ctx: Arc<SandboxContext>,
) -> Action {
    warn!(error = %error, "SandboxPool reconcile failed");
    Action::requeue(std::time::Duration::from_secs(30))
}

fn lease_error_policy(
    _lease: Arc<SandboxLease>,
    error: &SandboxPlacementError,
    _ctx: Arc<SandboxContext>,
) -> Action {
    warn!(error = %error, reason = error.reason_code(), "SandboxLease placement failed");
    Action::requeue(std::time::Duration::from_secs(15))
}

/// Run both placement controllers until shutdown.
pub async fn run_sandbox_controller(client: Client, namespace: &str, shutdown: CancellationToken) {
    let ctx = Arc::new(SandboxContext {
        client: client.clone(),
        namespace: namespace.to_string(),
    });

    let pools: Api<SandboxPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<SandboxLease> = Api::namespaced(client, namespace);

    info!("Starting Sandbox placement controller (management)");

    let pool_ctx = ctx.clone();
    let pool_shutdown = shutdown.clone();
    let pool_loop = async move {
        Controller::new(pools, Config::default())
            .graceful_shutdown_on(async move { pool_shutdown.cancelled().await })
            .run(reconcile_pool, pool_error_policy, pool_ctx)
            .for_each(|result| async move {
                if let Err(error) = result {
                    error!(error = %error, "SandboxPool controller error");
                }
            })
            .await;
    };

    let lease_shutdown = shutdown.clone();
    let lease_loop = async move {
        Controller::new(leases, Config::default())
            .graceful_shutdown_on(async move { lease_shutdown.cancelled().await })
            .run(reconcile_lease, lease_error_policy, ctx)
            .for_each(|result| async move {
                if let Err(error) = result {
                    error!(error = %error, "SandboxLease controller error");
                }
            })
            .await;
    };

    tokio::join!(pool_loop, lease_loop);
    info!("Sandbox placement controller shut down");
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Upstream object names are DERIVED, never taken from caller input.
    ///
    /// A lease supplies only a pool reference and an alias; if either reached a
    /// name here, one caller could collide with — or impersonate — another
    /// pool's template or another lease's claim.
    #[test]
    fn upstream_names_are_derived_and_namespaced_by_kind() {
        assert_eq!(template_name("agent-small"), "kobe-agent-small");
        assert_eq!(warm_pool_name("agent-small"), "kobe-agent-small");
        assert_eq!(claim_name("sandbox-abc123"), "kobe-sandbox-abc123");
        // The `kobe-` prefix marks ownership: an object without it was not
        // created by this controller and must never be adopted.
        for derived in [
            template_name("p"),
            warm_pool_name("p"),
            claim_name("sandbox-x"),
        ] {
            assert!(derived.starts_with("kobe-"), "{derived}");
        }
    }

    fn claim_with(status: serde_json::Value) -> DynamicObject {
        let mut claim = DynamicObject::new(
            "kobe-sandbox-x",
            &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
        );
        claim.data = serde_json::json!({ "status": status });
        claim
    }

    /// "Cannot tell" must never read as ready.
    ///
    /// Readiness starts the runtime TTL. Treating an absent, malformed, or
    /// not-yet-populated status as Ready would start the clock on a Sandbox
    /// that may never serve — handing the caller a lease that expires without
    /// ever having worked, which is worse than waiting.
    #[test]
    fn only_an_explicit_ready_condition_starts_the_clock() {
        assert!(upstream_claim_is_ready(&claim_with(serde_json::json!({
            "conditions": [{ "type": "Ready", "status": "True" }]
        }))));

        // Every one of these is "not yet", not "yes".
        for not_ready in [
            serde_json::json!({}),
            serde_json::json!({ "conditions": [] }),
            serde_json::json!({ "conditions": [{ "type": "Ready", "status": "False" }] }),
            serde_json::json!({ "conditions": [{ "type": "Ready", "status": "Unknown" }] }),
            serde_json::json!({ "conditions": [{ "type": "Provisioning", "status": "True" }] }),
            // Malformed shapes must fail closed rather than panic or pass.
            serde_json::json!({ "conditions": "not-an-array" }),
            serde_json::json!({ "conditions": [{ "type": "Ready" }] }),
        ] {
            assert!(
                !upstream_claim_is_ready(&claim_with(not_ready.clone())),
                "must not read as ready: {not_ready}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Reconcile-level fixtures
    //
    // These exercise `reconcile_lease` itself rather than an extracted helper:
    // the bugs that matter here — starting a TTL that was never earned, marking
    // a lease Ready without a shutdown backstop — are bugs in the ORDER of the
    // writes, and an order bug is invisible to a test of any single step.
    // -----------------------------------------------------------------------

    use crate::crd::{
        SandboxContainerResources, SandboxContainerSpec, SandboxExecutionCanary, SandboxIsolation,
        SandboxLeaseSpec, SandboxLeaseStatus, SandboxPoolReference, SandboxPoolSpec,
        SandboxPortSpec, SandboxPrincipal, SandboxReadinessRequirements, SandboxResourceQuantity,
        SandboxTemplateSpec,
    };
    use kube::api::ObjectMeta;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NS: &str = "test-ns";
    const POOL_UID: &str = "pool-uid-1";
    const POOL_GENERATION: i64 = 3;
    const LEASE: &str = "sbx-1";

    const POOL_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agents";
    const CLAIMS_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims";
    const CLAIM_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims/kobe-sbx-1";
    const LEASE_STATUS_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1/status";

    async fn test_context() -> (Arc<SandboxContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let ctx = Arc::new(SandboxContext {
            client: crate::testutil::mock_k8s_client(&server),
            namespace: NS.to_string(),
        });
        (ctx, server)
    }

    fn quantity(cpu: &str, memory: &str, ephemeral_storage: &str) -> SandboxResourceQuantity {
        SandboxResourceQuantity {
            cpu: cpu.into(),
            memory: memory.into(),
            ephemeral_storage: ephemeral_storage.into(),
        }
    }

    pub(crate) fn management_pool(uid: &str, generation: i64) -> SandboxPool {
        SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                namespace: Some(NS.into()),
                uid: Some(uid.into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: SandboxPoolSpec {
                warm_capacity: 2,
                default_ttl: "1h".into(),
                max_ttl: "8h".into(),
                provisioning_timeout: "10m".into(),
                placement: SandboxPlacement::Management {},
                template: SandboxTemplateSpec {
                    default_container: "agent".into(),
                    containers: vec![SandboxContainerSpec {
                        name: "agent".into(),
                        image: "example.invalid/agent@sha256:abc".into(),
                        command: vec!["/agent".into()],
                        args: vec!["serve".into()],
                        resources: SandboxContainerResources {
                            requests: quantity("500m", "512Mi", "256Mi"),
                            limits: quantity("1", "1Gi", "2Gi"),
                        },
                    }],
                    exposed_ports: vec![SandboxPortSpec {
                        name: "http".into(),
                        container: "agent".into(),
                        port: 3000,
                    }],
                },
                isolation: SandboxIsolation::Gvisor {
                    runtime_class_name: "runsc".into(),
                },
                readiness: SandboxReadinessRequirements {
                    canary: SandboxExecutionCanary {
                        argv: vec!["/agent".into(), "health".into()],
                        timeout: "30s".into(),
                    },
                },
            },
            status: None,
        }
    }

    pub(crate) fn admitted_lease() -> SandboxLease {
        SandboxLease {
            metadata: ObjectMeta {
                name: Some(LEASE.into()),
                namespace: Some(NS.into()),
                uid: Some("lease-uid-1".into()),
                generation: Some(1),
                annotations: Some(
                    [(
                        SANDBOX_ADMISSION_ANNOTATION.to_string(),
                        SANDBOX_ADMISSION_ADMITTED.to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            spec: SandboxLeaseSpec {
                pool_ref: SandboxPoolReference {
                    name: "agents".into(),
                    uid: POOL_UID.into(),
                    generation: POOL_GENERATION,
                },
                ttl: "1h".into(),
                alias: None,
                requester: SandboxPrincipal {
                    provider: "oidc".into(),
                    requester_type: "user".into(),
                    issuer: "https://issuer.invalid".into(),
                    identity: "alice".into(),
                },
            },
            status: Some(SandboxLeaseStatus {
                phase: crate::crd::SandboxLeasePhase::Provisioning,
                observed_generation: Some(1),
                provisioning_deadline: Some(
                    (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                ),
                ..Default::default()
            }),
        }
    }

    /// A lease whose canary pass is already recorded.
    ///
    /// The canary execs over a websocket, which the HTTP mock cannot serve — so
    /// tests about what happens *after* readiness record the pass the same way
    /// a previous reconcile would have, which is also the production path after
    /// any controller restart.
    fn lease_past_the_canary() -> SandboxLease {
        let lease = admitted_lease();
        let conditions = with_condition(
            &lease,
            READINESS_CANARY_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "CanaryPassed",
            "recorded by an earlier reconcile",
        );
        let mut lease = lease;
        lease.status.as_mut().unwrap().conditions = conditions;
        lease
    }

    fn claim_json(status: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": AGENT_SANDBOX_API_VERSION,
            "kind": SANDBOX_CLAIM_KIND,
            "metadata": { "name": "kobe-sbx-1", "namespace": NS, "resourceVersion": "77" },
            "status": status,
        })
    }

    async fn requests_to(server: &MockServer, method: &str, target: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.method.as_str() == method && request.url.path() == target)
            .count()
    }

    /// An unready claim must not start the TTL clock.
    ///
    /// If readiness were assumed, the caller's paid runtime would begin while
    /// the Sandbox was still provisioning — or never came up at all — and the
    /// lease would be handed over already part-spent. The observable proof is
    /// that neither the upstream shutdown time nor the lease status is written.
    #[tokio::test]
    async fn an_unready_claim_starts_no_clock_and_writes_no_status() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "False" }]
                }))),
            )
            .mount(&server)
            .await;

        let action = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap();
        assert_ne!(
            action,
            Action::await_change(),
            "must come back and re-check"
        );

        assert_eq!(
            requests_to(&server, "PATCH", CLAIM_PATH).await,
            0,
            "no shutdown time may be stamped before readiness"
        );
        assert_eq!(
            requests_to(&server, "PATCH", LEASE_STATUS_PATH).await,
            0,
            "the lease must not be marked Ready before the Sandbox is"
        );
    }

    /// A lease is Ready only once its shutdown is bounded WITHOUT Kobe.
    ///
    /// The upstream `shutdownTime` is the backstop for Kobe crashing, being
    /// upgraded, or losing credentials. If the lease were marked Ready first
    /// and the stamp failed, the caller would hold a working Sandbox whose only
    /// expiry lived in a controller that is, by assumption, not running — a
    /// tenant workload that runs forever.
    #[tokio::test]
    async fn a_failed_shutdown_stamp_leaves_the_lease_unready() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "AlreadyExists"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "True" }]
                }))),
            )
            .mount(&server)
            .await;
        // The stamp fails — a conflict, an outage, anything.
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 500
            })))
            .mount(&server)
            .await;

        let result = reconcile_lease(Arc::new(lease_past_the_canary()), ctx).await;
        assert!(result.is_err(), "a failed backstop must fail the reconcile");
        assert_eq!(
            requests_to(&server, "PATCH", LEASE_STATUS_PATH).await,
            0,
            "the lease must not be Ready while its shutdown is unbounded"
        );
    }

    /// A pool that is not the one admission saw must not be placed against.
    ///
    /// `poolRef` carries a UID because a name is not an identity: delete and
    /// recreate `agents` with a different image, RuntimeClass or placement and
    /// the name still resolves. Quota, isolation and template were all decided
    /// against the admitted spec, so placing against a new object runs the
    /// caller under configuration nobody admitted them to.
    #[tokio::test]
    async fn a_recreated_pool_is_refused_before_anything_is_placed() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool("a-different-pool-uid", POOL_GENERATION)),
            )
            .mount(&server)
            .await;

        let error = reconcile_lease(Arc::new(admitted_lease()), ctx.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("uid")),
            "expected a UID fence failure, got: {error}"
        );
        assert_eq!(
            requests_to(&server, "POST", CLAIMS_PATH).await,
            0,
            "nothing may be placed against a pool the lease was not admitted against"
        );
    }

    /// An edited pool is refused for the same reason a recreated one is.
    ///
    /// Generation moves on any spec change — a raised warm capacity is
    /// harmless, a swapped image or a downgraded isolation tier is not, and
    /// placement cannot tell which happened.
    #[tokio::test]
    async fn a_mutated_pool_generation_is_refused() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION + 1)),
            )
            .mount(&server)
            .await;

        let error = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("generation")),
            "expected a generation fence failure, got: {error}"
        );
    }

    /// An unadmitted lease is not placed, and the check costs no API call.
    ///
    /// A `pending` lease exists before its quota reservation commits. Placing
    /// one creates real capacity that admission never authorised — the reason
    /// the annotation exists at all.
    #[tokio::test]
    async fn a_pending_lease_is_never_placed() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        lease.metadata.annotations = Some(
            [(
                SANDBOX_ADMISSION_ANNOTATION.to_string(),
                "pending".to_string(),
            )]
            .into_iter()
            .collect(),
        );

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "placement must decline before it touches the API at all"
        );
    }

    /// A Sandbox upstream calls Ready is not yet a Sandbox that works.
    ///
    /// Upstream's condition is about the container. A Pod whose agent
    /// crash-looped, whose weights failed to mount, or which is wedged on a
    /// lock satisfies it — and the moment Kobe believes it, the caller's paid
    /// runtime TTL starts on something that cannot serve. Until the pool's own
    /// canary passes, nothing is written: no clock, no shutdown time, no Ready.
    #[tokio::test]
    async fn upstream_ready_alone_does_not_start_the_clock() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        // Upstream says Ready — and says nothing about the agent inside.
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "True" }],
                    "sandbox": { "name": "sbx" },
                }))),
            )
            .mount(&server)
            .await;
        // The Sandbox object is unreachable, so the canary cannot run. That is
        // absence of evidence, and absence of evidence is not readiness.
        Mock::given(method("GET"))
            .and(path(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes/sbx",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap();
        assert_ne!(
            action,
            Action::await_change(),
            "the canary must be re-tried"
        );

        assert_eq!(
            requests_to(&server, "PATCH", CLAIM_PATH).await,
            0,
            "no shutdown time until the workload itself answers"
        );
        assert_eq!(
            requests_to(&server, "PATCH", LEASE_STATUS_PATH).await,
            0,
            "an unproven Sandbox must not be marked Ready"
        );
    }

    /// A recorded canary pass is not re-run.
    ///
    /// The canary executes an administrator-declared command inside a live
    /// tenant workload. Repeating it on every requeue would turn a health check
    /// into a recurring side effect on somebody else's Sandbox — and a
    /// controller that restarted after a pass must not run it again either,
    /// which is why the record lives on the lease rather than in memory.
    #[test]
    fn a_recorded_canary_pass_is_durable() {
        use crate::crd::SandboxConditionStatus;

        assert!(!canary_already_passed(&Default::default()));

        let lease = lease_past_the_canary();
        assert!(canary_already_passed(lease.status.as_ref().unwrap()));

        // A recorded FAILURE is not a pass. Only True counts.
        let mut failed = admitted_lease();
        failed.status.as_mut().unwrap().conditions = with_condition(
            &failed,
            READINESS_CANARY_CONDITION,
            SandboxConditionStatus::False,
            "CanaryFailed",
            "exited non-zero",
        );
        assert!(!canary_already_passed(failed.status.as_ref().unwrap()));

        // Nor is somebody else's condition.
        let mut unrelated = admitted_lease();
        unrelated.status.as_mut().unwrap().conditions = with_condition(
            &unrelated,
            "CleanupVerified",
            SandboxConditionStatus::True,
            "TeardownVerified",
            "gone",
        );
        assert!(!canary_already_passed(unrelated.status.as_ref().unwrap()));
    }

    // -----------------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------------

    const RESERVATIONS_PATH: &str = "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases";

    fn releasing_lease(phase: crate::crd::SandboxLeasePhase) -> SandboxLease {
        let mut lease = admitted_lease();
        lease.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.to_string(),
            chrono::Utc::now().to_rfc3339(),
        );
        lease.status.as_mut().unwrap().phase = phase;
        lease
    }

    fn phase_of(request: &wiremock::Request) -> Option<String> {
        let body: serde_json::Value = serde_json::from_slice(&request.body).ok()?;
        body.get("status")?
            .get("phase")?
            .as_str()
            .map(str::to_string)
    }

    async fn recorded_phases(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .filter_map(phase_of)
            .collect()
    }

    /// Mount the status PATCH and the reservation list/delete a teardown needs.
    async fn mount_teardown_scaffolding(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "SandboxLease",
                "metadata": { "name": LEASE, "namespace": NS },
                "spec": admitted_lease().spec,
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(RESERVATIONS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "LeaseList",
                "metadata": { "resourceVersion": "1" },
                "items": [{
                    "apiVersion": "coordination.k8s.io/v1",
                    "kind": "Lease",
                    "metadata": {
                        "name": "sbx-quota-abc-0",
                        "namespace": NS,
                        "uid": "reservation-uid-1",
                    },
                }],
            })))
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": { "name": "sbx-quota-abc-0", "namespace": NS },
            })))
            .mount(server)
            .await;
    }

    /// Capacity comes back only against proof that the Sandbox is gone.
    ///
    /// The quota slot is what stops a pool being over-subscribed. Returning it
    /// while the workload is still running would let the next caller be placed
    /// onto capacity that is still occupied — so the reservation is released
    /// only after the claim is observed absent, never merely after a DELETE was
    /// accepted.
    #[tokio::test]
    async fn capacity_returns_only_once_the_claim_is_proven_gone() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Ready);
        reconcile_lease(Arc::new(lease), ctx).await.unwrap();

        assert_eq!(
            recorded_phases(&server).await,
            vec!["Releasing".to_string(), "Released".to_string()],
            "intent must be visible in status before the terminal write"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            1,
            "the quota slot must be handed back"
        );
    }

    /// A claim that is still there is "not yet", not "gone" and not "broken".
    ///
    /// Foreground deletion takes as long as the Sandbox takes to stop. If that
    /// window released the quota slot, a pool would be over-subscribed for
    /// exactly as long as teardown takes — the busiest possible moment. The
    /// lease stays in Releasing and keeps holding its capacity.
    #[tokio::test]
    async fn a_claim_still_being_deleted_holds_its_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        // Present, with a deletionTimestamp: accepted, not finished.
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": SANDBOX_CLAIM_KIND,
                "metadata": {
                    "name": "kobe-sbx-1",
                    "namespace": NS,
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                },
            })))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Ready);
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_ne!(
            action,
            Action::await_change(),
            "teardown must be re-checked"
        );

        assert_eq!(
            recorded_phases(&server).await,
            vec!["Releasing".to_string()],
            "no terminal phase while the Sandbox may still be running"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            0,
            "capacity must not be handed back while the claim is still present"
        );
    }

    /// Uncertain teardown quarantines; it never releases.
    ///
    /// If Kobe is not permitted to look, no amount of retrying produces the
    /// evidence. Under-counting a pool is something an operator can see and
    /// fix; a Sandbox quietly double-booked onto released capacity is not.
    #[tokio::test]
    async fn an_unverifiable_teardown_quarantines_rather_than_releasing() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 403, "reason": "Forbidden"
            })))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Ready);
        reconcile_lease(Arc::new(lease), ctx).await.unwrap();

        let phases = recorded_phases(&server).await;
        assert_eq!(
            phases.last().map(String::as_str),
            Some("Quarantined"),
            "expected quarantine, got {phases:?}"
        );
        assert!(
            !phases
                .iter()
                .any(|phase| phase == "Released" || phase == "Expired"),
            "an unproven teardown must never reach a clean terminal phase"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            0,
            "capacity is withheld precisely because teardown is unproven"
        );
    }

    /// An elapsed TTL ends as `Expired`, not `Released`.
    ///
    /// The upstream shutdown backstop stops the Sandbox, but nothing upstream
    /// knows about Kobe's quota ledger — without this path every expiry would
    /// leak a slot. The phases are distinct because giving capacity back and
    /// having it taken are different events to anyone reading the history.
    #[tokio::test]
    async fn an_elapsed_ttl_expires_the_lease_and_frees_its_slot() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Ready;
        status.expires_at = Some((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());

        reconcile_lease(Arc::new(lease), ctx).await.unwrap();

        assert_eq!(
            recorded_phases(&server).await,
            vec!["Releasing".to_string(), "Expired".to_string()]
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            1
        );
    }

    /// A lease that is not being torn down is placed, and one that is, is not.
    ///
    /// Terminal leases are excluded outright: re-running teardown against a
    /// name that may since have been reused would act on somebody else's
    /// footprint.
    #[test]
    fn only_live_leases_are_torn_down_and_only_once() {
        use crate::crd::SandboxLeasePhase;

        assert_eq!(
            release_reason(&admitted_lease()),
            None,
            "a live lease is placed"
        );

        assert_eq!(
            release_reason(&releasing_lease(SandboxLeasePhase::Ready)),
            Some(ReleaseReason::Requested)
        );
        assert_eq!(
            release_reason(&releasing_lease(SandboxLeasePhase::Releasing)),
            Some(ReleaseReason::InProgress),
            "an interrupted teardown resumes"
        );

        for terminal in [
            SandboxLeasePhase::Released,
            SandboxLeasePhase::Expired,
            SandboxLeasePhase::Quarantined,
        ] {
            assert_eq!(
                release_reason(&releasing_lease(terminal)),
                None,
                "{terminal} is terminal and must not be torn down again"
            );
        }

        // Quarantine is deliberately terminal here: exiting it is an operator
        // decision backed by evidence, not something a requeue may do.
        assert_eq!(
            ReleaseReason::Expired.terminal_phase(),
            SandboxLeasePhase::Expired
        );
        assert_eq!(
            ReleaseReason::Requested.terminal_phase(),
            SandboxLeasePhase::Released
        );
    }

    /// An unparseable expiry must not be read as expired.
    ///
    /// Both readings are wrong in some sense, but they are not equally wrong:
    /// treating garbage as "expired" destroys a workload the caller is still
    /// using, while treating it as "not expired" leaves a visible lease an
    /// operator can act on.
    #[test]
    fn a_malformed_expiry_does_not_destroy_a_live_lease() {
        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().phase = crate::crd::SandboxLeasePhase::Ready;

        for value in ["", "not-a-timestamp", "0", "1970-13-45T99:99:99Z"] {
            lease.status.as_mut().unwrap().expires_at = Some(value.to_string());
            assert_eq!(release_reason(&lease), None, "must not expire on {value:?}");
        }

        lease.status.as_mut().unwrap().expires_at =
            Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        assert_eq!(
            release_reason(&lease),
            None,
            "a future expiry is not expiry"
        );
    }

    /// A cleanup condition must not silently drop the others.
    ///
    /// Status is written with a JSON merge patch, which REPLACES arrays. A
    /// patch carrying one condition would erase every other condition on the
    /// lease — and conditions are exactly what an operator reads to work out
    /// what happened.
    #[test]
    fn writing_the_cleanup_condition_preserves_the_others() {
        use crate::crd::SandboxConditionStatus;

        let mut lease = admitted_lease();
        let unrelated = crate::crd::SandboxCondition {
            condition_type: "Admitted".into(),
            status: SandboxConditionStatus::True,
            reason: "QuotaCommitted".into(),
            message: "reserved".into(),
            observed_generation: Some(1),
            last_transition_time: Some("2026-01-01T00:00:00Z".into()),
        };
        lease.status.as_mut().unwrap().conditions = vec![unrelated.clone()];

        let conditions = with_cleanup_condition(
            &lease,
            SandboxConditionStatus::True,
            "TeardownVerified",
            "ok",
        );
        assert!(
            conditions.contains(&unrelated),
            "unrelated conditions survive"
        );
        assert_eq!(conditions.len(), 2);

        // Rewriting an unchanged condition must not restamp its transition
        // time: a timestamp that moved on every requeue would make a condition
        // stable for an hour look like it just flipped.
        lease.status.as_mut().unwrap().conditions = conditions.clone();
        let again = with_cleanup_condition(
            &lease,
            SandboxConditionStatus::True,
            "TeardownVerified",
            "ok",
        );
        assert_eq!(
            again.len(),
            2,
            "the condition is upserted, never duplicated"
        );
        let before = conditions
            .iter()
            .find(|c| c.condition_type == CLEANUP_VERIFIED_CONDITION)
            .unwrap();
        let after = again
            .iter()
            .find(|c| c.condition_type == CLEANUP_VERIFIED_CONDITION)
            .unwrap();
        assert_eq!(before.last_transition_time, after.last_transition_time);

        // A real flip does restamp.
        let flipped = with_cleanup_condition(
            &lease,
            SandboxConditionStatus::False,
            "Unverifiable",
            "held",
        );
        let flipped = flipped
            .iter()
            .find(|c| c.condition_type == CLEANUP_VERIFIED_CONDITION)
            .unwrap();
        assert_ne!(flipped.last_transition_time, after.last_transition_time);
    }

    // -----------------------------------------------------------------------
    // Child composition
    // -----------------------------------------------------------------------

    fn child_placed_lease(cluster_lease_uid: &str) -> SandboxLease {
        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Ready;
        status.placement = Some(crate::crd::ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: crate::crd::SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterPool".into(),
                namespace: Some(NS.into()),
                name: "children".into(),
                uid: "cluster-pool-uid".into(),
                generation: Some(1),
            },
        });
        status.target = Some(crate::crd::SandboxTargetProvenance {
            namespace: NS.into(),
            child_cluster_lease: Some(crate::crd::SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterLease".into(),
                namespace: Some(NS.into()),
                name: "kobe-sbx-sbx-1".into(),
                uid: cluster_lease_uid.into(),
                generation: Some(1),
            }),
            child_cluster_instance: None,
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
        });
        lease.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.to_string(),
            chrono::Utc::now().to_rfc3339(),
        );
        lease
    }

    const CLUSTER_LEASE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/kobe-sbx-sbx-1";

    /// A child-placed lease must never be released by a claim delete here.
    ///
    /// Its claim lives in the child cluster, so deleting it against the
    /// management cluster 404s — and a 404 is precisely what this path treats
    /// as proof of absence. The quota slot would be handed to the next caller
    /// while the previous tenant's Sandbox was still running in a cluster
    /// nobody had touched. This is the single most dangerous confusion the two
    /// placements can have, so it is asserted directly.
    #[tokio::test]
    async fn a_child_lease_is_never_released_by_deleting_a_management_claim() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        // The child cluster lease is still there: the tenant's cluster, and
        // their Sandbox inside it, are still running.
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "kobe-sbx-sbx-1",
                    "namespace": NS,
                    "uid": "child-lease-uid",
                },
                "spec": { "poolRef": "children", "ttl": "2h",
                          "requester": { "type": "kobe:sandbox-composition", "identity": "kobe-operator" } },
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "kobe-sbx-sbx-1", "namespace": NS },
            })))
            .mount(&server)
            .await;

        reconcile_lease(Arc::new(child_placed_lease("child-lease-uid")), ctx)
            .await
            .unwrap();

        assert_eq!(
            requests_to(&server, "DELETE", CLAIM_PATH).await,
            0,
            "the claim is in the child cluster; nothing here may stand in for it"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            0,
            "capacity must not return while the tenant's cluster is still up"
        );
        let phases = recorded_phases(&server).await;
        assert_eq!(phases, vec!["Releasing".to_string()]);
    }

    /// Teardown acts on the recorded UID, not the recorded name.
    ///
    /// If the composed cluster lease is gone and a DIFFERENT object now holds
    /// its name, that object belongs to a later Sandbox. Deleting it would
    /// destroy a running tenant's cluster; treating its presence as "ours is
    /// still up" would strand this lease forever. Neither: this lease's
    /// cluster is provably not there, so the release completes.
    #[tokio::test]
    async fn a_name_reused_by_a_later_composition_is_not_this_leases_cluster() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "kobe-sbx-sbx-1",
                    "namespace": NS,
                    // Somebody else's composition, under a reused name.
                    "uid": "a-completely-different-uid",
                },
                "spec": { "poolRef": "children", "ttl": "2h",
                          "requester": { "type": "kobe:sandbox-composition", "identity": "kobe-operator" } },
            })))
            .mount(&server)
            .await;

        reconcile_lease(Arc::new(child_placed_lease("child-lease-uid")), ctx)
            .await
            .unwrap();

        assert_eq!(
            requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await,
            0,
            "a cluster this lease does not own must never be destroyed"
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released"),
            "this lease's own cluster is provably absent"
        );
    }

    /// If Kobe cannot tell whether the tenant's cluster is still running, it
    /// withholds the capacity rather than guessing.
    #[tokio::test]
    async fn an_unreadable_child_cluster_quarantines() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 403, "reason": "Forbidden"
            })))
            .mount(&server)
            .await;

        reconcile_lease(Arc::new(child_placed_lease("child-lease-uid")), ctx)
            .await
            .unwrap();

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            0
        );
    }

    /// A lease released before it ever got a cluster has nothing to prove.
    ///
    /// Requiring evidence of a footprint that was never created would strand
    /// the quota slot of every caller who cancelled while queuing — the most
    /// common cancellation there is.
    #[tokio::test]
    async fn a_composition_that_never_happened_releases_cleanly() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;

        let mut lease = child_placed_lease("child-lease-uid");
        // Placement is recorded, but no cluster was ever composed.
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .child_cluster_lease = None;

        reconcile_lease(Arc::new(lease), ctx).await.unwrap();

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/sbx-quota-abc-0")
            )
            .await,
            1,
            "the slot it was holding must come back"
        );
    }

    /// The pinned upstream version must match what #72 validates at startup.
    ///
    /// If these drifted, the operator would refuse to start against a runtime
    /// it then wrote to anyway, or worse, accept one and write objects the
    /// installed controller does not understand.
    #[test]
    fn the_written_api_version_matches_the_validated_one() {
        let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
        assert_eq!(resource.api_version, AGENT_SANDBOX_API_VERSION);
        assert_eq!(
            resource.api_version,
            crate::sandbox_runtime::REQUIRED_AGENT_SANDBOX_API_VERSION,
            "placement must write the version #72 validates"
        );
    }
}
