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
    Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams, Preconditions,
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
/// been satisfied by whoever won it. Terminal leases are inert: once cleanup
/// has reached `Released`, `Expired`, or `Quarantined`, reconciliation must not
/// resolve a pool or recreate any part of the workload.
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

    if matches!(
        lease.status.as_ref().map(|status| status.phase),
        Some(
            crate::crd::SandboxLeasePhase::Released
                | crate::crd::SandboxLeasePhase::Expired
                | crate::crd::SandboxLeasePhase::Quarantined
        )
    ) {
        debug!(lease = %name, "terminal Sandbox lease is inert");
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

    // Persist resolved management placement before creating any footprint.
    // Access and teardown must never infer a backend from the current pool
    // spec, and a later status write must not be able to retarget this lease.
    // Returning after the fenced write also makes the durable record precede
    // the first SandboxClaim creation rather than merely racing it.
    if matches!(pool.spec.placement, SandboxPlacement::Management {}) {
        let mut status = lease.status.clone().unwrap_or_default();
        let placement = crate::sandbox::record_placement_once(
            status.placement.as_ref(),
            crate::crd::ResolvedSandboxPlacement::Management {},
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        if status.placement.as_ref() != Some(&placement) {
            status.placement = Some(placement);
            if patch_lease_status_fenced(&ctx, &lease, &status).await? {
                info!(lease = %name, "recorded management Sandbox placement");
            } else {
                debug!(lease = %name, "management placement write lost a status race");
            }
            return Ok(Action::await_change());
        }
    }

    // Start the setup clock before either placement can wait. Management may
    // wait for its upstream Template/WarmPool and child placement may wait for
    // a whole cluster to bind; both are provisioning work and must be covered
    // by the administrator's `provisioningTimeout`.
    let mut status = lease.status.clone().unwrap_or_default();
    let observed_generation = lease.metadata.generation.unwrap_or_default();
    if status.phase == crate::crd::SandboxLeasePhase::Pending {
        let accepted_at = lease
            .metadata
            .creation_timestamp
            .as_ref()
            .and_then(|timestamp| {
                chrono::DateTime::parse_from_rfc3339(&timestamp.0.to_string())
                    .ok()
                    .map(|parsed| parsed.with_timezone(&chrono::Utc))
            })
            .ok_or_else(|| {
                SandboxPlacementError::Invalid(format!(
                    "SandboxLease {name} has no API-server creation timestamp"
                ))
            })?;
        let provisioning_timeout = crate::pool::parse_duration(&pool.spec.provisioning_timeout)
            .ok_or_else(|| {
                SandboxPlacementError::Invalid(format!(
                    "SandboxPool {} has an invalid provisioningTimeout",
                    pool.name_any()
                ))
            })?;
        let next = crate::sandbox::begin_sandbox_provisioning(
            &status,
            observed_generation,
            accepted_at,
            provisioning_timeout,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        if patch_lease_status_fenced(&ctx, &lease, &next).await? {
            info!(lease = %name, "Sandbox lease is provisioning");
        } else {
            debug!(lease = %name, "Provisioning checkpoint lost a status race");
        }
        return Ok(Action::await_change());
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

    if target.owned {
        let Some(proposed) = observed_management_pool_provenance(&ctx, &pool, &status).await?
        else {
            debug!(lease = %name, "management Sandbox pool objects not ready");
            return Ok(Action::requeue(std::time::Duration::from_secs(10)));
        };
        let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let merged = crate::sandbox::merge_target_provenance(
            status.target.as_ref(),
            proposed,
            placement,
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        if status.target.as_ref() != Some(&merged) {
            status.target = Some(merged);
            if patch_lease_status_fenced(&ctx, &lease, &status).await? {
                debug!(lease = %name, "recorded management pool provenance");
            } else {
                debug!(lease = %name, "management pool provenance write lost a status race");
            }
            return Ok(Action::await_change());
        }
    }

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
    let recorded_claim = status
        .target
        .as_ref()
        .and_then(|target| target.sandbox_claim.as_ref())
        .cloned();
    if recorded_claim.is_none() {
        match claims.create(&PostParams::default(), &claim).await {
            Ok(_) => info!(lease = %name, "created upstream SandboxClaim"),
            // A controller may have crashed after CREATE and before recording
            // the returned UID. GET plus the owner fence below recovers only
            // that exact lease-owned allocation.
            Err(kube::Error::Api(error)) if error.code == 409 => {
                debug!(lease = %name, "claim already exists")
            }
            Err(error) => return Err(error.into()),
        }
    }

    // The claim exists. Everything below turns "an object was created" into a
    // lease that is actually usable and actually bounded.
    let claim = claims.get(&claim_name(&name)).await?;
    if let Some(recorded) = recorded_claim.as_ref() {
        require_exact_reference(
            recorded,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &target.namespace,
            &claim_name(&name),
            &claim,
        )?;
    }
    if target.owned {
        let lease_uid = lease.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no UID to fence its claim"
            ))
        })?;
        if !is_controlled_by(
            &claim,
            "kobe.kunobi.ninja/v1alpha1",
            "SandboxLease",
            &name,
            &lease_uid,
        ) {
            return Err(SandboxPlacementError::Invalid(format!(
                "SandboxClaim {} is not controlled by SandboxLease {name} uid {lease_uid}",
                claim.name_any()
            )));
        }
        let mut proposed = status.target.clone().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "lease {name} has no management pool provenance before claim creation"
            ))
        })?;
        proposed.sandbox_claim = Some(target_reference(
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &target.namespace,
            &claim,
        )?);
        let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let merged = crate::sandbox::merge_target_provenance(
            status.target.as_ref(),
            proposed,
            placement,
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        if status.target.as_ref() != Some(&merged) {
            status.target = Some(merged);
            if patch_lease_status_fenced(&ctx, &lease, &status).await? {
                debug!(lease = %name, "recorded management claim provenance");
            } else {
                debug!(lease = %name, "management claim provenance write lost a status race");
            }
            return Ok(Action::await_change());
        }
    }
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
    // NOT a fresh read of `lease.status`: that would shadow the Provisioning
    // transition written above and hand every step below the stale `Pending`
    // copy, which is precisely how the missing transition stayed invisible.
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
        status.conditions = with_condition_for_status(
            &status,
            lease.metadata.generation,
            READINESS_CANARY_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "CanaryPassed",
            "Pool readiness canary exited zero inside the Sandbox",
        );
        if patch_lease_status_fenced(&ctx, &lease, &status).await? {
            debug!(lease = %name, "readiness canary passed");
        } else {
            warn!(lease = %name, "canary passed but its status checkpoint lost a race");
        }
        return Ok(Action::await_change());
    }

    // Record exactly which objects this lease resolved to. #81 routes every
    // Sandbox operation through these UIDs rather than through names, because
    // a name reused between placement and access would send a caller's exec
    // into somebody else's Pod. Recorded here, where the objects have just
    // been observed, rather than looked up again at access time.
    if target.owned && !management_provenance_is_complete(&status) {
        let provenance = match observed_provenance(&target, &claim, &status).await {
            Ok(Some(provenance)) => provenance,
            Ok(None) => {
                debug!(lease = %name, "management Sandbox target provenance not ready");
                return Ok(Action::requeue(std::time::Duration::from_secs(10)));
            }
            Err(error) => return Err(SandboxPlacementError::Invalid(error)),
        };
        let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let merged = crate::sandbox::merge_target_provenance(
            status.target.as_ref(),
            provenance,
            placement,
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        status.target = Some(merged);
        if patch_lease_status_fenced(&ctx, &lease, &status).await? {
            debug!(lease = %name, "recorded management Sandbox and Pod provenance");
        } else {
            debug!(lease = %name, "management target provenance write lost a status race");
        }
        return Ok(Action::await_change());
    } else if !target.owned {
        let provenance = match observed_provenance(&target, &claim, &status).await {
            Ok(Some(provenance)) => provenance,
            Ok(None) => {
                debug!(lease = %name, "child Sandbox target provenance not ready");
                return Ok(Action::requeue(std::time::Duration::from_secs(10)));
            }
            Err(error) => return Err(SandboxPlacementError::Invalid(error)),
        };
        let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let merged = crate::sandbox::merge_target_provenance(
            status.target.as_ref(),
            provenance,
            placement,
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        if status.target.as_ref() != Some(&merged) {
            status.target = Some(merged);
            if patch_lease_status_fenced(&ctx, &lease, &status).await? {
                debug!(lease = %name, "recorded child Sandbox and Pod provenance");
            } else {
                debug!(lease = %name, "child target provenance write lost a status race");
            }
            return Ok(Action::await_change());
        }
    }

    if target.owned && !management_provenance_is_complete(&status) {
        return Ok(Action::requeue(std::time::Duration::from_secs(10)));
    }

    // Runtime TTL starts HERE, at observed readiness — not when the request
    // arrived. A caller must not be billed for however long placement and
    // provisioning took, which is the whole reason the provisioning deadline
    // is a separate bound.
    let runtime_ttl = crate::pool::parse_duration(&lease.spec.ttl).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("lease {name} has an invalid TTL"))
    })?;
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
            // Checkpoint phase + cause first. A stale reconcile must not stamp
            // or tear down anything before it proves it can still update this
            // exact SandboxLease UID/resourceVersion.
            return drive_release(&lease, &ctx, ReleaseReason::ProvisioningDeadline).await;
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
    if !patch_lease_status_fenced(&ctx, &lease, &next_status).await? {
        debug!(lease = %name, "Ready write lost a status race");
        return Ok(Action::await_change());
    }
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
    /// reservations — an expiry that only fired upstream would leak a slot.
    RuntimeTtl,
    /// Setup did not finish within the pool's provisioning bound.
    ProvisioningDeadline,
    /// Legacy or corrupt Releasing state without the atomic cause checkpoint.
    /// This is quarantined before any destructive action.
    MissingCause,
}

impl ReleaseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "ReleaseRequested",
            Self::RuntimeTtl => "RuntimeTtlElapsed",
            Self::ProvisioningDeadline => "ProvisioningDeadlineElapsed",
            Self::MissingCause => "ReleaseCauseMissing",
        }
    }

    fn persisted_cause(self) -> Option<crate::crd::SandboxReleaseCause> {
        match self {
            Self::Requested => Some(crate::crd::SandboxReleaseCause::Requested),
            Self::RuntimeTtl => Some(crate::crd::SandboxReleaseCause::RuntimeTtl),
            Self::ProvisioningDeadline => {
                Some(crate::crd::SandboxReleaseCause::ProvisioningDeadline)
            }
            Self::MissingCause => None,
        }
    }

    fn from_persisted(cause: crate::crd::SandboxReleaseCause) -> Self {
        match cause {
            crate::crd::SandboxReleaseCause::Requested => Self::Requested,
            crate::crd::SandboxReleaseCause::RuntimeTtl => Self::RuntimeTtl,
            crate::crd::SandboxReleaseCause::ProvisioningDeadline => Self::ProvisioningDeadline,
        }
    }

    /// The terminal phase a verified teardown reaches.
    ///
    /// `Released` and `Expired` are both clean, but they are not
    /// interchangeable: billing, quota reporting and support all care whether
    /// a caller gave capacity back or had it taken.
    fn terminal_phase(self) -> crate::crd::SandboxLeasePhase {
        match self {
            Self::RuntimeTtl | Self::ProvisioningDeadline => crate::crd::SandboxLeasePhase::Expired,
            Self::Requested => crate::crd::SandboxLeasePhase::Released,
            Self::MissingCause => unreachable!("missing release cause must quarantine"),
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
        _ => {}
    }

    // Once written, the first cause wins forever. In particular, a late DELETE
    // cannot turn an expiry already in Releasing into a caller-requested
    // release and change its terminal accounting outcome.
    if let Some(cause) = status.release_cause {
        return Some(ReleaseReason::from_persisted(cause));
    }

    let now = chrono::Utc::now();
    // An unparseable deadline is NOT treated as elapsed. Deleting a live
    // workload because a timestamp failed to parse is the more damaging
    // reading of the same uncertainty; the lease stays put and stays visible.
    let runtime_deadline = status
        .ready_at
        .is_some()
        .then(|| {
            status
                .expires_at
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .filter(|deadline| now >= *deadline)
        })
        .flatten();
    let provisioning_deadline = status
        .ready_at
        .is_none()
        .then(|| {
            status
                .provisioning_deadline
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .filter(|deadline| now >= *deadline)
        })
        .flatten();
    let expiry = match (runtime_deadline, provisioning_deadline) {
        (Some(runtime), Some(provisioning)) if runtime <= provisioning => {
            Some((runtime, ReleaseReason::RuntimeTtl))
        }
        (Some(_), Some(provisioning)) => Some((provisioning, ReleaseReason::ProvisioningDeadline)),
        (Some(runtime), None) => Some((runtime, ReleaseReason::RuntimeTtl)),
        (None, Some(provisioning)) => Some((provisioning, ReleaseReason::ProvisioningDeadline)),
        (None, None) => None,
    };

    if let Some(requested) = lease
        .annotations()
        .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
    {
        let requested_at = chrono::DateTime::parse_from_rfc3339(requested).ok();
        // The annotation is server-owned. If its timestamp is corrupt, honour
        // a provably earlier elapsed deadline; otherwise preserve the request
        // rather than keeping a caller's workload alive on malformed metadata.
        if expiry.as_ref().is_none_or(|(deadline, _)| {
            requested_at.is_some_and(|requested| requested <= *deadline)
        }) {
            return Some(ReleaseReason::Requested);
        }
        if let Some((_, reason)) = expiry {
            return Some(reason);
        }
    }

    if let Some((_, reason)) = expiry {
        return Some(reason);
    }

    // Already releasing without a surviving request/deadline signal: teardown
    // was interrupted and is not proven done. The two durable signals above
    // preserve the original terminal outcome across the phase checkpoint.
    (status.phase == crate::crd::SandboxLeasePhase::Releasing)
        .then_some(ReleaseReason::MissingCause)
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

    // New controllers always persist phase and cause atomically. A legacy or
    // corrupt Releasing object without any surviving durable signal cannot be
    // assigned a clean outcome safely, so hold its capacity for operator
    // review instead of inventing "Requested".
    if reason == ReleaseReason::MissingCause && status.release_cause.is_none() {
        return quarantine_lease(lease, ctx, "release_cause_missing").await;
    }

    // Make the intent visible in status first. Until the phase moves, capacity
    // accounting and the API both still read this as a live lease, and a
    // teardown that crashed midway would look like one too.
    let proposed_cause = reason.persisted_cause();
    if let (Some(current), Some(proposed)) = (status.release_cause, proposed_cause)
        && current != proposed
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {name} releaseCause is immutable ({current:?} cannot become {proposed:?})"
        )));
    }
    if status.phase != SandboxLeasePhase::Releasing
        || (status.release_cause.is_none() && proposed_cause.is_some())
    {
        let phase = crate::sandbox::transition_sandbox_phase(
            status.phase,
            SandboxLeasePhase::Releasing,
            false,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let mut next = status.clone();
        next.phase = phase;
        next.release_cause = proposed_cause;
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            info!(lease = %name, reason = reason.as_str(), "releasing Sandbox lease");
        } else {
            debug!(lease = %name, "Releasing checkpoint lost a status race");
        }
        return Ok(Action::await_change());
    }

    // Footprint absence is a durable linearization point. Once it wins its
    // fenced race against quarantine, every retry skips external teardown
    // checks and completes only the idempotent reservation/terminal tail.
    if footprint_absence_proven(&status) {
        return finish_release(lease, ctx, reason).await;
    }

    // A child-placed lease is torn down by destroying its cluster, not by
    // deleting a claim from here.
    //
    // This is not an optimisation. The claim lives in the child cluster, so
    // deleting it against the management cluster would 404 — and a 404 is
    // exactly what this path treats as proof of absence. The quota slot would
    // be handed to the next caller while the previous tenant's Sandbox was
    // still running in a cluster nobody had touched.
    if is_child_placed(lease, ctx).await {
        return release_child_composition(lease, ctx, reason).await;
    }

    let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
    let claims: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &resource);
    let claim = claim_name(&name);
    let recorded_claim = status
        .target
        .as_ref()
        .and_then(|target| target.sandbox_claim.as_ref())
        .cloned();

    // Older objects and create-before-checkpoint crashes may have a live claim
    // but no recorded UID. Recover only an object controlled by this exact
    // lease, persist its identity, and end the pass before deleting anything.
    let recorded_claim = if let Some(recorded) = recorded_claim {
        recorded
    } else {
        let observed = match claims.get(&claim).await {
            Ok(observed) => observed,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return finish_release(lease, ctx, reason).await;
            }
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                return quarantine_lease(lease, ctx, "claim_absence_unverifiable").await;
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not recover upstream claim identity");
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
        };
        let lease_uid = lease.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no UID to recover claim provenance"
            ))
        })?;
        if !is_controlled_by(
            &observed,
            "kobe.kunobi.ninja/v1alpha1",
            "SandboxLease",
            &name,
            &lease_uid,
        ) {
            return quarantine_lease(lease, ctx, "claim_identity_unverifiable").await;
        }
        let reference = target_reference(
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &ctx.namespace,
            &observed,
        )?;
        let mut next = status.clone();
        let target = next
            .target
            .get_or_insert_with(|| crate::crd::SandboxTargetProvenance {
                namespace: ctx.namespace.clone(),
                child_cluster_lease: None,
                child_cluster_instance: None,
                sandbox_template: None,
                sandbox_warm_pool: None,
                sandbox_claim: None,
                sandbox: None,
                pod: None,
            });
        if target.namespace != ctx.namespace {
            return quarantine_lease(lease, ctx, "claim_namespace_changed").await;
        }
        target.sandbox_claim = Some(reference);
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            info!(lease = %name, "recovered management claim provenance before teardown");
        } else {
            debug!(lease = %name, "claim recovery checkpoint lost a status race");
        }
        return Ok(Action::await_change());
    };

    if recorded_claim.api_version != AGENT_SANDBOX_API_VERSION
        || recorded_claim.kind != SANDBOX_CLAIM_KIND
        || recorded_claim.namespace.as_deref() != Some(ctx.namespace.as_str())
        || recorded_claim.name != claim
        || recorded_claim.uid.is_empty()
    {
        return quarantine_lease(lease, ctx, "claim_provenance_invalid").await;
    }

    // Foreground propagation: the claim must not report gone while the Sandbox
    // it owns is still running, because that reported absence is what releases
    // the caller's quota slot.
    let delete = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        preconditions: Some(Preconditions {
            uid: Some(recorded_claim.uid.clone()),
            resource_version: None,
        }),
        ..Default::default()
    };
    match claims.delete(&claim, &delete).await {
        Ok(_) => {}
        Err(kube::Error::Api(error)) if error.code == 404 => {}
        Err(kube::Error::Api(error)) if error.code == 409 => {
            return quarantine_lease(lease, ctx, "claim_uid_precondition_failed").await;
        }
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
    match claim_absence(&claims, &claim, &recorded_claim.uid).await {
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
        ClaimAbsence::Replaced => {
            return quarantine_lease(lease, ctx, "claim_identity_changed_during_teardown").await;
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
    let status = lease.status.clone().unwrap_or_default();

    // Prove the lease-owned footprint absent in status before freeing quota.
    // This checkpoint and Quarantined compete on the same UID/resourceVersion:
    // whichever wins determines whether capacity may ever be returned.
    if !footprint_absence_proven(&status) {
        let mut next = status.clone();
        next.conditions = with_condition_for_status(
            &status,
            lease.metadata.generation,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "Lease-owned Sandbox footprint was verified absent",
        );
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            info!(lease = %name, "Sandbox footprint absence checkpointed");
        } else {
            debug!(lease = %name, "footprint absence checkpoint lost a status race");
        }
        return Ok(Action::await_change());
    }

    let uid = lease
        .uid()
        .ok_or_else(|| SandboxPlacementError::Invalid(format!("lease {name} has no UID")))?;
    let reservations: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    if let Err(error) =
        crate::api::sandbox::release_reservations_for_lease(&reservations, lease, &uid).await
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
    let mut next = status;
    next.phase = terminal;
    next.conditions = with_cleanup_condition(
        lease,
        crate::crd::SandboxConditionStatus::True,
        "TeardownVerified",
        "Lease-owned footprint observed absent and reservations released",
    );
    if !patch_lease_status_fenced(ctx, lease, &next).await? {
        debug!(lease = %name, "terminal teardown checkpoint lost a status race");
        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
    }
    info!(lease = %name, phase = %terminal, "Sandbox lease teardown verified");
    Ok(Action::await_change())
}

/// Whether this lease's Sandbox runs in a composed child cluster.
///
/// Three sources, in order of directness, because status alone is not enough.
///
/// A composition IN FLIGHT has no resolved placement: the internal
/// `ClusterLease` is created first, and the placement is not recorded until the
/// binding resolves — which takes as long as a cluster takes to build. A
/// release landing in that window read the missing placement as "management",
/// deleted a `SandboxClaim` this cluster never had, took the 404 as proof of
/// absence and handed the quota slot back, while the child cluster it had
/// already allocated carried on running.
///
/// So the decisive signal is the ARTIFACT: an internal `ClusterLease` under
/// this lease's derived name, owned by this lease. That exists from the moment
/// a cluster is allocated, which is exactly when releasing on the management
/// path becomes wrong — and unlike the pool spec, it survives the pool being
/// edited or deleted.
async fn is_child_placed(lease: &SandboxLease, ctx: &SandboxContext) -> bool {
    let status = lease.status.clone().unwrap_or_default();
    match status.placement {
        Some(crate::crd::ResolvedSandboxPlacement::Management {}) => return false,
        Some(crate::crd::ResolvedSandboxPlacement::ChildCluster { .. }) => return true,
        None => {}
    }

    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let name = crate::controllers::sandbox_child::internal_lease_name(&lease.name_any());
    match internal.get(&name).await {
        // Existence selects the conservative child path. Exact owner identity
        // is checked there before recovery or mutation; a foreign same-named
        // object therefore quarantines instead of being mistaken for either a
        // management Sandbox or this lease's composition.
        Ok(_) => true,
        Err(kube::Error::Api(error)) if error.code == 404 => false,
        // Cannot tell. Take the child path: it waits for evidence, where the
        // management path would release the quota slot on a 404 that proves
        // nothing about a cluster this controller cannot currently see.
        Err(_) => true,
    }
}

/// Tear a child composition down, and complete only against its receipt.
///
/// The internal `ClusterLease` was created with `CleanupMode::VerifiedDestroy`,
/// so *releasing* it is what puts #80's machinery to work: the cluster's exact
/// footprint must be observed gone before its capacity returns to the
/// `ClusterPool`, and the evidence is written to the lease as a receipt.
/// Destroying the cluster destroys the Sandbox inside it, which is why this
/// replaces — rather than accompanies — the claim delete.
///
/// The internal lease is **released, never deleted**. Deleting the object would
/// destroy the receipt along with it, at exactly the moment the evidence
/// matters; it is collected later by its owner reference, once the Sandbox
/// lease itself goes.
///
/// The quota slot returns only once a receipt proves the exact recorded
/// instance gone. The disappearance of a name is not evidence — a same-named
/// replacement is fresh capacity, not proof that the original was destroyed.
async fn release_child_composition(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();

    // Act on the exact recorded identity. A same-named ClusterLease composed
    // for a later Sandbox is somebody else's cluster, and releasing it would
    // destroy a running tenant's work.
    let internal_api: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let derived = crate::controllers::sandbox_child::internal_lease_name(&name);

    // Provenance is written only once the binding resolves, so a release
    // landing while the child cluster is still building finds none — and
    // reading that as "nothing was composed" hands the quota slot back while a
    // whole cluster carries on running. Absence of a RECORD is not absence of a
    // CLUSTER, so look for the object under the derived name before concluding
    // anything.
    let recorded = match status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
    {
        Some(recorded) => recorded.clone(),
        None => match internal_api.get(&derived).await {
            Ok(unrecorded) => {
                let lease_uid = lease.uid().ok_or_else(|| {
                    SandboxPlacementError::Invalid(format!(
                        "SandboxLease {name} has no UID to recover child provenance"
                    ))
                })?;
                if !metadata_is_controlled_by(
                    &unrecorded.metadata,
                    "kobe.kunobi.ninja/v1alpha1",
                    "SandboxLease",
                    &name,
                    &lease_uid,
                ) {
                    return quarantine_lease(lease, ctx, "child_composition_identity_unverifiable")
                        .await;
                }
                let Some(unrecorded_uid) = unrecorded.uid().filter(|uid| !uid.is_empty()) else {
                    return quarantine_lease(lease, ctx, "child_composition_uid_missing").await;
                };
                warn!(
                    lease = %name,
                    cluster_lease = %derived,
                    "releasing a child composition that was allocated but never recorded"
                );
                crate::crd::SandboxObjectReference {
                    api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                    kind: "ClusterLease".into(),
                    namespace: Some(ctx.namespace.clone()),
                    name: derived.clone(),
                    uid: unrecorded_uid,
                    generation: unrecorded.metadata.generation,
                }
            }
            // Genuinely nothing composed: no record AND no object. There is no
            // footprint to prove absent.
            Err(kube::Error::Api(error)) if error.code == 404 => {
                debug!(lease = %name, "no child composition recorded or allocated");
                return finish_release(lease, ctx, reason).await;
            }
            // Cannot tell whether a cluster is out there. Withhold rather than
            // release: an under-counted pool is recoverable, a stranded cluster
            // with its slot already returned is not.
            Err(_) => {
                return quarantine_lease(lease, ctx, "child_composition_unverifiable").await;
            }
        },
    };
    let recorded = &recorded;
    let recorded_instance = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_instance.as_ref());

    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match internal.get(&recorded.name).await {
        Ok(current) if current.uid().as_deref() == Some(recorded.uid.as_str()) => {
            let lease_uid = lease.uid().ok_or_else(|| {
                SandboxPlacementError::Invalid(format!(
                    "SandboxLease {name} has no UID to verify child ownership"
                ))
            })?;
            if !metadata_is_controlled_by(
                &current.metadata,
                "kobe.kunobi.ninja/v1alpha1",
                "SandboxLease",
                &name,
                &lease_uid,
            ) {
                return quarantine_lease(lease, ctx, "child_composition_owner_changed").await;
            }
            let child_status = current.status.clone().unwrap_or_default();

            // #80 could not prove the cluster's own teardown. Nothing this
            // controller can do makes that evidence appear.
            if child_status.phase == crate::crd::LeasePhase::Quarantined {
                return quarantine_lease(lease, ctx, "child_teardown_quarantined").await;
            }

            match child_status.teardown_receipt.as_ref() {
                Some(receipt) if receipt_proves_child_gone(receipt, recorded_instance) => {
                    info!(lease = %name, "child teardown receipt verified");
                    return finish_release(lease, ctx, reason).await;
                }
                // A receipt exists but is not about this instance, or does not
                // say Verified. Present-but-wrong is worse than absent: it is
                // the case a laxer check would accept.
                Some(_) => {
                    return quarantine_lease(lease, ctx, "child_receipt_does_not_match").await;
                }
                None => {}
            }

            // No receipt yet. Ask for release if nobody has, then wait —
            // destroying a cluster and proving it gone both take time.
            if !matches!(
                child_status.phase,
                crate::crd::LeasePhase::Released
                    | crate::crd::LeasePhase::Expired
                    | crate::crd::LeasePhase::Recycling
            ) {
                request_child_release(&internal, &current).await?;
            }
            debug!(lease = %name, "waiting for the child teardown receipt");
            Ok(Action::requeue(std::time::Duration::from_secs(30)))
        }
        // The recorded lease is gone, or a different object holds its name. Its
        // receipt went with it, so there is nothing left that can prove this
        // lease's cluster was destroyed — and #74 is explicit that the
        // disappearance of a name is not evidence.
        Ok(_) => quarantine_lease(lease, ctx, "child_receipt_unavailable").await,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            quarantine_lease(lease, ctx, "child_receipt_unavailable").await
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

/// Whether a child teardown receipt proves THIS lease's cluster gone.
///
/// #80's own gate already ran inside the `ClusterLease` controller before the
/// receipt was written; this is the outer lease checking the one thing that
/// gate cannot know — that the evidence is about the instance this Sandbox was
/// actually placed on.
///
/// A same-named replacement instance is fresh capacity, not proof the original
/// was reset, so the UID recorded at composition time is what must match. An
/// unrecorded instance UID fails closed: two absent UIDs would otherwise
/// compare equal and any receipt would satisfy any lease.
fn receipt_proves_child_gone(
    receipt: &crate::crd::TeardownReceipt,
    recorded_instance: Option<&crate::crd::SandboxObjectReference>,
) -> bool {
    if receipt.outcome != crate::crd::TeardownOutcome::Verified
        || receipt.completed_at.is_none()
        || crate::crd::TeardownReceipt::outcome_for(&receipt.checks)
            != crate::crd::TeardownOutcome::Verified
        || receipt.schema_version != crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION
    {
        return false;
    }
    let Some(expected) = recorded_instance else {
        return false;
    };
    let Some(proven) = receipt.instance.uid.as_deref() else {
        return false;
    };
    !expected.uid.is_empty() && proven == expected.uid && receipt.instance.name == expected.name
}

/// Ask the internal lease to release, fenced on the exact object.
///
/// The same UID and resourceVersion test ops the public release path uses:
/// between the read and this write the lease could be deleted and a same-named
/// one composed for another Sandbox, and a merge patch would release theirs.
async fn request_child_release(
    internal: &Api<crate::crd::ClusterLease>,
    current: &crate::crd::ClusterLease,
) -> Result<(), SandboxPlacementError> {
    let (Some(uid), Some(resource_version)) = (current.uid(), current.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(
            "child cluster lease has no UID or resourceVersion to fence on".into(),
        ));
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/status/phase", "value": "Released" }
    ]));
    match internal
        .patch_status(
            &current.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        // Lost the race: somebody already moved it on. The next reconcile reads
        // whatever they wrote, which is exactly what should decide.
        Err(kube::Error::Api(error)) if error.code == 409 || error.code == 404 => Ok(()),
        Err(error) => Err(error.into()),
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
    /// The recorded claim is gone, but its name now resolves to another UID.
    /// That object is never deleted or counted as proof of clean teardown.
    Replaced,
    /// The question could not be answered and retrying will not change that.
    Unverifiable,
}

/// Whether the upstream claim is provably gone.
///
/// Absence is proven by a 404 and nothing else. Reading "I could not check" as
/// "it is gone" is how a live Sandbox's capacity gets handed to somebody else.
async fn claim_absence(
    claims: &Api<DynamicObject>,
    claim: &str,
    expected_uid: &str,
) -> ClaimAbsence {
    match claims.get(claim).await {
        Ok(current) if current.uid().as_deref() == Some(expected_uid) => ClaimAbsence::StillPresent,
        Ok(_) => ClaimAbsence::Replaced,
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
    let mut next = lease.status.clone().unwrap_or_default();
    if footprint_absence_proven(&next) {
        warn!(lease = %name, reason, "refusing to quarantine after footprint absence was proven");
        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
    }
    let phase = crate::sandbox::transition_sandbox_phase(
        next.phase,
        crate::crd::SandboxLeasePhase::Quarantined,
        false,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    next.phase = phase;
    next.conditions = with_cleanup_condition(
        lease,
        crate::crd::SandboxConditionStatus::False,
        reason,
        "Teardown could not be verified; capacity is withheld",
    );
    if !patch_lease_status_fenced(ctx, lease, &next).await? {
        debug!(lease = %name, "quarantine checkpoint lost a status race");
        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
    }
    warn!(lease = %name, reason, "Sandbox lease quarantined; capacity withheld");
    Ok(Action::requeue(std::time::Duration::from_secs(300)))
}

/// The durable record of when a lease's teardown question was answered.
///
/// `pub(crate)` because the retention sweep in `api::sandbox` dates a terminal
/// lease by this condition. A second copy of the string would be a second thing
/// to rename, and a sweep matching a condition type nobody writes any more
/// would simply stop retiring anything, silently.
pub(crate) const CLEANUP_VERIFIED_CONDITION: &str = "CleanupVerified";
/// Durable latch proving the lease-owned workload is gone before quota moves.
const FOOTPRINT_ABSENT_CONDITION: &str = "FootprintAbsent";
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

fn footprint_absence_proven(status: &crate::crd::SandboxLeaseStatus) -> bool {
    status.conditions.iter().any(|condition| {
        condition.condition_type == FOOTPRINT_ABSENT_CONDITION
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
/// The full list is rebuilt because lifecycle checkpoints replace the complete
/// status value: sending one condition alone would silently drop every other
/// condition on the lease.
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
    let status_value = lease.status.clone().unwrap_or_default();
    with_condition_for_status(
        &status_value,
        lease.metadata.generation,
        condition_type,
        status,
        reason,
        message,
    )
}

/// Upsert a condition into the current in-memory status. Reconcile checkpoints
/// use this form so a later full-status write cannot erase a condition written
/// earlier in the same pass.
fn with_condition_for_status(
    current: &crate::crd::SandboxLeaseStatus,
    observed_generation: Option<i64>,
    condition_type: &str,
    status: crate::crd::SandboxConditionStatus,
    reason: &str,
    message: &str,
) -> Vec<crate::crd::SandboxCondition> {
    let existing = current.conditions.clone();
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
        observed_generation,
        last_transition_time,
    });
    conditions
}

/// Whether a Kubernetes object is controlled by the exact parent identity we
/// expect. A matching name is insufficient after delete-and-recreate.
fn is_controlled_by(
    object: &DynamicObject,
    api_version: &str,
    kind: &str,
    name: &str,
    uid: &str,
) -> bool {
    metadata_is_controlled_by(&object.metadata, api_version, kind, name, uid)
}

fn metadata_is_controlled_by(
    metadata: &kube::api::ObjectMeta,
    api_version: &str,
    kind: &str,
    name: &str,
    uid: &str,
) -> bool {
    metadata.owner_references.as_ref().is_some_and(|owners| {
        owners.iter().any(|owner| {
            owner.api_version == api_version
                && owner.kind == kind
                && owner.name == name
                && owner.uid == uid
                && owner.controller == Some(true)
        })
    })
}

fn target_reference(
    api_version: &str,
    kind: &str,
    namespace: &str,
    object: &DynamicObject,
) -> Result<crate::crd::SandboxObjectReference, SandboxPlacementError> {
    let uid = object.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "{kind} {} has no UID to record as Sandbox provenance",
            object.name_any()
        ))
    })?;
    Ok(crate::crd::SandboxObjectReference {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        namespace: Some(namespace.to_string()),
        name: object.name_any(),
        uid,
        // UID is the identity fence. Upstream generations move when the pool
        // controller corrects spec drift; recording one would turn a safe
        // in-place reconciliation into an apparent identity replacement.
        generation: None,
    })
}

/// Prove that a live object is still the exact identity previously recorded in
/// lease status. A same-named replacement is not the original allocation.
fn require_exact_reference(
    recorded: &crate::crd::SandboxObjectReference,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    object: &DynamicObject,
) -> Result<(), SandboxPlacementError> {
    let live_uid = object.uid().unwrap_or_else(|| "<none>".into());
    let generation_matches = recorded
        .generation
        .is_none_or(|generation| object.metadata.generation == Some(generation));
    if recorded.api_version != api_version
        || recorded.kind != kind
        || recorded.namespace.as_deref() != Some(namespace)
        || recorded.name != name
        || recorded.uid != live_uid
        || !generation_matches
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "recorded {kind} provenance cannot change: expected {namespace}/{name} uid {}, observed uid {live_uid}",
            recorded.uid
        )));
    }
    Ok(())
}

/// Observe the exact management-cluster pool objects a lease will consume.
/// Missing objects are ordinary pool reconciliation lag; foreign or
/// same-named replacements fail closed.
async fn observed_management_pool_provenance(
    ctx: &SandboxContext,
    pool: &SandboxPool,
    status: &crate::crd::SandboxLeaseStatus,
) -> Result<Option<crate::crd::SandboxTargetProvenance>, SandboxPlacementError> {
    let resources = [
        (
            upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
            template_name(&pool.name_any()),
            SANDBOX_TEMPLATE_KIND,
        ),
        (
            upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
            warm_pool_name(&pool.name_any()),
            SANDBOX_WARM_POOL_KIND,
        ),
    ];
    let mut observed = Vec::with_capacity(resources.len());
    for (resource, name, kind) in resources {
        let objects: Api<DynamicObject> =
            Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &resource);
        let object = match objects.get(&name).await {
            Ok(object) => object,
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let pool_uid = pool.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxPool {} has no UID to fence its upstream objects",
                pool.name_any()
            ))
        })?;
        if !is_controlled_by(
            &object,
            "kobe.kunobi.ninja/v1alpha1",
            "SandboxPool",
            &pool.name_any(),
            &pool_uid,
        ) {
            return Err(SandboxPlacementError::Invalid(format!(
                "{kind} {name} is not controlled by SandboxPool {} uid {pool_uid}",
                pool.name_any()
            )));
        }
        observed.push(target_reference(
            AGENT_SANDBOX_API_VERSION,
            kind,
            &ctx.namespace,
            &object,
        )?);
    }

    let mut proposed = status
        .target
        .clone()
        .unwrap_or(crate::crd::SandboxTargetProvenance {
            namespace: ctx.namespace.clone(),
            child_cluster_lease: None,
            child_cluster_instance: None,
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
        });
    proposed.sandbox_template = Some(observed.remove(0));
    proposed.sandbox_warm_pool = Some(observed.remove(0));
    Ok(Some(proposed))
}

fn management_provenance_is_complete(status: &crate::crd::SandboxLeaseStatus) -> bool {
    status.target.as_ref().is_some_and(|target| {
        target.sandbox_template.is_some()
            && target.sandbox_warm_pool.is_some()
            && target.sandbox_claim.is_some()
            && target.sandbox.is_some()
            && target.pod.is_some()
    })
}

/// Build the full target provenance for a placed, ready lease.
///
/// Monotonic: whatever was already recorded — the child cluster identities for
/// a composition — is preserved, and only the upstream references are added.
/// Provenance that could be *cleared* would let a teardown lose the very
/// identity it has to prove absent.
///
/// Returns `None` when the objects cannot be identified. Recording a reference
/// without a UID is worse than recording nothing: two absent UIDs compare
/// equal, so any later same-named object would satisfy a check meant to
/// exclude it.
async fn observed_provenance(
    target: &Target,
    claim: &DynamicObject,
    status: &crate::crd::SandboxLeaseStatus,
) -> Result<Option<crate::crd::SandboxTargetProvenance>, String> {
    let Some(claim_uid) = claim.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(None);
    };
    let resolved = crate::controllers::sandbox_canary::resolve_sandbox_pod(
        &target.client,
        &target.namespace,
        claim,
    )
    .await?;
    let Some(resolved) = resolved else {
        return Ok(None);
    };

    let existing = status.target.clone();
    let reference =
        |api_version: &str, kind: &str, name: &str, uid: &str| crate::crd::SandboxObjectReference {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            namespace: Some(target.namespace.clone()),
            name: name.to_string(),
            uid: uid.to_string(),
            generation: None,
        };

    Ok(Some(crate::crd::SandboxTargetProvenance {
        namespace: target.namespace.clone(),
        child_cluster_lease: existing
            .as_ref()
            .and_then(|existing| existing.child_cluster_lease.clone()),
        child_cluster_instance: existing
            .as_ref()
            .and_then(|existing| existing.child_cluster_instance.clone()),
        sandbox_template: existing
            .as_ref()
            .and_then(|existing| existing.sandbox_template.clone()),
        sandbox_warm_pool: existing
            .as_ref()
            .and_then(|existing| existing.sandbox_warm_pool.clone()),
        sandbox_claim: Some(reference(
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &claim.name_any(),
            &claim_uid,
        )),
        sandbox: Some(reference(
            crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
            crate::controllers::sandbox_canary::SANDBOX_KIND,
            &resolved.sandbox_name,
            &resolved.sandbox_uid,
        )),
        pod: Some(reference(
            "v1",
            "Pod",
            &resolved.pod_name,
            &resolved.pod_uid,
        )),
    }))
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
    let lease_uid = lease.uid().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxLease {name} has no UID to own a child"))
    })?;
    if !metadata_is_controlled_by(
        &internal_lease.metadata,
        "kobe.kunobi.ninja/v1alpha1",
        "SandboxLease",
        &name,
        &lease_uid,
    ) {
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
    let child_provenance = child::child_provenance(
        &ctx.namespace,
        &binding.lease,
        &binding.binding.instance.name,
        &binding.binding.instance.uid,
        Some(binding.binding.instance.observed_generation),
    );
    let status = lease.status.clone().unwrap_or_default();
    let placement = crate::sandbox::record_placement_once(
        status.placement.as_ref(),
        crate::crd::ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: crate::crd::SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterPool".into(),
                namespace: Some(ctx.namespace.clone()),
                name: cluster_pool.name_any(),
                uid: cluster_pool.uid().unwrap_or_default(),
                generation: cluster_pool.metadata.generation,
            },
        },
        &ctx.namespace,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    let mut proposed = status
        .target
        .clone()
        .unwrap_or_else(|| child_provenance.clone());
    proposed.namespace = child_provenance.namespace;
    proposed.child_cluster_lease = child_provenance.child_cluster_lease;
    proposed.child_cluster_instance = child_provenance.child_cluster_instance;
    let provenance = crate::sandbox::merge_target_provenance(
        status.target.as_ref(),
        proposed,
        &placement,
        &ctx.namespace,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    if status.placement.as_ref() != Some(&placement) || status.target.as_ref() != Some(&provenance)
    {
        let mut next = status;
        next.placement = Some(placement);
        next.target = Some(provenance);
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            debug!(lease = %name, "recorded child composition provenance");
        } else {
            debug!(lease = %name, "child composition provenance write lost a status race");
        }
        return Ok(ChildTarget::Pending(Action::await_change()));
    }

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

/// Replace one lease status only if this is still the exact object version the
/// reconcile read. Monotonic placement/provenance writes cannot use an
/// unfenced merge: a stale replica could otherwise erase a newer identity or
/// write through delete-and-recreate name reuse.
///
/// A conflict is treated as an ordinary lost race. The watch event for the
/// winning write will reconcile the current object; retrying this stale value
/// here would defeat the fence.
async fn patch_lease_status_fenced(
    ctx: &SandboxContext,
    lease: &SandboxLease,
    status: &crate::crd::SandboxLeaseStatus,
) -> Result<bool, SandboxPlacementError> {
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no UID or resourceVersion to fence status",
            lease.name_any()
        )));
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/status", "value": status }
    ]));
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
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
    const TEMPLATE_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxtemplates/kobe-agents";
    const WARM_POOL_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxwarmpools/kobe-agents";
    const SANDBOX_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes/sbx";
    const PODS_PATH: &str = "/api/v1/namespaces/test-ns/pods";
    const LEASE_STATUS_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1/status";

    async fn test_context() -> (Arc<SandboxContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let ctx = Arc::new(SandboxContext {
            client: crate::testutil::mock_k8s_client(&server),
            namespace: NS.to_string(),
        });
        for (path_value, kind, uid) in [
            (TEMPLATE_PATH, SANDBOX_TEMPLATE_KIND, "template-uid"),
            (WARM_POOL_PATH, SANDBOX_WARM_POOL_KIND, "warm-pool-uid"),
        ] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": AGENT_SANDBOX_API_VERSION,
                    "kind": kind,
                    "metadata": {
                        "name": "kobe-agents",
                        "namespace": NS,
                        "uid": uid,
                        "ownerReferences": [{
                            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                            "kind": "SandboxPool",
                            "name": "agents",
                            "uid": POOL_UID,
                            "controller": true,
                        }],
                    },
                })))
                .with_priority(10)
                .mount(&server)
                .await;
        }
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
                    runner_path: None,
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
        let created_at = chrono::Utc::now();
        let reference = |api_version: &str, kind: &str, name: &str, uid: &str| {
            crate::crd::SandboxObjectReference {
                api_version: api_version.into(),
                kind: kind.into(),
                namespace: Some(NS.into()),
                name: name.into(),
                uid: uid.into(),
                generation: None,
            }
        };
        SandboxLease {
            metadata: ObjectMeta {
                name: Some(LEASE.into()),
                namespace: Some(NS.into()),
                uid: Some("lease-uid-1".into()),
                resource_version: Some("lease-rv-1".into()),
                generation: Some(1),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_millisecond(created_at.timestamp_millis())
                        .unwrap(),
                )),
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
                    crate::sandbox::sandbox_provisioning_deadline(
                        created_at,
                        chrono::Duration::minutes(10),
                    )
                    .unwrap(),
                ),
                placement: Some(crate::crd::ResolvedSandboxPlacement::Management {}),
                target: Some(crate::crd::SandboxTargetProvenance {
                    namespace: NS.into(),
                    child_cluster_lease: None,
                    child_cluster_instance: None,
                    sandbox_template: Some(reference(
                        AGENT_SANDBOX_API_VERSION,
                        SANDBOX_TEMPLATE_KIND,
                        "kobe-agents",
                        "template-uid",
                    )),
                    sandbox_warm_pool: Some(reference(
                        AGENT_SANDBOX_API_VERSION,
                        SANDBOX_WARM_POOL_KIND,
                        "kobe-agents",
                        "warm-pool-uid",
                    )),
                    sandbox_claim: Some(reference(
                        AGENT_SANDBOX_API_VERSION,
                        SANDBOX_CLAIM_KIND,
                        "kobe-sbx-1",
                        "claim-uid",
                    )),
                    sandbox: Some(reference(
                        crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                        crate::controllers::sandbox_canary::SANDBOX_KIND,
                        "sbx",
                        "sandbox-uid",
                    )),
                    pod: Some(reference("v1", "Pod", "sandbox-pod", "pod-uid")),
                }),
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
            "metadata": {
                "name": "kobe-sbx-1",
                "namespace": NS,
                "uid": "claim-uid",
                "resourceVersion": "77",
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "SandboxLease",
                    "name": LEASE,
                    "uid": "lease-uid-1",
                    "controller": true,
                }],
            },
            "status": status,
        })
    }

    async fn mount_resolved_sandbox(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(SANDBOX_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                "metadata": { "name": "sbx", "namespace": NS, "uid": "sandbox-uid" },
                "status": { "selector": "kobe.test/sandbox=sbx" },
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(PODS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": [{
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "sandbox-pod", "namespace": NS, "uid": "pod-uid" },
                    "status": { "phase": "Running" },
                }],
            })))
            .mount(server)
            .await;
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

    fn status_value_of(request: &wiremock::Request) -> Option<serde_json::Value> {
        let body: serde_json::Value = serde_json::from_slice(&request.body).ok()?;
        if let Some(status) = body.get("status") {
            return Some(status.clone());
        }
        body.as_array()?
            .iter()
            .find(|operation| operation["op"] == "add" && operation["path"] == "/status")
            .map(|operation| operation["value"].clone())
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
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "True" }],
                    "sandbox": { "name": "sbx" }
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

    /// Management placement is durable before the first upstream object is
    /// created, and the write is fenced to the exact lease version observed.
    #[tokio::test]
    async fn management_placement_is_persisted_before_claim_creation() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().placement = None;
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);

        let requests = server.received_requests().await.unwrap_or_default();
        let patch_request = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("placement status patch");
        let operations: serde_json::Value = serde_json::from_slice(&patch_request.body).unwrap();
        let operations = operations.as_array().unwrap();
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/uid"
                && operation["value"] == "lease-uid-1"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "lease-rv-1"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status"
                && operation["value"]["placement"]["type"] == "management"
        }));
    }

    /// An admitted management pool cannot retarget a lease whose resolved
    /// placement already names a child backend.
    #[tokio::test]
    async fn persisted_management_placement_cannot_change() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().placement =
            Some(crate::crd::ResolvedSandboxPlacement::ChildCluster {
                cluster_pool: crate::crd::SandboxObjectReference {
                    api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                    kind: "ClusterPool".into(),
                    namespace: Some(NS.into()),
                    name: "child-pool".into(),
                    uid: "child-pool-uid".into(),
                    generation: Some(1),
                },
            });

        let error = reconcile_lease(Arc::new(lease), ctx).await.unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("cannot change")),
            "expected immutable placement failure, got: {error}"
        );
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 0);
    }

    /// Once management placement is explicit, a same-named child artifact is
    /// irrelevant and must never redirect teardown into the child path.
    #[tokio::test]
    async fn explicit_management_placement_never_follows_a_derived_child_artifact() {
        let (ctx, server) = test_context().await;
        assert!(!is_child_placed(&admitted_lease(), &ctx).await);
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "explicit management placement must not look up a derived child lease"
        );
    }

    /// Pool object identities are checkpointed before a claim can refer to
    /// them. This prevents a same-named foreign WarmPool from becoming the
    /// source of tenant workloads.
    #[tokio::test]
    async fn management_pool_provenance_is_persisted_before_claim_creation() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().target = None;
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);

        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        let target = &statuses.last().expect("pool provenance status")["target"];
        assert_eq!(target["sandboxTemplate"]["uid"], "template-uid");
        assert_eq!(target["sandboxWarmPool"]["uid"], "warm-pool-uid");
        assert!(target.get("sandboxClaim").is_none());
    }

    /// A lost optimistic status race ends the pass. In particular, a stale
    /// Provisioning checkpoint cannot fall through to claim creation or Ready
    /// side effects under the resourceVersion it just invalidated.
    #[tokio::test]
    async fn a_conflicted_provisioning_checkpoint_has_no_later_side_effects() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"
            })))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Pending;
        status.provisioning_deadline = None;
        status.observed_generation = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 1);
    }

    /// Missing upstream pool objects are part of provisioning, not a queue
    /// outside its clock. The deadline is durable before the first Template
    /// lookup and can expire without those objects ever appearing.
    #[tokio::test]
    async fn missing_management_pool_objects_are_bounded_by_provisioning_deadline() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(TEMPLATE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Pending;
        status.observed_generation = None;
        status.provisioning_deadline = None;
        status.target = None;

        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", TEMPLATE_PATH).await, 0);
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-2").await;
        assert_eq!(
            lease.status.as_ref().unwrap().phase,
            crate::crd::SandboxLeasePhase::Provisioning
        );
        assert!(
            lease
                .status
                .as_ref()
                .unwrap()
                .provisioning_deadline
                .is_some()
        );

        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        assert_eq!(requests_to(&server, "GET", TEMPLATE_PATH).await, 1);

        lease.status.as_mut().unwrap().provisioning_deadline =
            Some((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339());
        lease.metadata.resource_version = Some("lease-rv-3".into());
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", TEMPLATE_PATH).await, 1);
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("Releasing checkpoint");
        assert_eq!(status["phase"], "Releasing");
        assert_eq!(status["releaseCause"], "ProvisioningDeadline");
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);
    }

    /// Child-cluster allocation cannot sit outside the provisioning bound. A
    /// Pending child lease checkpoints its deadline before even reading the
    /// ClusterPool, and an elapsed checkpoint releases without composing.
    #[tokio::test]
    async fn child_binding_wait_is_bounded_before_composition() {
        const CHILD_POOL_PATH: &str =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool";
        let (ctx, server) = test_context().await;
        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.placement = serde_json::from_value(serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "child-pool"
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Pending;
        status.observed_generation = None;
        status.provisioning_deadline = None;
        status.placement = None;
        status.target = None;

        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CHILD_POOL_PATH).await, 0);
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-2").await;
        lease.status.as_mut().unwrap().provisioning_deadline =
            Some((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339());

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CHILD_POOL_PATH).await, 0);
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("child expiry checkpoint");
        assert_eq!(status["releaseCause"], "ProvisioningDeadline");
    }

    /// An unready claim is still an allocated identity. Record it before the
    /// normal readiness requeue so restart-safe cleanup can address the exact
    /// object rather than a derived name.
    #[tokio::test]
    async fn claim_provenance_is_written_before_unready_requeue() {
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
                    "conditions": [{ "type": "Ready", "status": "False" }]
                }))),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox_claim = None;
        target.sandbox = None;
        target.pod = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 0);
        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert_eq!(
            statuses.last().expect("claim provenance status")["target"]["sandboxClaim"]["uid"],
            "claim-uid"
        );
    }

    /// A recorded claim UID cannot be replaced by a same-named object between
    /// reconciles, even when the replacement carries a plausible owner name.
    #[tokio::test]
    async fn same_named_replacement_claim_is_rejected() {
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
                    "conditions": [{ "type": "Ready", "status": "False" }]
                }))),
            )
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .sandbox_claim
            .as_mut()
            .unwrap()
            .uid = "original-claim-uid".into();

        let error = reconcile_lease(Arc::new(lease), ctx).await.unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("SandboxClaim") && message.contains("cannot change")),
            "expected immutable claim provenance failure, got: {error}"
        );
        assert_eq!(
            requests_to(&server, "POST", CLAIMS_PATH).await,
            0,
            "a recorded claim is never recreated"
        );
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 0);
    }

    /// Ready is a later checkpoint than Sandbox/Pod discovery. A partial
    /// target is enriched durably and requeued, never exposed as Ready first.
    #[tokio::test]
    async fn management_ready_requires_complete_persisted_provenance() {
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
                    "conditions": [{ "type": "Ready", "status": "True" }],
                    "sandbox": { "name": "sbx" }
                }))),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;
        mount_resolved_sandbox(&server).await;

        let mut lease = lease_past_the_canary();
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox = None;
        target.pod = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 0);
        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        let status = statuses.last().expect("target provenance status");
        assert_ne!(status["phase"], "Ready");
        assert_eq!(status["target"]["sandbox"]["uid"], "sandbox-uid");
        assert_eq!(status["target"]["pod"]["uid"], "pod-uid");
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

    /// Terminal leases never recreate capacity after teardown has finished or
    /// become unverifiable. This guard belongs at the reconcile boundary: the
    /// release classifier intentionally returns no new release reason for a
    /// terminal phase, which must mean "stop", never "resume placement".
    #[tokio::test]
    async fn terminal_leases_never_recreate_capacity() {
        let (ctx, server) = test_context().await;

        for phase in [
            crate::crd::SandboxLeasePhase::Released,
            crate::crd::SandboxLeasePhase::Expired,
            crate::crd::SandboxLeasePhase::Quarantined,
        ] {
            let mut lease = admitted_lease();
            lease.status.as_mut().unwrap().phase = phase;

            let action = reconcile_lease(Arc::new(lease), ctx.clone()).await.unwrap();
            assert_eq!(action, Action::await_change(), "terminal phase {phase}");
        }

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "terminal reconciliation must not resolve a pool or recreate a claim"
        );
    }

    /// The lease admission actually creates must be able to reach Ready.
    ///
    /// Each durable checkpoint is a separate reconcile: placement must be
    /// recorded before a claim exists, then provisioning can create and bound
    /// the workload on the next observed object version.
    #[tokio::test]
    async fn a_lease_in_the_state_admission_leaves_it_in_can_become_ready() {
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
                    "conditions": [{ "type": "Ready", "status": "True" }],
                    "sandbox": { "name": "sbx" }
                }))),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        mount_teardown_scaffolding(&server).await;
        mount_resolved_sandbox(&server).await;

        // This is the actual CR shape after admission: admitted annotation and
        // no controller-authored status. Every returned checkpoint is fed into
        // the next reconcile at a distinct resourceVersion, as Kubernetes
        // would do. The websocket canary itself cannot be served by wiremock;
        // its already-persisted condition is injected at that one boundary.
        let mut lease = admitted_lease();
        lease.status = None;

        for (resource_version, checkpoint) in [
            ("lease-rv-2", "placement"),
            ("lease-rv-3", "Provisioning"),
            ("lease-rv-4", "pool provenance"),
            ("lease-rv-5", "claim provenance"),
        ] {
            let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .unwrap();
            assert_eq!(action, Action::await_change(), "{checkpoint} checkpoint");
            advance_lease_to_latest_status(&mut lease, &server, resource_version).await;
            if checkpoint != "claim provenance" {
                assert_eq!(
                    requests_to(&server, "POST", CLAIMS_PATH).await,
                    0,
                    "claim creation must wait through {checkpoint}"
                );
            }
        }

        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            READINESS_CANARY_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "CanaryPassed",
            "recorded at the websocket boundary",
        );
        lease.metadata.resource_version = Some("lease-rv-6".into());
        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(
            action,
            Action::await_change(),
            "target provenance checkpoint"
        );
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-7").await;

        reconcile_lease(Arc::new(lease), ctx).await.unwrap();

        assert!(
            recorded_phases(&server)
                .await
                .contains(&"Ready".to_string()),
            "a lease created through the API must be able to reach Ready; \
             recorded phases were {:?}",
            recorded_phases(&server).await
        );
        let ready_status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .find(|status| status["phase"] == "Ready")
            .expect("Ready status write");
        assert!(
            ready_status["conditions"]
                .as_array()
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition["type"] == READINESS_CANARY_CONDITION
                            && condition["status"] == "True"
                    })
                })
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

    /// A reservation name the hardened release path will accept.
    ///
    /// Derived from the fixture lease's own principal, because carrying the
    /// right UID label is deliberately NOT enough: anyone able to create a
    /// coordination Lease could otherwise label one with a victim's UID and
    /// have Kobe's credentials delete it during that victim's cleanup.
    fn reservation_name() -> String {
        crate::api::sandbox::quota_reservation_name(
            &crate::api::sandbox::principal_hash_for(&admitted_lease().spec.requester),
            0,
        )
    }

    fn releasing_lease(phase: crate::crd::SandboxLeasePhase) -> SandboxLease {
        let mut lease = admitted_lease();
        lease.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.to_string(),
            chrono::Utc::now().to_rfc3339(),
        );
        let status = lease.status.as_mut().unwrap();
        status.phase = phase;
        if phase == crate::crd::SandboxLeasePhase::Releasing {
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        }
        lease
    }

    /// Run the destructive half only after the durable Releasing checkpoint
    /// has been observed at a new Kubernetes resourceVersion.
    async fn reconcile_release_after_checkpoint(
        mut lease: SandboxLease,
        ctx: Arc<SandboxContext>,
        server: &MockServer,
    ) -> Action {
        for pass in 0..4 {
            let before = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
                })
                .count();
            let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .expect("release checkpoint");
            if action != Action::await_change() {
                return action;
            }
            let statuses: Vec<_> = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
                })
                .filter_map(status_value_of)
                .collect();
            let Some(latest) = statuses.get(before).cloned() else {
                return action;
            };
            lease.status = Some(serde_json::from_value(latest).expect("typed release checkpoint"));
            lease.metadata.resource_version = Some(format!("lease-rv-after-release-{pass}"));
            if matches!(
                lease.status.as_ref().unwrap().phase,
                crate::crd::SandboxLeasePhase::Released
                    | crate::crd::SandboxLeasePhase::Expired
                    | crate::crd::SandboxLeasePhase::Quarantined
            ) {
                return action;
            }
        }
        panic!("release did not settle within four durable checkpoints")
    }

    async fn advance_lease_to_latest_status(
        lease: &mut SandboxLease,
        server: &MockServer,
        resource_version: &str,
    ) {
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("durable status checkpoint");
        lease.status = Some(serde_json::from_value(status).expect("typed SandboxLeaseStatus"));
        lease.metadata.resource_version = Some(resource_version.into());
    }

    fn phase_of(request: &wiremock::Request) -> Option<String> {
        status_value_of(request)?
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
                        "name": reservation_name(),
                        "namespace": NS,
                        "uid": "reservation-uid-1",
                    },
                }],
            })))
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("{RESERVATIONS_PATH}/{}", reservation_name())))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": { "name": "sbx-quota-abc-0", "namespace": NS },
            })))
            .mount(server)
            .await;
    }

    /// Let one status writer win, then make every stale writer lose its
    /// UID/resourceVersion fence. Both proof and quarantine tests use the same
    /// apiserver ordering so the only variable is which state is submitted
    /// first.
    async fn mount_one_winning_status_patch(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"
            })))
            .with_priority(1)
            .mount(server)
            .await;
    }

    /// A crash can land after CREATE but before the claim UID checkpoint. The
    /// release path first recovers the exact lease-owned identity and ends the
    /// pass; it never deletes an object known only by a derived name.
    #[tokio::test]
    async fn teardown_recovers_missing_claim_provenance_before_delete() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;

        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .sandbox_claim = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        let recovered = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("recovered status");
        assert_eq!(recovered["target"]["sandboxClaim"]["uid"], "claim-uid");
    }

    /// A derived name is not provenance. If the object at that name is not
    /// controlled by this exact lease UID, recovery quarantines without
    /// deleting it or returning quota.
    #[tokio::test]
    async fn teardown_never_recovers_a_foreign_claim() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut foreign = claim_json(serde_json::json!({}));
        foreign["metadata"]["ownerReferences"][0]["uid"] = "another-lease-uid".into();
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(foreign))
            .mount(&server)
            .await;

        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .sandbox_claim = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
    }

    /// A successful DELETE is only an acknowledgement. If the same name is
    /// already occupied by another UID when absence is checked, teardown is
    /// unproven and the reservation remains held.
    #[tokio::test]
    async fn teardown_rejects_a_same_named_claim_replacement() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        let mut replacement = claim_json(serde_json::json!({}));
        replacement["metadata"]["uid"] = "replacement-claim-uid".into();
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 1);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
    }

    /// A legacy/corrupt Releasing object without the atomic cause checkpoint
    /// cannot be given a clean terminal outcome. It quarantines without
    /// touching either the claim or quota reservations.
    #[tokio::test]
    async fn a_releasing_lease_without_cause_fails_closed() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().phase = crate::crd::SandboxLeasePhase::Releasing;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("quarantine status patch");
        let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/uid"
                && operation["value"] == "lease-uid-1"
        }));
        assert_eq!(status_value_of(&request).unwrap()["phase"], "Quarantined");
    }

    /// After footprint proof and idempotent reservation release, a stale
    /// terminal writer must lose on UID/resourceVersion rather than mutate a
    /// same-named replacement lease.
    #[tokio::test]
    async fn terminal_status_conflict_cannot_write_through_name_reuse() {
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
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "recorded by an earlier reconcile",
        );
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1,
            "reservation cleanup remains safely idempotent"
        );
        let patch = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("terminal status attempt");
        let operations: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "lease-rv-1"
        }));
        assert_eq!(
            status_value_of(&patch).unwrap()["releaseCause"],
            "Requested"
        );
    }

    /// Quarantine has the same identity fence as a clean terminal write and
    /// never frees reservations when that fence loses a race.
    #[tokio::test]
    async fn quarantine_status_conflict_cannot_write_through_name_reuse() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("DELETE"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        let patch = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("quarantine status attempt");
        assert_eq!(status_value_of(&patch).unwrap()["phase"], "Quarantined");
    }

    /// Footprint proof and quarantine are mutually exclusive durable outcomes.
    /// If proof wins the shared resourceVersion first, a stale quarantine may
    /// not overwrite it and quota remains untouched until a fresh reconcile
    /// observes that proof.
    #[tokio::test]
    async fn footprint_proof_wins_the_race_without_releasing_quota_in_that_pass() {
        let (ctx, server) = test_context().await;
        mount_one_winning_status_patch(&server).await;
        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);

        let proof = finish_release(&lease, &ctx, ReleaseReason::Requested)
            .await
            .unwrap();
        assert_eq!(proof, Action::await_change());
        let stale_quarantine = quarantine_lease(&lease, &ctx, "stale_uncertainty")
            .await
            .unwrap();
        assert_eq!(
            stale_quarantine,
            Action::requeue(std::time::Duration::from_secs(5))
        );

        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert_eq!(statuses.len(), 2);
        assert!(
            statuses[0]["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["type"] == FOOTPRINT_ABSENT_CONDITION && condition["status"] == "True"
                })
        );
        assert_eq!(statuses[1]["phase"], "Quarantined");
        assert_eq!(requests_to(&server, "GET", RESERVATIONS_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
    }

    /// The opposite ordering fails closed too. A quarantine that wins first
    /// keeps the reservation; a stale proof writer cannot free quota because a
    /// proof checkpoint never performs reservation cleanup itself.
    #[tokio::test]
    async fn quarantine_wins_the_race_without_releasing_quota() {
        let (ctx, server) = test_context().await;
        mount_one_winning_status_patch(&server).await;
        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);

        let quarantine = quarantine_lease(&lease, &ctx, "absence_unverifiable")
            .await
            .unwrap();
        assert_eq!(
            quarantine,
            Action::requeue(std::time::Duration::from_secs(300))
        );
        let stale_proof = finish_release(&lease, &ctx, ReleaseReason::Requested)
            .await
            .unwrap();
        assert_eq!(stale_proof, Action::await_change());

        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0]["phase"], "Quarantined");
        assert!(
            statuses[1]["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["type"] == FOOTPRINT_ABSENT_CONDITION && condition["status"] == "True"
                })
        );
        assert_eq!(requests_to(&server, "GET", RESERVATIONS_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
    }

    /// `FootprintAbsent` is the restart boundary. Once present, reconciliation
    /// must skip both placement-specific teardown paths and run only the
    /// idempotent reservation/terminal tail.
    #[tokio::test]
    async fn restart_from_footprint_proof_skips_claim_and_child_teardown() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut lease = child_placed_lease("child-lease-uid");
        {
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Releasing;
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        }
        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "persisted before controller restart",
        );

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 0);
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1
        );
        let terminal = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("terminal status");
        assert_eq!(terminal["phase"], "Released");
        assert!(
            terminal["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["type"] == FOOTPRINT_ABSENT_CONDITION && condition["status"] == "True"
                })
        );
    }

    /// A reservation API outage occurs after workload absence is durable. The
    /// proof must survive the failed tail so a retry neither rechecks nor
    /// re-destroys the external footprint.
    #[tokio::test]
    async fn reservation_failure_retains_footprint_proof_for_retry() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(RESERVATIONS_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 500, "reason": "InternalError"
            })))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        {
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Releasing;
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        }
        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "persisted before reservation cleanup",
        );

        let first = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(first, Action::requeue(std::time::Duration::from_secs(15)));
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert!(footprint_absence_proven(lease.status.as_ref().unwrap()));

        let retry = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(retry, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1
        );
        let terminal = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("terminal status after retry");
        assert!(
            terminal["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["type"] == FOOTPRINT_ABSENT_CONDITION && condition["status"] == "True"
                })
        );
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
        reconcile_release_after_checkpoint(lease, ctx, &server).await;

        assert_eq!(
            recorded_phases(&server).await,
            vec![
                "Releasing".to_string(),
                "Releasing".to_string(),
                "Released".to_string()
            ],
            "intent and footprint proof must be durable before the terminal write"
        );
        let delete = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| request.method.as_str() == "DELETE" && request.url.path() == CLAIM_PATH)
            .expect("claim DELETE");
        let delete_options: serde_json::Value =
            serde_json::from_slice(&delete.body).expect("DeleteOptions body");
        assert_eq!(delete_options["preconditions"]["uid"], "claim-uid");
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
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
                    "uid": "claim-uid",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                },
            })))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Ready);
        let action = reconcile_release_after_checkpoint(lease, ctx, &server).await;
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
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
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
        reconcile_release_after_checkpoint(lease, ctx, &server).await;

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
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
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
        status.ready_at = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        status.expires_at = Some((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());

        reconcile_release_after_checkpoint(lease, ctx, &server).await;

        assert_eq!(
            recorded_phases(&server).await,
            vec![
                "Releasing".to_string(),
                "Releasing".to_string(),
                "Expired".to_string()
            ]
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
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
            Some(ReleaseReason::Requested),
            "the durable request preserves its terminal outcome"
        );
        let mut interrupted = admitted_lease();
        interrupted.status.as_mut().unwrap().phase = SandboxLeasePhase::Releasing;
        assert_eq!(
            release_reason(&interrupted),
            Some(ReleaseReason::MissingCause),
            "an interrupted teardown without a durable cause fails closed"
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
            ReleaseReason::RuntimeTtl.terminal_phase(),
            SandboxLeasePhase::Expired
        );
        assert_eq!(
            ReleaseReason::Requested.terminal_phase(),
            SandboxLeasePhase::Released
        );
    }

    /// The earliest durable teardown signal owns the outcome, and the cause
    /// remains immutable once checkpointed.
    #[test]
    fn release_cause_orders_requests_and_deadlines_chronologically() {
        let deadline = chrono::Utc::now() - chrono::Duration::minutes(1);
        let before = deadline - chrono::Duration::seconds(1);
        let after = deadline + chrono::Duration::seconds(1);

        let runtime = |requested_at: chrono::DateTime<chrono::Utc>| {
            let mut lease = admitted_lease();
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Ready;
            status.ready_at = Some((deadline - chrono::Duration::hours(1)).to_rfc3339());
            status.expires_at = Some(deadline.to_rfc3339());
            lease.metadata.annotations.as_mut().unwrap().insert(
                SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.into(),
                requested_at.to_rfc3339(),
            );
            lease
        };
        assert_eq!(
            release_reason(&runtime(before)),
            Some(ReleaseReason::Requested)
        );
        assert_eq!(
            release_reason(&runtime(deadline)),
            Some(ReleaseReason::Requested)
        );
        assert_eq!(
            release_reason(&runtime(after)),
            Some(ReleaseReason::RuntimeTtl)
        );

        let mut provisioning = admitted_lease();
        provisioning.status.as_mut().unwrap().provisioning_deadline = Some(deadline.to_rfc3339());
        provisioning.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.into(),
            after.to_rfc3339(),
        );
        assert_eq!(
            release_reason(&provisioning),
            Some(ReleaseReason::ProvisioningDeadline)
        );

        // Persisted first cause beats every later signal.
        provisioning.status.as_mut().unwrap().release_cause =
            Some(crate::crd::SandboxReleaseCause::ProvisioningDeadline);
        provisioning.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.into(),
            before.to_rfc3339(),
        );
        assert_eq!(
            release_reason(&provisioning),
            Some(ReleaseReason::ProvisioningDeadline)
        );

        // A stale expiresAt cannot start the runtime clock without Ready proof.
        let mut not_ready = admitted_lease();
        not_ready.status.as_mut().unwrap().expires_at = Some(deadline.to_rfc3339());
        assert_eq!(release_reason(&not_ready), None);
    }

    /// Corrupt server-owned request time never beats a known elapsed deadline,
    /// but still represents immediate release intent when no clock elapsed.
    #[test]
    fn malformed_release_request_time_fails_closed_on_cause_ordering() {
        let mut expired = admitted_lease();
        let status = expired.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Ready;
        status.ready_at = Some((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339());
        status.expires_at = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        expired.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.into(),
            "not-a-timestamp".into(),
        );
        assert_eq!(release_reason(&expired), Some(ReleaseReason::RuntimeTtl));

        expired.status.as_mut().unwrap().ready_at = None;
        expired.status.as_mut().unwrap().expires_at = None;
        assert_eq!(release_reason(&expired), Some(ReleaseReason::Requested));
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
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Ready;
        status.ready_at = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());

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

    /// Provisioning also remains live when its deadline is malformed or still
    /// in the future; uncertainty must never be interpreted as permission to
    /// destroy a workload.
    #[test]
    fn a_malformed_or_future_provisioning_deadline_does_not_release() {
        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().phase = crate::crd::SandboxLeasePhase::Provisioning;

        for value in ["", "not-a-timestamp", "0", "1970-13-45T99:99:99Z"] {
            lease.status.as_mut().unwrap().provisioning_deadline = Some(value.to_string());
            assert_eq!(release_reason(&lease), None, "must not expire on {value:?}");
        }

        lease.status.as_mut().unwrap().provisioning_deadline =
            Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        assert_eq!(release_reason(&lease), None);
    }

    /// A cleanup condition must not silently drop the others.
    ///
    /// Lifecycle checkpoints replace the complete status value. A status
    /// carrying one condition would erase every other condition on the lease —
    /// and conditions are exactly what an operator reads to work out what
    /// happened.
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
            child_cluster_instance: Some(crate::crd::SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterInstance".into(),
                namespace: Some(NS.into()),
                name: "kobe-abc123".into(),
                uid: "child-instance-uid".into(),
                generation: Some(2),
            }),
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

    async fn mount_child_release_patch(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path(format!("{CLUSTER_LEASE_PATH}/status")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Released",
                    None,
                )),
            )
            .mount(server)
            .await;
    }

    fn child_cluster_lease(
        uid: &str,
        phase: &str,
        receipt: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut status = serde_json::json!({ "phase": phase });
        if let Some(receipt) = receipt {
            status["teardownReceipt"] = receipt;
        }
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": "kobe-sbx-sbx-1",
                "namespace": NS,
                "uid": uid,
                "resourceVersion": "42",
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "SandboxLease",
                    "name": LEASE,
                    "uid": "lease-uid-1",
                    "controller": true,
                }],
            },
            "spec": {
                "poolRef": "children",
                "ttl": "2h",
                "requester": { "type": "kobe:sandbox-composition", "identity": "kobe-operator" },
            },
            "status": status,
        })
    }

    /// A receipt about the exact instance recorded at composition time.
    fn verified_receipt(instance_name: &str, instance_uid: &str) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION,
            "attemptId": "attempt-1",
            "lease": { "name": "kobe-sbx-sbx-1", "uid": "child-lease-uid" },
            "instance": { "name": instance_name, "uid": instance_uid },
            "pool": { "name": "children", "uid": "cluster-pool-uid" },
            "backendType": "k3s",
            "configDigest": "digest",
            "instanceSpecDigest": "spec-digest",
            "startedAt": "2026-01-01T00:00:00Z",
            "completedAt": "2026-01-01T00:05:00Z",
            "checks": [{ "subject": "serverStatefulSet", "result": "verified" }],
            "outcome": "verified",
        })
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
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Bound",
                    None,
                )),
            )
            .mount(&server)
            .await;
        mount_child_release_patch(&server).await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            requests_to(&server, "DELETE", CLAIM_PATH).await,
            0,
            "the claim is in the child cluster; nothing here may stand in for it"
        );
        assert_eq!(
            requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await,
            0,
            "the internal lease is RELEASED, never deleted: deleting it destroys \
             the receipt at exactly the moment the evidence matters"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "capacity must not return while the tenant's cluster is still up"
        );
        let phases = recorded_phases(&server).await;
        assert_eq!(phases, vec!["Releasing".to_string()]);
    }

    /// Teardown acts on the recorded UID, not the recorded name — and a name
    /// that now belongs to somebody else is not evidence of anything.
    ///
    /// A different object under the same name belongs to a later Sandbox.
    /// Releasing it would destroy a running tenant's cluster. But its presence
    /// also does not prove OURS was destroyed: our lease is gone and its
    /// receipt went with it. #74 is explicit that the disappearance of a name
    /// is not evidence, so this quarantines rather than completing.
    #[tokio::test]
    async fn a_name_reused_by_a_later_composition_is_not_this_leases_cluster() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            // Somebody else's composition, under a reused name.
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "a-completely-different-uid",
                    "Bound",
                    None,
                )),
            )
            .mount(&server)
            .await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await,
            0,
            "a cluster this lease does not own must never be destroyed"
        );
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0,
            "nor may it be released"
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined"),
            "our own cluster's receipt is gone; absence of a name proves nothing"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "capacity is withheld precisely because nothing proved it safe"
        );
    }

    /// Recovery of an uncheckpointed child allocation is allowed only from an
    /// exact controller owner reference. A foreign owner and a recreated
    /// same-named SandboxLease are both somebody else's cluster.
    #[tokio::test]
    async fn unrecorded_child_with_foreign_or_recreated_owner_quarantines() {
        for (case, owner_name, owner_uid) in [
            ("foreign owner", "another-sandbox", "another-lease-uid"),
            ("same-name replacement", LEASE, "replacement-lease-uid"),
        ] {
            let (ctx, server) = test_context().await;
            mount_teardown_scaffolding(&server).await;
            let mut child = child_cluster_lease("child-lease-uid", "Bound", None);
            child["metadata"]["ownerReferences"][0]["name"] = serde_json::json!(owner_name);
            child["metadata"]["ownerReferences"][0]["uid"] = serde_json::json!(owner_uid);
            Mock::given(method("GET"))
                .and(path(CLUSTER_LEASE_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(child))
                .mount(&server)
                .await;

            let mut lease = child_placed_lease("child-lease-uid");
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Releasing;
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
            status.target.as_mut().unwrap().child_cluster_lease = None;

            let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
            assert_eq!(
                action,
                Action::requeue(std::time::Duration::from_secs(300)),
                "{case}"
            );
            assert_eq!(
                requests_to(&server, "GET", CLUSTER_LEASE_PATH).await,
                1,
                "{case}"
            );
            assert_eq!(
                requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
                0,
                "{case}: a foreign child must not be released"
            );
            assert_eq!(
                requests_to(
                    &server,
                    "DELETE",
                    &format!("{RESERVATIONS_PATH}/{}", reservation_name())
                )
                .await,
                0,
                "{case}: uncertain ownership must retain quota"
            );
            assert_eq!(
                recorded_phases(&server).await.last().map(String::as_str),
                Some("Quarantined"),
                "{case}"
            );
        }
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

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
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

        reconcile_release_after_checkpoint(lease, ctx, &server).await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1,
            "the slot it was holding must come back"
        );
    }

    /// A lease released while its child cluster was still being composed must
    /// not have its quota returned on a management-cluster 404.
    ///
    /// REVIEW FINDING (expected to fail). `compose_child_target` creates the
    /// internal `ClusterLease` first and only records `placement` +
    /// `target.childClusterLease` on the *next* reconcile, after
    /// `resolve_lease_binding` succeeds — which is minutes later, because the
    /// child cluster has to be provisioned. Between those two writes the lease
    /// carries no resolved placement.
    ///
    /// `drive_release` decides which teardown path to take from
    /// `status.placement`, so a release landing in that window takes the
    /// MANAGEMENT path: it deletes a `SandboxClaim` that was never created in
    /// this cluster, reads the 404 as proof of absence, and calls
    /// `finish_release`. The quota slot goes back while a whole child cluster
    /// is still allocated from the `ClusterPool` — the internal `ClusterLease`
    /// survives, because release marks the SandboxLease terminal rather than
    /// deleting it, so the owner reference collects nothing for a week.
    ///
    /// `a_composition_that_never_happened_releases_cleanly` looks like it
    /// covers this, but it sets `placement = ChildCluster` with
    /// `childClusterLease = None` — a state the single combined status patch
    /// can never produce. The reachable state is the opposite one, and it is
    /// untested.
    #[tokio::test]
    async fn a_composition_in_flight_is_not_released_by_a_management_cluster_404() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        // The child cluster lease exists: composition got as far as allocating
        // one, and it is still waiting to be bound.
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Pending",
                    None,
                )),
            )
            .mount(&server)
            .await;
        // Nothing was ever placed in the management cluster.
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

        // The state a real lease is in while its child cluster provisions: the
        // internal ClusterLease exists, but no placement has been recorded yet.
        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Pending;
        status.placement = None;
        status.target = None;

        reconcile_release_after_checkpoint(lease, ctx, &server).await;

        assert!(
            !recorded_phases(&server)
                .await
                .contains(&"Released".to_string()),
            "a lease holding an unbound child cluster must not reach a clean \
             terminal phase on a management-cluster 404; phases were {:?}",
            recorded_phases(&server).await
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "the quota slot must not come back while a child cluster is still allocated"
        );
    }

    /// Capacity returns only against a receipt for the exact instance.
    ///
    /// This is the point of composing through a `VerifiedDestroy` lease at all:
    /// the caller had a whole cluster to themselves, and the next caller gets
    /// it only once somebody proved the previous tenant's footprint is gone.
    #[tokio::test]
    async fn a_verified_receipt_for_the_recorded_instance_completes_the_release() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Released",
                    Some(verified_receipt("kobe-abc123", "child-instance-uid")),
                )),
            )
            .mount(&server)
            .await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1
        );
    }

    /// A receipt for a DIFFERENT instance must not release this lease.
    ///
    /// The child cluster can be destroyed and replaced under the same lease
    /// name — that is what recycling does. A receipt proving the replacement
    /// gone says nothing about the instance this Sandbox actually ran on, and
    /// accepting it would return capacity on the strength of evidence about
    /// somebody else's cluster. Present-but-wrong is the dangerous case,
    /// because it is the one a laxer check accepts.
    #[tokio::test]
    async fn a_receipt_for_another_instance_does_not_release_this_lease() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Released",
                    Some(verified_receipt("kobe-later", "a-later-instance-uid")),
                )),
            )
            .mount(&server)
            .await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
    }

    /// A child whose own teardown quarantined cannot release the outer lease.
    #[tokio::test]
    async fn a_quarantined_child_quarantines_the_sandbox_lease() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Quarantined",
                    None,
                )),
            )
            .mount(&server)
            .await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
    }

    /// Everything short of a complete, verified, correctly-addressed receipt
    /// fails closed.
    ///
    /// Each of these is a receipt that *looks* like evidence. A quarantined
    /// outcome, an unfinished attempt, a check that came back Unknown, or a
    /// schema this build does not understand are all "we could not prove it" —
    /// and an unrecorded instance UID is worse still, because two absent UIDs
    /// compare equal and any receipt would satisfy any lease.
    #[test]
    fn only_a_complete_receipt_about_this_instance_counts() {
        let recorded = crate::crd::SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterInstance".into(),
            namespace: Some(NS.into()),
            name: "kobe-abc123".into(),
            uid: "child-instance-uid".into(),
            generation: Some(2),
        };
        let parse = |value: serde_json::Value| -> crate::crd::TeardownReceipt {
            serde_json::from_value(value).expect("receipt fixture parses")
        };

        let good = parse(verified_receipt("kobe-abc123", "child-instance-uid"));
        assert!(receipt_proves_child_gone(&good, Some(&recorded)));

        // No recorded instance: nothing to compare against.
        assert!(!receipt_proves_child_gone(&good, None));

        // An empty recorded UID must not be satisfiable.
        let mut blank = recorded.clone();
        blank.uid = String::new();
        let mut blank_receipt = good.clone();
        blank_receipt.instance.uid = Some(String::new());
        assert!(!receipt_proves_child_gone(&blank_receipt, Some(&blank)));

        let mut quarantined = good.clone();
        quarantined.outcome = crate::crd::TeardownOutcome::Quarantined;
        assert!(!receipt_proves_child_gone(&quarantined, Some(&recorded)));

        let mut unfinished = good.clone();
        unfinished.completed_at = None;
        assert!(!receipt_proves_child_gone(&unfinished, Some(&recorded)));

        // Outcome says Verified but the evidence does not agree. The receipt is
        // not trusted over its own checks.
        let mut inconsistent = good.clone();
        inconsistent.checks = vec![crate::crd::TeardownCheck {
            subject: crate::crd::TeardownSubject::ServerStatefulSet,
            result: crate::crd::CheckResult::Unknown,
            reason: Some("api_error".into()),
            // Nothing was observed: an Unknown check has no verified subjects
            // to name, which is precisely what makes it Unknown.
            verified: Vec::new(),
        }];
        assert!(!receipt_proves_child_gone(&inconsistent, Some(&recorded)));

        let mut future_schema = good.clone();
        future_schema.schema_version = crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION + 1;
        assert!(!receipt_proves_child_gone(&future_schema, Some(&recorded)));

        // Right UID, wrong name — a shape mismatch that should never occur, and
        // must not be resolved in favour of releasing capacity.
        let mut renamed = good.clone();
        renamed.instance.name = "kobe-something-else".into();
        assert!(!receipt_proves_child_gone(&renamed, Some(&recorded)));
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
