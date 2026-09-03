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
//! is built from the administrator-owned pool spec and named by the controller.
//! Pool objects use same-cluster ownership; a management `SandboxClaim` instead
//! carries the exact lease UID and is deleted explicitly under the outer
//! finalizer, so garbage collection cannot bypass teardown proof. There is no
//! path from lease intent to a Pod spec, RuntimeClass, namespace, or host mount.
//!
//! # Admission is a precondition, not a formality
//!
//! Only leases annotated `admitted` are placed. A `pending` lease may exist
//! before its quota reservation committed, so acting on one would place work
//! that admission never authorised — the reason that annotation exists.

use std::{collections::BTreeMap, sync::Arc};

use futures::StreamExt;
use k8s_openapi::api::core::v1::{
    ConfigMap, Namespace, PersistentVolume, PersistentVolumeClaim, Pod, Secret,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
    Preconditions, PropagationPolicy,
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
use crate::crd::{
    SandboxCondition, SandboxConditionStatus, SandboxLease, SandboxLeasePhase,
    SandboxObjectReference, SandboxPlacement, SandboxPool, SandboxPoolStatus,
};
use crate::sandbox::{
    AGENT_SANDBOX_API_VERSION, CHILD_SANDBOX_NAMESPACE, SANDBOX_CLAIM_KIND, SANDBOX_TEMPLATE_KIND,
    SANDBOX_WARM_POOL_KIND, build_sandbox_claim, build_sandbox_template, build_sandbox_warm_pool,
};

/// Shared state for Sandbox placement and cleanup controllers.
pub struct SandboxContext {
    pub client: Client,
    /// Operator-owned namespace the upstream objects live in. Never
    /// caller-selectable: a lease that could choose its namespace could place
    /// work next to somebody else's.
    pub namespace: String,
    /// Dedicated, operator-only namespace for admission coordination Leases.
    /// It is separate from workload/control-plane objects so a hard ledger
    /// quota cannot starve unrelated controllers or leader election.
    pub reservation_namespace: String,
    /// Stops bounded runner cancellation during operator shutdown.
    shutdown: CancellationToken,
    /// Whether the protected distributed access ledger is available.
    /// Production lifecycle controllers always enable it; focused controller
    /// unit tests may disable it and exercise the barrier through its own
    /// API-server CAS suite instead of duplicating every teardown fixture.
    access_ledger_enabled: bool,
    /// Whether this process may create or advance Sandbox workload placement.
    /// Disabled-mode controllers set this false but still reconcile every
    /// admitted lease through verified teardown.
    pub placement_enabled: bool,
    /// Runtime ownership mode carried into child-pool certification.
    pub runtime_mode: crate::sandbox_runtime::AgentSandboxMode,
    /// Exact chart identity required for managed child bootstrap references.
    pub managed_runtime_identity: Option<crate::sandbox_runtime::ManagedRuntimeIdentity>,
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

pub(crate) fn allocation_fence_name(lease: &str) -> String {
    format!("kobe-sbx-fence-{lease}")
}

/// Absolute deadline stored on an inert management Claim. The Claim name stays
/// occupied beyond the outer lease's audit-retention window, so a delayed
/// create from an older reconcile cannot resurrect workload after teardown.
pub(crate) const SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION: &str =
    "kobe.kunobi.ninja/tombstone-retain-until";

/// Original workload Claim UID when release had to create a replacement
/// tombstone after the workload Claim was already absent.
pub(crate) const SANDBOX_CLAIM_TOMBSTONE_PRIOR_UID_LABEL: &str =
    "kobe.kunobi.ninja/prior-sandbox-claim-uid";
pub(crate) const SANDBOX_CLAIM_TOMBSTONE_LABEL: &str = "kobe.kunobi.ninja/sandbox-claim-tombstone";

/// The final authorization read and the Claim POST share this deadline. A
/// release fence only has to drain this bounded interval before absence can be
/// considered stable; a timed-out POST is always recovered by exact GET.
pub(crate) const SANDBOX_CLAIM_CREATE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Extra time beyond the bounded create interval before a tombstone can be
/// reaped. This absorbs watch/API scheduling jitter without weakening the
/// lease-retention guarantee.
const SANDBOX_CLAIM_TOMBSTONE_MARGIN: chrono::Duration = chrono::Duration::minutes(5);

pub(crate) const SANDBOX_ALLOCATION_FENCE_LABEL: &str =
    "kobe.kunobi.ninja/sandbox-allocation-fence";
pub(crate) const SANDBOX_ALLOCATION_FENCE_RETAIN_UNTIL_ANNOTATION: &str =
    "kobe.kunobi.ninja/allocation-fence-retain-until";
pub(crate) const SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION: &str =
    "kobe.kunobi.ninja/sandbox-lease-name";
const SANDBOX_ALLOCATION_FENCE_HOLDER_PREFIX: &str = "closed:";
const SANDBOX_ALLOCATION_DRAIN_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Result of making the deterministic management Claim name an inert durable
/// release fence.
#[derive(Debug)]
pub(super) enum ManagementClaimTombstone {
    /// Exact tombstone identity was just persisted; reconcile from the fresh
    /// status object before proving anything absent.
    Checkpointed,
    /// The exact recorded Claim exists, is expired with `Retain`, and has a
    /// future reaping deadline.
    Ready {
        claim: Box<DynamicObject>,
        tombstone_ref: crate::crd::SandboxObjectReference,
        prior_claim_uid: Option<String>,
    },
    /// A normal converging or optimistic-race state.
    Retry(std::time::Duration),
    /// Durable identity uncertainty. The caller must quarantine while cleanup
    /// proof is still mutable, or record a durable post-proof failure.
    Quarantine(&'static str),
}

#[derive(Debug)]
enum AllocationFence {
    Checkpointed,
    Draining(std::time::Duration),
    Ready,
    Quarantine(&'static str),
}

/// What reachable execution cleanup permits the release state machine to do.
///
/// `DestroyTarget` is intentionally distinct from `Retry`: a terminal runner
/// verdict without process-absence proof must retain its record and capacity,
/// but it must also let management Claim or child-cluster destruction advance.
/// Exact target absence then authorises the post-proof retirement pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionCleanupAdvance {
    Continue,
    Checkpointed,
    DestroyTarget,
    Retry,
    Quarantine(&'static str),
}

/// Re-list execution cleanup state after one durable child-resource mutation.
///
/// The lifecycle controller watches [`SandboxLease`] objects, not the access
/// ledger Lease or [`crate::crd::SandboxExecution`] records mutated by cleanup.
/// `Action::await_change()` would therefore strand a lease after a successful
/// checkpoint when no unrelated parent update happens to wake it.
fn execution_cleanup_checkpoint_action() -> Action {
    Action::requeue(std::time::Duration::from_secs(1))
}

fn execution_cleanup_advance(
    outcome: crate::api::sandbox_executions::ExecutionCleanupOutcome,
) -> ExecutionCleanupAdvance {
    match outcome {
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Clean => {
            ExecutionCleanupAdvance::Continue
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Checkpointed => {
            ExecutionCleanupAdvance::Checkpointed
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::AwaitTargetDestruction => {
            ExecutionCleanupAdvance::DestroyTarget
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Retry => {
            ExecutionCleanupAdvance::Retry
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Quarantine(reason) => {
            ExecutionCleanupAdvance::Quarantine(reason)
        }
    }
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

/// One core/v1 resource addressed through the same dynamic-object machinery
/// used for upstream Agent Sandbox kinds.
fn core_resource(kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: String::new(),
        version: "v1".into(),
        api_version: "v1".into(),
        kind: kind.into(),
        plural: plural.into(),
    }
}

fn sandbox_resource() -> ApiResource {
    ApiResource {
        group: "agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: crate::controllers::sandbox_canary::SANDBOX_API_VERSION.into(),
        kind: crate::controllers::sandbox_canary::SANDBOX_KIND.into(),
        plural: "sandboxes".into(),
    }
}

/// Create or update one exact controller-owned upstream object.
///
/// Ownership is checked before force-SSA and updates carry the observed
/// resourceVersion. Without both fences, a same-named foreign object or a
/// delete-and-recreate race could be adopted while correcting ordinary drift.
async fn apply_upstream(
    client: &Client,
    namespace: &str,
    resource: &ApiResource,
    object: &DynamicObject,
    owner: &OwnerReference,
) -> Result<DynamicObject, SandboxPlacementError> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, resource);
    let existing = match api.get(&object.name_any()).await {
        Ok(existing) => Some(existing),
        Err(kube::Error::Api(error)) if error.code == 404 => {
            match api.create(&PostParams::default(), object).await {
                Ok(created) => {
                    if !metadata_is_controlled_by(
                        &created.metadata,
                        &owner.api_version,
                        &owner.kind,
                        &owner.name,
                        &owner.uid,
                    ) {
                        return Err(SandboxPlacementError::Invalid(format!(
                            "created {} {} without the expected owner",
                            resource.kind,
                            object.name_any()
                        )));
                    }
                    return Ok(created);
                }
                Err(kube::Error::Api(error)) if error.code == 409 => {
                    Some(api.get(&object.name_any()).await?)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };
    let existing = existing.expect("owned object lookup resolves above");
    if !metadata_is_controlled_by(
        &existing.metadata,
        &owner.api_version,
        &owner.kind,
        &owner.name,
        &owner.uid,
    ) {
        return Err(SandboxPlacementError::Invalid(format!(
            "{} {} exists but is not controlled by {} {} uid {}",
            resource.kind,
            object.name_any(),
            owner.kind,
            owner.name,
            owner.uid
        )));
    }
    let resource_version = existing.resource_version().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "{} {} has no resourceVersion",
            resource.kind,
            object.name_any()
        ))
    })?;
    let mut desired = object.clone();
    desired.metadata.resource_version = Some(resource_version);
    let applied = api
        .patch(
            &object.name_any(),
            &PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY).force(),
            &Patch::Apply(&desired),
        )
        .await?;
    if !metadata_is_controlled_by(
        &applied.metadata,
        &owner.api_version,
        &owner.kind,
        &owner.name,
        &owner.uid,
    ) {
        return Err(SandboxPlacementError::Invalid(format!(
            "{} {} changed owner during reconciliation",
            resource.kind,
            object.name_any()
        )));
    }
    Ok(applied)
}

/// Apply one pool's `SandboxTemplate` and `SandboxWarmPool` into a cluster.
///
/// Shared by management placement and by child composition, so the two cannot
/// drift into projecting a pool differently — #76 asks for equivalent
/// semantics across placements, and equivalence built from one code path is
/// the only kind that stays true.
///
/// In management placement `owner` is the exact `SandboxPool`; in a child it is
/// the exact target `Namespace`. Both are same-cluster controller references,
/// so no upstream object is ever adopted by name alone.
async fn ensure_upstream_pool_objects(
    client: &Client,
    namespace: &str,
    pool_name: &str,
    spec: &crate::crd::SandboxPoolSpec,
    owner: &OwnerReference,
) -> Result<(DynamicObject, DynamicObject), SandboxPlacementError> {
    let template = build_sandbox_template(&template_name(pool_name), namespace, spec, Some(owner))?;
    let template = apply_upstream(
        client,
        namespace,
        &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
        &template,
        owner,
    )
    .await?;

    let warm_pool = build_sandbox_warm_pool(
        &warm_pool_name(pool_name),
        namespace,
        &template_name(pool_name),
        spec.warm_capacity,
        Some(owner),
    )?;
    let warm_pool = apply_upstream(
        client,
        namespace,
        &upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
        &warm_pool,
        owner,
    )
    .await?;
    Ok((template, warm_pool))
}

const POOL_READY_CONDITION: &str = "Ready";
const POOL_CERTIFICATION_PENDING_REASON: &str = "CertificationPending";

#[derive(Debug, Clone)]
struct WarmPoolObservation {
    replicas: u32,
    ready_replicas: u32,
    template: DynamicObject,
    warm_pool: DynamicObject,
}

/// Observe the exact upstream objects that back one management pool.
///
/// Reconciliation writes the desired objects first, then this independent GET
/// proves their exact Pool owner and reads the WarmPool controller's
/// `replicas`/`readyReplicas`. A create/apply response is not reused as
/// readiness evidence: it may predate the upstream controller's status write.
/// True while a certification protocol attempt is between its fence install
/// and the fence's confirmed removal. In that window the pool's WarmPool is
/// deliberately drained and restored by the protocol itself, so the outer
/// freshness and full-capacity gates describe states the protocol cannot be
/// in — enforcing them starves the very arms that would leave the window.
pub(crate) fn certification_protocol_in_flight(pool: &SandboxPool) -> bool {
    pool.status
        .as_ref()
        .and_then(|status| status.certification.as_ref())
        .is_some_and(|certification| certification_phase_is_in_flight(&certification.phase))
}

pub(crate) fn certification_phase_is_in_flight(
    phase: &crate::crd::sandbox::SandboxPoolCertificationPhase,
) -> bool {
    use crate::crd::sandbox::SandboxPoolCertificationPhase as Phase;
    matches!(
        phase,
        Phase::FenceInstalled
            | Phase::DrainAcknowledged
            | Phase::ClaimDeleting
            | Phase::AbsenceProven
            | Phase::Replenished
            | Phase::FenceFinalizerRemoved
            | Phase::FenceDeleting
    )
}

async fn observe_management_pool(
    ctx: &SandboxContext,
    pool: &SandboxPool,
) -> Result<WarmPoolObservation, SandboxPlacementError> {
    let pool_uid = pool.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxPool {} has no UID to fence its upstream objects",
            pool.name_any()
        ))
    })?;
    let expected_owner = (
        "kobe.kunobi.ninja/v1alpha1",
        "SandboxPool",
        pool.name_any(),
        pool_uid,
    );

    let template_api: Api<DynamicObject> = Api::namespaced_with(
        ctx.client.clone(),
        &ctx.namespace,
        &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
    );
    let template = template_api.get(&template_name(&pool.name_any())).await?;
    if template.uid().is_none_or(|uid| uid.is_empty())
        || !is_controlled_by(
            &template,
            expected_owner.0,
            expected_owner.1,
            &expected_owner.2,
            &expected_owner.3,
        )
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxTemplate {} is not the exact object owned by SandboxPool {} uid {}",
            template_name(&pool.name_any()),
            pool.name_any(),
            expected_owner.3
        )));
    }
    let owner = pool.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxPool {} cannot own its upstream objects",
            pool.name_any()
        ))
    })?;
    let desired_template = build_sandbox_template(
        &template_name(&pool.name_any()),
        &ctx.namespace,
        &pool.spec,
        Some(&owner),
    )?;
    if template.data.get("spec") != desired_template.data.get("spec") {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxTemplate {} spec does not match SandboxPool {}",
            template.name_any(),
            pool.name_any()
        )));
    }

    let warm_pool_api: Api<DynamicObject> = Api::namespaced_with(
        ctx.client.clone(),
        &ctx.namespace,
        &upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
    );
    let warm_pool = warm_pool_api.get(&warm_pool_name(&pool.name_any())).await?;
    if warm_pool.uid().is_none_or(|uid| uid.is_empty())
        || !is_controlled_by(
            &warm_pool,
            expected_owner.0,
            expected_owner.1,
            &expected_owner.2,
            &expected_owner.3,
        )
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxWarmPool {} is not the exact object owned by SandboxPool {} uid {}",
            warm_pool_name(&pool.name_any()),
            pool.name_any(),
            expected_owner.3
        )));
    }
    let desired_warm_pool = build_sandbox_warm_pool(
        &warm_pool_name(&pool.name_any()),
        &ctx.namespace,
        &template_name(&pool.name_any()),
        pool.spec.warm_capacity,
        Some(&owner),
    )?;
    // Between fence install and fence deletion the certification arms own
    // `spec.replicas` (drain to zero, restore to capacity), so the exact
    // comparison accepts the live value for that one field. Every other
    // field must still match the Pool byte-for-byte.
    let mut desired_spec = desired_warm_pool
        .data
        .get("spec")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if certification_protocol_in_flight(pool)
        && let Some(desired_map) = desired_spec.as_object_mut()
    {
        match warm_pool.data.pointer("/spec/replicas").cloned() {
            Some(live) => {
                desired_map.insert("replicas".into(), live);
            }
            None => {
                desired_map.remove("replicas");
            }
        }
    }
    if warm_pool.data.get("spec") != Some(&desired_spec) {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxWarmPool {} spec does not match SandboxPool {}",
            warm_pool.name_any(),
            pool.name_any()
        )));
    }

    let status = warm_pool
        .data
        .get("status")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxWarmPool {} has no status",
                warm_pool.name_any()
            ))
        })?;
    // Upstream serializes its counters with `omitempty`: a zero-member pool
    // omits the field entirely, so absence IS the zero reading. Only a
    // present-but-malformed value is an invalid observation.
    let count = |field: &'static str| match status.get(field) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                SandboxPlacementError::Invalid(format!(
                    "SandboxWarmPool {} has invalid status.{field}",
                    warm_pool.name_any()
                ))
            }),
    };
    let warm_pool_generation = warm_pool.metadata.generation.ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxWarmPool {} has no generation",
            warm_pool.name_any()
        ))
    })?;
    // Mid-protocol, the certification arms scale the WarmPool themselves and
    // wait for the exact drain/replenish generation with their own barriers;
    // demanding currency here would block those arms from ever running while
    // upstream is still catching up to the protocol's own writes.
    if !certification_protocol_in_flight(pool)
        && status
            .get("observedGeneration")
            .and_then(serde_json::Value::as_i64)
            != Some(warm_pool_generation)
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxWarmPool {} has not observed generation {warm_pool_generation}",
            warm_pool.name_any()
        )));
    }
    let observation = WarmPoolObservation {
        replicas: count("replicas")?,
        ready_replicas: count("readyReplicas")?,
        template,
        warm_pool,
    };
    if observation.ready_replicas > observation.replicas {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxWarmPool {} reports readyReplicas greater than replicas",
            observation.warm_pool.name_any()
        )));
    }
    Ok(observation)
}

/// Count only admitted leases bound to the exact Pool UID.
///
/// The name label is intentionally not authoritative: a deleted-and-recreated
/// pool has the same label, and older objects may be missing it. UID filtering
/// over the complete namespace list keeps replacement capacity separate.
fn pool_allocation_counts(
    leases: impl IntoIterator<Item = SandboxLease>,
    pool_uid: &str,
) -> Result<(u32, u32), SandboxPlacementError> {
    let mut allocated = 0u32;
    let mut quarantined = 0u32;
    for lease in leases {
        if lease.spec.pool_ref.uid != pool_uid
            || lease
                .annotations()
                .get(SANDBOX_ADMISSION_ANNOTATION)
                .map(String::as_str)
                != Some(SANDBOX_ADMISSION_ADMITTED)
        {
            continue;
        }
        let phase = lease
            .status
            .as_ref()
            .map(|status| status.phase)
            .unwrap_or_default();
        if phase.consumes_capacity() {
            allocated = allocated.checked_add(1).ok_or_else(|| {
                SandboxPlacementError::Invalid(
                    "SandboxPool allocated lease count exceeds u32".into(),
                )
            })?;
        }
        if phase == SandboxLeasePhase::Quarantined {
            quarantined = quarantined.checked_add(1).ok_or_else(|| {
                SandboxPlacementError::Invalid(
                    "SandboxPool quarantined lease count exceeds u32".into(),
                )
            })?;
        }
    }
    Ok((allocated, quarantined))
}

/// Build one current-generation Pool readiness result.
///
/// Counters remain observations; only `Ready=True` authorizes admission. The
/// caller must therefore pass `certified=true` only after completing every
/// placement-specific live check described by [`reconcile_pool`].
fn pool_status(
    pool: &SandboxPool,
    ready: u32,
    allocated: u32,
    quarantined: u32,
    certified: bool,
    reason: &str,
    message: &str,
) -> Result<SandboxPoolStatus, SandboxPlacementError> {
    let generation = pool.metadata.generation.ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxPool {} has no generation to observe",
            pool.name_any()
        ))
    })?;
    let previous = pool.status.as_ref().and_then(|status| {
        status
            .conditions
            .iter()
            .find(|condition| condition.condition_type == POOL_READY_CONDITION)
    });
    let last_transition_time = match previous {
        Some(previous)
            if previous.status
                == if certified {
                    SandboxConditionStatus::True
                } else {
                    SandboxConditionStatus::False
                } =>
        {
            previous.last_transition_time.clone()
        }
        _ => Some(chrono::Utc::now().to_rfc3339()),
    };
    let mut conditions: Vec<_> = pool
        .status
        .as_ref()
        .map(|status| status.conditions.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|condition| condition.condition_type != POOL_READY_CONDITION)
        .collect();
    conditions.push(SandboxCondition {
        condition_type: POOL_READY_CONDITION.into(),
        status: if certified {
            SandboxConditionStatus::True
        } else {
            SandboxConditionStatus::False
        },
        reason: reason.into(),
        message: message.into(),
        observed_generation: Some(generation),
        last_transition_time,
    });
    Ok(SandboxPoolStatus {
        observed_generation: Some(generation),
        ready,
        allocated,
        quarantined,
        // The resolved placement is mirrored into status so the CRD's
        // placement invariants stay status-only: a spec-only edit carries the
        // previous status over unchanged and must not be rejected for
        // disagreeing with itself.
        placement: Some(pool.spec.placement.clone()),
        placement_authority: None,
        certification: pool
            .status
            .as_ref()
            .and_then(|status| status.certification.clone()),
        conditions,
    })
}

/// Replace Pool status only for the exact UID/resourceVersion reconciled.
/// A lost race returns `false`; the winning watch event owns the next write.
async fn patch_pool_status_fenced(
    ctx: &SandboxContext,
    pool: &SandboxPool,
    status: &SandboxPoolStatus,
) -> Result<bool, SandboxPlacementError> {
    if pool.status.as_ref() == Some(status) {
        return Ok(true);
    }
    let (Some(uid), Some(resource_version)) = (pool.uid(), pool.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxPool {} has no UID or resourceVersion to fence status",
            pool.name_any()
        )));
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/status", "value": status }
    ]));
    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match pools
        .patch_status(
            &pool.name_any(),
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

/// Reconcile one `SandboxPool` into its controller-owned upstream objects.
///
/// Every placement reports exact-UID lease allocation. Management placement
/// additionally creates and independently observes its exact-owned upstream
/// Template/WarmPool. Child pools do not create management-cluster capacity.
///
/// `Ready=True` is published only after placement-specific live proof.
/// Management validates the pinned runtime, exact WarmPool population,
/// restricted scheduled Pods, strict NetworkPolicy and real execution canary.
/// Child placement proves composition eligibility and repeats runtime/canary
/// checks inside the exact child before its Claim. Replica counters alone
/// never authorize admission.
pub async fn reconcile_pool(
    pool: Arc<SandboxPool>,
    ctx: Arc<SandboxContext>,
) -> Result<Action, SandboxPlacementError> {
    let name = pool.name_any();
    let pool_uid = pool
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| SandboxPlacementError::Invalid(format!("SandboxPool {name} has no UID")))?;
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let lease_list = match leases.list(&ListParams::default()).await {
        Ok(leases) => leases,
        Err(error) => {
            let previous = pool.status.clone().unwrap_or_default();
            let status = pool_status(
                &pool,
                0,
                previous.allocated,
                previous.quarantined,
                false,
                "LeaseAccountingUnavailable",
                "Exact-UID lease accounting is unavailable; pool certification is withheld",
            )?;
            patch_pool_status_fenced(&ctx, &pool, &status).await?;
            return Err(error.into());
        }
    };
    let (allocated, quarantined) = pool_allocation_counts(lease_list, &pool_uid)?;

    if let SandboxPlacement::ChildCluster { cluster_pool_ref } = &pool.spec.placement {
        let cluster_pools: Api<crate::crd::ClusterPool> =
            Api::namespaced(ctx.client.clone(), &ctx.namespace);
        let child_result = async {
            let cluster_pool = cluster_pools.get(cluster_pool_ref).await?;
            let authority = crate::controllers::sandbox_child::eligible_child_placement_authority(
                &pool,
                &cluster_pool,
                &ctx.namespace,
            )?;
            if ctx.runtime_mode != crate::sandbox_runtime::AgentSandboxMode::Managed {
                return Err(SandboxPlacementError::Invalid(
                    "child placement requires agentSandbox.mode=managed".into(),
                ));
            }
            let identity = ctx.managed_runtime_identity.as_ref().ok_or_else(|| {
                SandboxPlacementError::Invalid(
                    "managed child bootstrap identity is unavailable".into(),
                )
            })?;
            crate::controllers::sandbox_child::validate_managed_child_bootstrap(
                &ctx.client,
                &ctx.namespace,
                &cluster_pool,
                identity,
            )
            .await?;
            Ok::<_, SandboxPlacementError>(authority)
        }
        .await;
        let (reason, message, authority) = match child_result {
            Ok(authority) => (
                "CompositionEligible",
                format!(
                    "ClusterPool {cluster_pool_ref} is eligible for verified composition and references the exact managed runtime bootstrap; live child certification remains required before its tenant Claim"
                ),
                Some(authority),
            ),
            Err(error) => (
                "ChildPlacementUnavailable",
                format!("Child placement certification is withheld: {error}"),
                None,
            ),
        };
        let mut status = pool_status(&pool, 0, allocated, quarantined, false, reason, &message)?;
        status.placement_authority = authority;
        if !patch_pool_status_fenced(&ctx, &pool, &status).await? {
            debug!(pool = %name, "child SandboxPool status write lost a race");
            return Ok(Action::await_change());
        }
        debug!(pool = %name, "reconciled fail-closed child SandboxPool eligibility");
        return Ok(Action::requeue(std::time::Duration::from_secs(30)));
    }

    let owner = pool.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxPool {name} has no UID to own its objects"))
    })?;

    let observation = match async {
        // Mid-protocol the certification arms own the WarmPool: re-asserting
        // spec.replicas = warmCapacity here would undo every drain one beat
        // after it lands, churning upstream through delete/create cycles
        // forever. The arms' UID/resourceVersion fences carry the identity
        // protection for that window.
        if !certification_protocol_in_flight(&pool) {
            ensure_upstream_pool_objects(
                &ctx.client,
                &ctx.namespace,
                &name,
                &pool.spec,
                // Owner-referenced here, where the parent SandboxPool actually exists.
                &owner,
            )
            .await?;
        }
        observe_management_pool(&ctx, &pool).await
    }
    .await
    {
        Ok(observation) => observation,
        Err(error) => {
            let status = pool_status(
                &pool,
                0,
                allocated,
                quarantined,
                false,
                "UpstreamObservationUnavailable",
                "Exact-owned Template/WarmPool replicas are unavailable; pool certification is withheld",
            )?;
            patch_pool_status_fenced(&ctx, &pool, &status).await?;
            return Err(error);
        }
    };
    // The full-capacity gate applies only to STARTING (or re-validating) a
    // certification. Mid-protocol the arms drain the pool to zero and restore
    // it by design, so their own barriers — not this gate — decide progress.
    let certification = if !certification_protocol_in_flight(&pool)
        && (observation.replicas != pool.spec.warm_capacity
            || observation.ready_replicas != pool.spec.warm_capacity)
    {
        Err(format!(
            "WarmPool has replicas={}/readyReplicas={}, expected {} exact Ready members",
            observation.replicas, observation.ready_replicas, pool.spec.warm_capacity
        ))
    } else {
        Box::pin(
            crate::controllers::sandbox_pool_certification::reconcile_management_pool_certification(
                &ctx.client,
                &ctx.namespace,
                &pool,
                &observation.template,
                &observation.warm_pool,
            ),
        )
        .await
    };
    let (certified, ready, reason, message, progress_status, mutated) = match certification {
        Ok(progress) => (
            progress.certified,
            progress.ready,
            progress.reason,
            progress.message,
            Some(progress.status),
            progress.mutated,
        ),
        Err(error) => (
            false,
            observation.ready_replicas,
            POOL_CERTIFICATION_PENDING_REASON,
            format!("Management placement certification is withheld: {error}"),
            pool.status
                .as_ref()
                .and_then(|status| status.certification.clone()),
            false,
        ),
    };
    // Creating a Claim or fence is the sole mutation for that reconcile. Its
    // returned identity is deliberately checkpointed by the next strong GET.
    if mutated {
        return Ok(Action::requeue(std::time::Duration::from_secs(1)));
    }
    let mut status = pool_status(
        &pool,
        ready,
        allocated,
        quarantined,
        certified,
        reason,
        &message,
    )?;
    status.certification = progress_status;
    if !patch_pool_status_fenced(&ctx, &pool, &status).await? {
        debug!(pool = %name, "SandboxPool status write lost a race");
        return Ok(Action::await_change());
    }

    debug!(pool = %name, certified, "reconciled management SandboxPool certification");
    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// Reconcile one admitted `SandboxLease` into exactly one `SandboxClaim`.
///
/// Creation is `create`-then-tolerate-409 rather than apply: exactly one claim
/// per lease is the invariant, and a create that loses the race has already
/// been satisfied by whoever won it. Terminal leases never resolve a pool or
/// recreate workload; clean terminal leases only remove Kobe's cleanup
/// finalizer after both teardown proof checkpoints are durable.
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

    let status = lease.status.clone().unwrap_or_default();
    match status.phase {
        crate::crd::SandboxLeasePhase::Released | crate::crd::SandboxLeasePhase::Expired => {
            if sandbox_finalizer_present(&lease) {
                if footprint_absence_proven(&status) && cleanup_verified(&status) {
                    if patch_sandbox_finalizer(&ctx, &lease, false).await? {
                        info!(lease = %name, "removed Sandbox cleanup finalizer after verified teardown");
                    } else {
                        debug!(lease = %name, "cleanup finalizer removal lost an object race");
                    }
                    return Ok(Action::await_change());
                }
                warn!(lease = %name, "clean terminal Sandbox lease lacks durable teardown proof; retaining finalizer");
                return Ok(Action::requeue(std::time::Duration::from_secs(300)));
            }
            debug!(lease = %name, "clean terminal Sandbox lease is inert");
            return Ok(Action::await_change());
        }
        crate::crd::SandboxLeasePhase::Quarantined => {
            // Quarantine keeps the finalizer and quota, then periodically
            // retries the exact evidence path below. A repaired permission or
            // backend may make proof available later; only that proof can move
            // it to a clean terminal phase.
            if status.release_cause.is_none() {
                warn!(lease = %name, "quarantined Sandbox lease has no durable release cause; retaining finalizer and capacity");
                return Ok(Action::requeue(std::time::Duration::from_secs(300)));
            }
            debug!(lease = %name, "retrying quarantined Sandbox teardown evidence");
        }
        _ => {}
    }

    // Admission creates the finalizer before reservations commit. Backfill a
    // legacy admitted object before touching its pool or footprint, fenced so
    // a stale reconcile cannot modify a same-named replacement. Kubernetes
    // forbids adding a finalizer after deletion has begun; such a legacy object
    // therefore fails closed instead of pretending it can be protected.
    if !sandbox_finalizer_present(&lease) {
        if lease.metadata.deletion_timestamp.is_some() {
            warn!(lease = %name, "deleting admitted Sandbox lease is missing cleanup finalizer");
            return Ok(Action::await_change());
        }
        if patch_sandbox_finalizer(&ctx, &lease, true).await? {
            info!(lease = %name, "backfilled Sandbox cleanup finalizer");
        } else {
            debug!(lease = %name, "cleanup finalizer backfill lost an object race");
        }
        return Ok(Action::await_change());
    }

    // Teardown is evaluated BEFORE the pool is resolved, and deliberately so.
    // Release must work when the pool was edited or deleted outright — those
    // are exactly the situations that strand capacity — so it must not sit
    // behind a fence that a missing pool would fail.
    if let Some(reason) = release_reason(&lease) {
        return drive_release(&lease, &ctx, reason).await;
    }

    // `disabled` stops admission and placement, but it must not stop lifecycle
    // ownership for leases admitted by the previous configuration. Drain every
    // nonterminal lease through the ordinary, evidence-gated release path.
    // Existing Releasing causes were handled above and remain immutable.
    if !ctx.placement_enabled {
        return drive_release(&lease, &ctx, ReleaseReason::ModeDisabled).await;
    }

    // `admitted` is only the arbitration winner; it is not sufficient workload
    // authority on its own. The same atomic patch must also have persisted the
    // exact pre-created gate name+UID, and that object must still be the
    // canonical open gate. A lost/mutated admission response can otherwise
    // leave a caller holding a durable lease whose controller creates a
    // workload that teardown can never drain safely.
    if ctx.access_ledger_enabled {
        match crate::sandbox_access_ledger::verify_open_admitted_gate(
            &ctx.client,
            &ctx.reservation_namespace,
            &lease,
        )
        .await
        {
            Ok(()) => {}
            Err(
                crate::sandbox_access_ledger::AccessLedgerError::Invalid(_)
                | crate::sandbox_access_ledger::AccessLedgerError::Serialization(_),
            ) => {
                return quarantine_unverifiable_gate(&lease, &ctx, "access_gate_unverifiable")
                    .await;
            }
            Err(crate::sandbox_access_ledger::AccessLedgerError::Kubernetes(kube::Error::Api(
                response,
            ))) if response.code == 401 || response.code == 403 => {
                return quarantine_unverifiable_gate(&lease, &ctx, "access_gate_forbidden").await;
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not verify admitted Sandbox access gate");
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
        }
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
            // Pool objects are owned by the SandboxPool. The Claim is not
            // owned by the SandboxLease: it must survive GC until explicit
            // teardown proof is durable.
            owned: true,
            claim_owner: None,
        },
        SandboxPlacement::ChildCluster { cluster_pool_ref } => {
            if current_sandbox_pool_for_create(&lease, &pools)
                .await?
                .is_none()
            {
                debug!(lease = %name, pool = %lease.spec.pool_ref.name, "child composition withheld until current pool certification");
                return Ok(Action::requeue(std::time::Duration::from_secs(10)));
            }
            // Child runtime certification contains its own multi-checkpoint
            // async state machine. Heap it so management/release reconciles do
            // not inherit that future's stack footprint.
            match Box::pin(compose_child_target(&lease, &pool, cluster_pool_ref, &ctx)).await? {
                ChildTarget::Ready(target) => target,
                ChildTarget::Pending(action) => return Ok(action),
            }
        }
    };
    let claim_resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
    let claims: Api<DynamicObject> =
        Api::namespaced_with(target.client.clone(), &target.namespace, &claim_resource);

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

        // Migrate a Claim emitted by the previous protocol before claiming the
        // FinalizerV1 invariant. The finalizer and ownerRef removal are one
        // UID/RV-fenced metadata patch; ending the pass prevents any workload
        // use before a fresh read sees the complete fence.
        if status.claim_cleanup_fence.is_none() {
            match claims.get(&claim_name(&name)).await {
                Ok(observed) => {
                    if let Some(recorded) = status
                        .target
                        .as_ref()
                        .and_then(|target| target.sandbox_claim.as_ref())
                    {
                        require_exact_reference(
                            recorded,
                            AGENT_SANDBOX_API_VERSION,
                            SANDBOX_CLAIM_KIND,
                            &target.namespace,
                            &claim_name(&name),
                            &observed,
                        )?;
                    }
                    match ensure_management_claim_fenced(
                        &claims,
                        &observed,
                        &lease,
                        &target.namespace,
                    )
                    .await?
                    {
                        ManagementClaimFence::Ready => {}
                        ManagementClaimFence::Patched => {
                            info!(lease = %name, claim = %observed.name_any(), "migrated exact legacy management Claim cleanup fence");
                            return Ok(Action::await_change());
                        }
                        ManagementClaimFence::Foreign => {
                            return Err(SandboxPlacementError::Invalid(format!(
                                "management SandboxClaim {} cannot be migrated to the cleanup fence",
                                observed.name_any()
                            )));
                        }
                    }
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => return Err(error.into()),
            }

            // Only a verified 404 or a freshly-read fenced Claim reaches this
            // checkpoint. Every later create body also carries the finalizer.
            status.claim_cleanup_fence = Some(crate::crd::SandboxClaimCleanupFence::FinalizerV1);
            if patch_lease_status_fenced(&ctx, &lease, &status).await? {
                debug!(lease = %name, "recorded management Claim cleanup fence");
            } else {
                debug!(lease = %name, "management Claim cleanup-fence write lost a status race");
            }
            return Ok(Action::await_change());
        }
    }

    let lease_uid = lease.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxLease {name} has no UID to fence its claim"))
    })?;
    let provisioning_deadline = status
        .provisioning_deadline
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no parseable provisioning deadline for its Claim backstop"
            ))
        })?;
    let claim_owner = target.claim_owner.as_deref();
    let claim = build_sandbox_claim(
        &claim_name(&name),
        &target.namespace,
        &warm_pool_name(&pool.name_any()),
        &lease_uid,
        provisioning_deadline,
        target.owned,
        claim_owner,
    );

    let recorded_claim = status
        .target
        .as_ref()
        .and_then(|target| target.sandbox_claim.as_ref())
        .cloned();
    if recorded_claim.is_none() {
        // Keep the complete final live-certification + allocation-fence + POST
        // state machine off the parent reconcile future's stack. Release and
        // child-placement passes never execute this branch, but an unboxed
        // async child still inflates every `reconcile_lease` future.
        if Box::pin(create_sandbox_claim_fenced(&lease, &ctx, &claims, &claim)).await? {
            info!(lease = %name, "created upstream SandboxClaim behind final allocation fence");
        } else {
            // Includes a lost 409 race, a revoked Pool certificate, a release
            // fence, or a bounded request timeout. Exact GET on the next pass
            // distinguishes them without assuming whether POST committed.
            debug!(lease = %name, "SandboxClaim creation did not commit in this reconcile");
            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
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
    if !claim_is_for_lease(&claim, &lease_uid) {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxClaim {} is not labelled for SandboxLease {name} uid {lease_uid}",
            claim.name_any()
        )));
    }
    if target.owned {
        match ensure_management_claim_fenced(&claims, &claim, &lease, &target.namespace).await? {
            ManagementClaimFence::Ready => {}
            ManagementClaimFence::Patched => {
                info!(lease = %name, claim = %claim.name_any(), "fenced exact legacy management Claim before use");
                return Ok(Action::await_change());
            }
            ManagementClaimFence::Foreign => {
                return Err(SandboxPlacementError::Invalid(format!(
                    "management SandboxClaim {} has unverifiable cleanup ownership",
                    claim.name_any()
                )));
            }
        }
    }
    if target.owned
        && status.claim_cleanup_fence == Some(crate::crd::SandboxClaimCleanupFence::FinalizerV1)
        && !claim
            .metadata
            .finalizers
            .as_ref()
            .is_some_and(|finalizers| {
                finalizers
                    .iter()
                    .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
            })
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "management SandboxClaim {} is missing its checkpointed cleanup finalizer",
            claim.name_any()
        )));
    }
    match claim_owner {
        Some(owner)
            if !metadata_is_controlled_by(
                &claim.metadata,
                &owner.api_version,
                &owner.kind,
                &owner.name,
                &owner.uid,
            ) =>
        {
            return Err(SandboxPlacementError::Invalid(format!(
                "SandboxClaim {} is not controlled by the exact target owner {} {} uid {}",
                claim.name_any(),
                owner.kind,
                owner.name,
                owner.uid
            )));
        }
        None if !metadata_has_no_owner_references(&claim.metadata) => {
            return Err(SandboxPlacementError::Invalid(format!(
                "management SandboxClaim {} has foreign or ambiguous ownerReferences",
                claim.name_any()
            )));
        }
        _ => {}
    }
    let mut proposed = status.target.clone().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "lease {name} has no target provenance before claim creation"
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
            debug!(lease = %name, "recorded target claim provenance");
        } else {
            debug!(lease = %name, "target claim provenance write lost a status race");
        }
        return Ok(Action::await_change());
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
    let service_required = !pool.spec.template.exposed_ports.is_empty();
    if target.owned && !management_provenance_is_complete(&status, service_required) {
        let provenance = match observed_provenance(&target, &claim, &status, service_required).await
        {
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
        let provenance = match observed_provenance(&target, &claim, &status, service_required).await
        {
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

    if (target.owned && !management_provenance_is_complete(&status, service_required))
        || !workload_provenance_is_complete(&status, service_required)
    {
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
    /// The operator disabled new Sandbox service. Existing leases are drained
    /// through the same proof path rather than being left finalized forever.
    ModeDisabled,
    /// Legacy or corrupt Releasing state without the atomic cause checkpoint.
    /// This is quarantined before any destructive action.
    MissingCause,
    /// A live lease whose own admission gate could not be verified. It is
    /// stamped `Unverifiable` and torn down through the ordinary evidence path
    /// rather than being held without a reachable exit.
    Unverifiable,
}

impl ReleaseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "ReleaseRequested",
            Self::RuntimeTtl => "RuntimeTtlElapsed",
            Self::ProvisioningDeadline => "ProvisioningDeadlineElapsed",
            Self::ModeDisabled => "ModeDisabled",
            Self::MissingCause => "ReleaseCauseMissing",
            Self::Unverifiable => "IntegrityUnverifiable",
        }
    }

    fn persisted_cause(self) -> Option<crate::crd::SandboxReleaseCause> {
        match self {
            Self::Requested => Some(crate::crd::SandboxReleaseCause::Requested),
            Self::RuntimeTtl => Some(crate::crd::SandboxReleaseCause::RuntimeTtl),
            Self::ProvisioningDeadline => {
                Some(crate::crd::SandboxReleaseCause::ProvisioningDeadline)
            }
            Self::ModeDisabled => Some(crate::crd::SandboxReleaseCause::ModeDisabled),
            Self::Unverifiable => Some(crate::crd::SandboxReleaseCause::Unverifiable),
            Self::MissingCause => None,
        }
    }

    fn from_persisted(cause: crate::crd::SandboxReleaseCause) -> Self {
        match cause {
            crate::crd::SandboxReleaseCause::Requested => Self::Requested,
            crate::crd::SandboxReleaseCause::RuntimeTtl => Self::RuntimeTtl,
            crate::crd::SandboxReleaseCause::ProvisioningDeadline => Self::ProvisioningDeadline,
            crate::crd::SandboxReleaseCause::ModeDisabled => Self::ModeDisabled,
            crate::crd::SandboxReleaseCause::Unverifiable => Self::Unverifiable,
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
            // Unverifiable is a system-taken teardown, not a caller request,
            // but the terminal phases only distinguish given-back from taken:
            // the durable `releaseCause` carries that distinction for billing
            // and support.
            Self::Requested | Self::ModeDisabled | Self::Unverifiable => {
                crate::crd::SandboxLeasePhase::Released
            }
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
        crate::crd::SandboxLeasePhase::Released | crate::crd::SandboxLeasePhase::Expired => {
            return None;
        }
        crate::crd::SandboxLeasePhase::Quarantined => {
            return status.release_cause.map(ReleaseReason::from_persisted);
        }
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

    let annotated_request = lease
        .annotations()
        .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
        .map(String::as_str);
    let annotation_time = annotated_request
        .and_then(|requested| chrono::DateTime::parse_from_rfc3339(requested).ok())
        .map(|requested| requested.with_timezone(&chrono::Utc));
    let deletion_time = lease
        .metadata
        .deletion_timestamp
        .as_ref()
        .and_then(|timestamp| {
            chrono::DateTime::parse_from_rfc3339(&timestamp.0.to_string())
                .ok()
                .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        });
    let requested_at = match (annotation_time, deletion_time) {
        (Some(annotation), Some(deletion)) => Some(annotation.min(deletion)),
        (Some(annotation), None) => Some(annotation),
        (None, Some(deletion)) => Some(deletion),
        (None, None) => None,
    };
    if annotated_request.is_some() || lease.metadata.deletion_timestamp.is_some() {
        // The annotation is server-owned. If its timestamp is corrupt, honour
        // a provably earlier elapsed deadline. deletionTimestamp is also
        // apiserver-owned and revokes a direct kubectl DELETE immediately.
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

/// Whether release won before any placement controller checkpoint.
///
/// Admission writes the deadline and exact reservation provenance before the
/// `admitted` marker. Every placement step then writes one of
/// `observedGeneration`, `placement`, `target`, or `claimCleanupFence` and ends
/// its pass before a management Claim POST is possible. The Releasing status
/// patch is UID/resourceVersion-fenced, so it cannot certify this shape while a
/// competing placement checkpoint also commits.
fn admitted_pending_is_allocation_free(
    lease: &SandboxLease,
    status: &crate::crd::SandboxLeaseStatus,
) -> bool {
    status.phase == crate::crd::SandboxLeasePhase::Pending
        && status.observed_generation.is_none()
        && status
            .provisioning_deadline
            .as_deref()
            .is_some_and(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).is_ok())
        && status.ready_at.is_none()
        && status.expires_at.is_none()
        && status.release_cause.is_none()
        && status.placement.is_none()
        && status.target.is_none()
        && status.claim_cleanup_fence.is_none()
        && status.sandbox_claim_tombstone.is_none()
        && status.allocation_fence.is_none()
        && status.conditions.is_empty()
        && sandbox_finalizer_present(lease)
        && crate::api::sandbox::admitted_reservation_provenance_is_valid(lease)
}

fn claim_reference_has_expected_shape(
    reference: &crate::crd::SandboxObjectReference,
    namespace: &str,
    name: &str,
) -> bool {
    reference.api_version == AGENT_SANDBOX_API_VERSION
        && reference.kind == SANDBOX_CLAIM_KIND
        && reference.namespace.as_deref() == Some(namespace)
        && reference.name == name
        && !reference.uid.is_empty()
}

fn exact_legacy_claim_owner(lease: &SandboxLease, claim: &DynamicObject) -> bool {
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    claim
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.len() == 1
                && owners[0].api_version == SandboxLease::api_version(&()).as_ref()
                && owners[0].kind == SandboxLease::kind(&()).as_ref()
                && owners[0].name == lease.name_any()
                && owners[0].uid == lease_uid
                && owners[0].controller == Some(true)
        })
}

fn claim_matches_release_shape(
    claim: &DynamicObject,
    lease_uid: &str,
    expected_warm_pool: &str,
) -> bool {
    claim_is_for_lease(claim, lease_uid)
        && claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(serde_json::Value::as_str)
            == Some(expected_warm_pool)
}

fn claim_is_expired_retain_tombstone(
    claim: &DynamicObject,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let retain = claim
        .data
        .pointer("/spec/lifecycle/shutdownPolicy")
        .and_then(serde_json::Value::as_str)
        == Some("Retain");
    let expired = claim
        .data
        .pointer("/spec/lifecycle/shutdownTime")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|shutdown| shutdown.with_timezone(&chrono::Utc) <= now);
    let retained = claim
        .annotations()
        .get(SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|until| until.with_timezone(&chrono::Utc) > now);
    let labelled = claim
        .labels()
        .get(SANDBOX_CLAIM_TOMBSTONE_LABEL)
        .is_some_and(|value| value == "true");
    let cleanup_finalizer_present = claim
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|finalizers| {
            finalizers
                .iter()
                .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
        });
    retain
        && expired
        && retained
        && labelled
        && cleanup_finalizer_present
        && metadata_has_no_owner_references(&claim.metadata)
}

fn claim_tombstone_covers_provisioning_deadline(
    claim: &DynamicObject,
    lease: &SandboxLease,
) -> bool {
    let required = lease
        .status
        .as_ref()
        .and_then(|status| status.provisioning_deadline.as_deref())
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|deadline| deadline.with_timezone(&chrono::Utc) + SANDBOX_CLAIM_TOMBSTONE_MARGIN);
    let retained_until = claim
        .annotations()
        .get(SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|deadline| deadline.with_timezone(&chrono::Utc));
    matches!((required, retained_until), (Some(required), Some(retained)) if retained >= required)
}

fn new_claim_tombstone_deadline(
    lease: &SandboxLease,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let configured = std::env::var(crate::api::sandbox::ENV_SANDBOX_LEASE_RETENTION).ok();
    let retention = crate::api::sandbox::sandbox_lease_retention(configured.as_deref());
    let create_window = chrono::Duration::from_std(SANDBOX_CLAIM_CREATE_TIMEOUT)
        .expect("the fixed Claim create timeout fits chrono");
    let retention_bound = now + retention + create_window + SANDBOX_CLAIM_TOMBSTONE_MARGIN;
    let provisioning_bound = lease
        .status
        .as_ref()
        .and_then(|status| status.provisioning_deadline.as_deref())
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|deadline| deadline.with_timezone(&chrono::Utc) + SANDBOX_CLAIM_TOMBSTONE_MARGIN);
    provisioning_bound.map_or(retention_bound, |deadline| retention_bound.max(deadline))
}

fn build_management_claim_tombstone(
    lease: &SandboxLease,
    namespace: &str,
    prior_claim_uid: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DynamicObject, SandboxPlacementError> {
    let lease_uid = lease.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no UID to fence its release tombstone",
            lease.name_any()
        ))
    })?;
    let mut claim = build_sandbox_claim(
        &claim_name(&lease.name_any()),
        namespace,
        &warm_pool_name(&lease.spec.pool_ref.name),
        &lease_uid,
        now,
        true,
        None,
    );
    claim.data["spec"]["lifecycle"] = serde_json::json!({
        "shutdownTime": now.to_rfc3339(),
        "shutdownPolicy": "Retain"
    });
    claim.metadata.annotations.get_or_insert_default().insert(
        SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION.to_string(),
        new_claim_tombstone_deadline(lease, now).to_rfc3339(),
    );
    claim.metadata.annotations.get_or_insert_default().insert(
        SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION.to_string(),
        lease.name_any(),
    );
    claim
        .metadata
        .labels
        .get_or_insert_default()
        .insert(SANDBOX_CLAIM_TOMBSTONE_LABEL.to_string(), "true".into());
    if let Some(prior_claim_uid) = prior_claim_uid {
        claim.metadata.labels.get_or_insert_default().insert(
            SANDBOX_CLAIM_TOMBSTONE_PRIOR_UID_LABEL.to_string(),
            prior_claim_uid.to_string(),
        );
    }
    Ok(claim)
}

async fn patch_management_claim_tombstone(
    claims: &Api<DynamicObject>,
    claim: &DynamicObject,
    lease: &SandboxLease,
    prior_claim_uid: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, SandboxPlacementError> {
    let Some(uid) = claim.uid().filter(|uid| !uid.is_empty()) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxClaim {} has no UID for its tombstone fence",
            claim.name_any()
        )));
    };
    let Some(resource_version) = claim.resource_version() else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxClaim {} has no resourceVersion for its tombstone fence",
            claim.name_any()
        )));
    };
    let mut annotations = claim.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(
        SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION.to_string(),
        new_claim_tombstone_deadline(lease, now).to_rfc3339(),
    );
    annotations.insert(
        SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION.to_string(),
        lease.name_any(),
    );
    let mut labels = claim.metadata.labels.clone().unwrap_or_default();
    labels.insert(SANDBOX_CLAIM_TOMBSTONE_LABEL.to_string(), "true".into());
    if let Some(prior_claim_uid) = prior_claim_uid {
        labels.insert(
            SANDBOX_CLAIM_TOMBSTONE_PRIOR_UID_LABEL.to_string(),
            prior_claim_uid.to_string(),
        );
    }
    // Conversion never reopens the deterministic name. Whether the object is
    // live or already has a queued DELETE, Kobe's finalizer stays until the
    // UID/RV-fenced reaper has observed the exact outer UID absent after the
    // retention window.
    let mut retained_finalizers = claim.metadata.finalizers.clone().unwrap_or_default();
    if !retained_finalizers
        .iter()
        .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
    {
        retained_finalizers.push(crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER.to_string());
    }
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/metadata/ownerReferences", "value": [] },
        { "op": "add", "path": "/metadata/annotations", "value": annotations },
        { "op": "add", "path": "/metadata/labels", "value": labels },
        { "op": "add", "path": "/metadata/finalizers", "value": retained_finalizers },
        { "op": "add", "path": "/spec/lifecycle", "value": {
            "shutdownTime": now.to_rfc3339(),
            "shutdownPolicy": "Retain"
        }}
    ]));
    match claims
        .patch(
            &claim.name_any(),
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

fn sandbox_claim_cleanup_finalizer_present(claim: &DynamicObject) -> bool {
    claim
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|finalizers| {
            finalizers
                .iter()
                .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
        })
}

fn sandbox_claim_has_tombstone_shape(claim: &DynamicObject) -> bool {
    claim
        .labels()
        .get(SANDBOX_CLAIM_TOMBSTONE_LABEL)
        .is_some_and(|value| value == "true")
        || claim
            .annotations()
            .contains_key(SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION)
        || claim
            .data
            .pointer("/spec/lifecycle/shutdownPolicy")
            .and_then(serde_json::Value::as_str)
            == Some("Retain")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagementClaimFence {
    Ready,
    Patched,
    Foreign,
}

/// Return the lifecycle Kobe must install while migrating a legacy management
/// Claim, or `None` when the existing backstop is already safe.
///
/// A Provisioning Claim is bounded by the already-persisted provisioning
/// deadline. Once Ready, its runtime expiry is the caller-visible contract and
/// a metadata-only migration must not shorten it back to the provisioning
/// deadline. Missing/invalid Ready lifecycle data is repaired from the exact
/// persisted runtime expiry instead.
fn management_claim_lifecycle_patch(
    claim: &DynamicObject,
    lease: &SandboxLease,
) -> Result<Option<serde_json::Value>, SandboxPlacementError> {
    let status = lease.status.as_ref().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no status for Claim lifecycle migration",
            lease.name_any()
        ))
    })?;
    let current_shutdown = claim
        .data
        .pointer("/spec/lifecycle/shutdownTime")
        .and_then(serde_json::Value::as_str);
    let current_is_parseable = current_shutdown
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some();
    let foreground = claim
        .data
        .pointer("/spec/lifecycle/shutdownPolicy")
        .and_then(serde_json::Value::as_str)
        == Some("DeleteForeground");

    let desired = if status.ready_at.is_some() {
        if current_is_parseable && foreground {
            return Ok(None);
        }
        // Preserve a valid shutdown timestamp even when only the policy needs
        // repair; otherwise recover the exact persisted runtime expiry.
        current_shutdown
            .filter(|_| current_is_parseable)
            .map(ToOwned::to_owned)
            .or_else(|| status.expires_at.clone())
    } else {
        let deadline = status.provisioning_deadline.clone();
        let already_exact = deadline.as_deref().is_some_and(|deadline| {
            foreground
                && matches!(
                    (
                        chrono::DateTime::parse_from_rfc3339(deadline),
                        current_shutdown.and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    ),
                    (Ok(expected), Some(current)) if expected == current
                )
        });
        if already_exact {
            return Ok(None);
        }
        deadline
    };
    let desired = desired
        .filter(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {} has no parseable deadline for Claim lifecycle migration",
                lease.name_any()
            ))
        })?;
    Ok(Some(serde_json::json!({
        "shutdownTime": desired,
        "shutdownPolicy": "DeleteForeground"
    })))
}

/// Migrate one exact live management Claim to the current cleanup fence.
///
/// The base protocol emitted a Claim controlled by the outer SandboxLease and
/// without Kobe's cleanup finalizer. Clearing only that owner reference leaves
/// a crash window where the owner-independent Claim can disappear before the
/// status checkpoint. One UID/resourceVersion-fenced patch therefore installs
/// the finalizer and removes the sole exact legacy owner atomically. The caller
/// must end its pass after `Patched` and authorize creation/use only after a
/// fresh read reports `Ready`.
async fn ensure_management_claim_fenced(
    claims: &Api<DynamicObject>,
    claim: &DynamicObject,
    lease: &SandboxLease,
    namespace: &str,
) -> Result<ManagementClaimFence, SandboxPlacementError> {
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(ManagementClaimFence::Foreign);
    };
    let ownership_is_safe =
        metadata_has_no_owner_references(&claim.metadata) || exact_legacy_claim_owner(lease, claim);
    if claim.name_any() != claim_name(&lease.name_any())
        || claim.namespace().as_deref() != Some(namespace)
        || claim.metadata.deletion_timestamp.is_some()
        || sandbox_claim_has_tombstone_shape(claim)
        || !ownership_is_safe
        || !claim_matches_release_shape(
            claim,
            &lease_uid,
            &warm_pool_name(&lease.spec.pool_ref.name),
        )
    {
        return Ok(ManagementClaimFence::Foreign);
    }
    let needs_legacy_migration =
        exact_legacy_claim_owner(lease, claim) || !sandbox_claim_cleanup_finalizer_present(claim);
    let lifecycle_patch = needs_legacy_migration
        .then(|| management_claim_lifecycle_patch(claim, lease))
        .transpose()?
        .flatten();
    if metadata_has_no_owner_references(&claim.metadata)
        && sandbox_claim_cleanup_finalizer_present(claim)
        && lifecycle_patch.is_none()
    {
        return Ok(ManagementClaimFence::Ready);
    }

    let Some(uid) = claim.uid().filter(|uid| !uid.is_empty()) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxClaim {} has no UID for cleanup-fence migration",
            claim.name_any()
        )));
    };
    let Some(resource_version) = claim.resource_version() else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxClaim {} has no resourceVersion for cleanup-fence migration",
            claim.name_any()
        )));
    };
    let mut finalizers = claim.metadata.finalizers.clone().unwrap_or_default();
    if !sandbox_claim_cleanup_finalizer_present(claim) {
        finalizers.push(crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER.to_string());
    }
    let mut operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": resource_version }),
        serde_json::json!({ "op": "add", "path": "/metadata/ownerReferences", "value": [] }),
        serde_json::json!({ "op": "add", "path": "/metadata/finalizers", "value": finalizers }),
    ];
    if let Some(lifecycle) = lifecycle_patch {
        operations.push(serde_json::json!({
            "op": "add", "path": "/spec/lifecycle", "value": lifecycle
        }));
    }
    let patch = crate::controllers::lease::json_patch(serde_json::Value::Array(operations));
    match claims
        .patch(
            &claim.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(ManagementClaimFence::Patched),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {
            Ok(ManagementClaimFence::Patched)
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalHandleFence {
    Ready,
    Patched,
    Foreign,
}

fn internal_handle_retention_fence_matches(
    current: &crate::crd::ClusterLease,
    lease: &SandboxLease,
    now: chrono::DateTime<chrono::Utc>,
    allow_deleting: bool,
) -> bool {
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    let deadline = current
        .annotations()
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|deadline| deadline.with_timezone(&chrono::Utc));
    current.name_any() == crate::controllers::sandbox_child::internal_lease_name(&lease.name_any())
        && current.namespace() == lease.namespace()
        && (allow_deleting || current.metadata.deletion_timestamp.is_none())
        && current
            .metadata
            .owner_references
            .as_ref()
            .is_none_or(Vec::is_empty)
        && current
            .labels()
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
        && current
            .labels()
            .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
            .is_some_and(|value| value == &lease_uid)
        && current
            .labels()
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL)
            .is_some_and(|value| value == "true")
        && current
            .annotations()
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION)
            .is_some_and(|value| value == &lease.name_any())
        && deadline.is_some_and(|deadline| allow_deleting || deadline > now)
        && current.finalizers().iter().any(|finalizer| {
            finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
        })
        && current.spec.requester.requester_type == "kobe:sandbox-composition"
        && (current.spec.requester.identity == lease_uid
            || current.spec.requester.identity == "kobe-operator")
        && current.spec.cleanup_mode == Some(crate::crd::CleanupMode::VerifiedDestroy)
}

/// Fence an exact internal handle before allocation or release.
///
/// The only ownerRef migration accepted is the exact sole legacy outer owner.
/// The retention finalizer and deadline keep the ClusterLease name occupied
/// after proof is ACKed, closing stale creates from controllers that predate
/// the coordination fence. Anything foreign or already deleting fails closed.
async fn ensure_internal_lease_fenced(
    internal: &Api<crate::crd::ClusterLease>,
    current: &crate::crd::ClusterLease,
    lease: &SandboxLease,
) -> Result<InternalHandleFence, SandboxPlacementError> {
    use crate::controllers::sandbox_child::InternalLeaseOwnership;

    let ownership = crate::controllers::sandbox_child::internal_lease_ownership(current, lease);
    if ownership == InternalLeaseOwnership::Foreign {
        return Ok(InternalHandleFence::Foreign);
    }
    if current
        .annotations()
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION)
        .is_some_and(|name| name != &lease.name_any())
    {
        return Ok(InternalHandleFence::Foreign);
    }

    let now = chrono::Utc::now();
    if ownership == InternalLeaseOwnership::Ownerless
        && internal_handle_retention_fence_matches(current, lease, now, false)
    {
        return Ok(InternalHandleFence::Ready);
    }

    let (Some(uid), Some(resource_version)) = (current.uid(), current.resource_version()) else {
        return Ok(InternalHandleFence::Foreign);
    };
    let mut labels = current.metadata.labels.clone().unwrap_or_default();
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(InternalHandleFence::Foreign);
    };
    labels.insert(
        crate::sandbox::SANDBOX_LEASE_UID_LABEL.to_string(),
        lease_uid,
    );
    labels.insert(
        crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL.to_string(),
        "true".into(),
    );
    let mut annotations = current.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(
        crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION.to_string(),
        lease.name_any(),
    );
    let deadline_is_live = annotations
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|deadline| deadline.with_timezone(&chrono::Utc) > now);
    if !deadline_is_live {
        annotations.insert(
            crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION.to_string(),
            allocation_fence_deadline(now).to_rfc3339(),
        );
    }
    let mut finalizers = current.metadata.finalizers.clone().unwrap_or_default();
    if !finalizers.iter().any(|finalizer| {
        finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
    }) {
        finalizers
            .push(crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER.to_string());
    }
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/metadata/ownerReferences", "value": [] },
        { "op": "add", "path": "/metadata/labels", "value": labels },
        { "op": "add", "path": "/metadata/annotations", "value": annotations },
        { "op": "add", "path": "/metadata/finalizers", "value": finalizers }
    ]));
    match internal
        .patch(
            &current.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(InternalHandleFence::Patched),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {
            Ok(InternalHandleFence::Patched)
        }
        Err(error) => Err(error.into()),
    }
}

fn allocation_fence_deadline(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let configured = std::env::var(crate::api::sandbox::ENV_SANDBOX_LEASE_RETENTION).ok();
    now + crate::api::sandbox::sandbox_lease_retention(configured.as_deref())
        + chrono::Duration::from_std(SANDBOX_CLAIM_CREATE_TIMEOUT)
            .expect("fixed create timeout fits chrono")
        + SANDBOX_CLAIM_TOMBSTONE_MARGIN
}

fn allocation_fence_matches(
    fence: &k8s_openapi::api::coordination::v1::Lease,
    lease: &SandboxLease,
    namespace: &str,
) -> bool {
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    fence.name_any() == allocation_fence_name(&lease.name_any())
        && fence.namespace().as_deref() == Some(namespace)
        && fence.metadata.deletion_timestamp.is_none()
        && fence
            .metadata
            .owner_references
            .as_ref()
            .is_none_or(Vec::is_empty)
        && fence
            .labels()
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
        && fence
            .labels()
            .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
            .is_some_and(|value| value == &lease_uid)
        && fence
            .labels()
            .get(SANDBOX_ALLOCATION_FENCE_LABEL)
            .is_some_and(|value| value == "true")
        && fence
            .annotations()
            .get(SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION)
            .is_some_and(|value| value == &lease.name_any())
        && fence
            .spec
            .as_ref()
            .and_then(|spec| spec.holder_identity.as_deref())
            == Some(format!("{SANDBOX_ALLOCATION_FENCE_HOLDER_PREFIX}{lease_uid}").as_str())
}

async fn ensure_allocation_fence(
    lease: &SandboxLease,
    ctx: &SandboxContext,
) -> Result<AllocationFence, SandboxPlacementError> {
    let status = lease.status.clone().unwrap_or_default();
    let name = allocation_fence_name(&lease.name_any());
    let lease_uid = lease.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no UID for its allocation fence",
            lease.name_any()
        ))
    })?;
    let fences: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    if let Some(recorded) = status.allocation_fence.as_ref()
        && (recorded.api_version != "coordination.k8s.io/v1"
            || recorded.kind != "Lease"
            || recorded.namespace.as_deref() != Some(ctx.namespace.as_str())
            || recorded.name != name
            || recorded.uid.is_empty())
    {
        return Ok(AllocationFence::Quarantine(
            "allocation_fence_provenance_invalid",
        ));
    }

    let fence = match fences.get(&name).await {
        Ok(fence) => fence,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            if status.allocation_fence.is_some() {
                return Ok(AllocationFence::Quarantine("allocation_fence_missing"));
            }
            let now = chrono::Utc::now();
            let fence = k8s_openapi::api::coordination::v1::Lease {
                metadata: kube::api::ObjectMeta {
                    name: Some(name),
                    namespace: Some(ctx.namespace.clone()),
                    labels: Some(
                        [
                            (
                                "app.kubernetes.io/managed-by".to_string(),
                                crate::sandbox::KOBE_MANAGED_BY.to_string(),
                            ),
                            (
                                crate::sandbox::SANDBOX_LEASE_UID_LABEL.to_string(),
                                lease_uid.clone(),
                            ),
                            (SANDBOX_ALLOCATION_FENCE_LABEL.to_string(), "true".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    annotations: Some(
                        [
                            (
                                SANDBOX_ALLOCATION_FENCE_RETAIN_UNTIL_ANNOTATION.to_string(),
                                allocation_fence_deadline(now).to_rfc3339(),
                            ),
                            (
                                SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION.to_string(),
                                lease.name_any(),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
                spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
                    holder_identity: Some(format!(
                        "{SANDBOX_ALLOCATION_FENCE_HOLDER_PREFIX}{lease_uid}"
                    )),
                    ..Default::default()
                }),
            };
            return match tokio::time::timeout(
                SANDBOX_CLAIM_CREATE_TIMEOUT,
                fences.create(&PostParams::default(), &fence),
            )
            .await
            {
                Ok(Ok(_)) => Ok(AllocationFence::Draining(std::time::Duration::from_secs(1))),
                Ok(Err(kube::Error::Api(error))) if error.code == 409 => {
                    Ok(AllocationFence::Draining(std::time::Duration::from_secs(1)))
                }
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Ok(AllocationFence::Draining(std::time::Duration::from_secs(
                    10,
                ))),
            };
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return Ok(AllocationFence::Quarantine("allocation_fence_unverifiable"));
        }
        Err(error) => return Err(error.into()),
    };
    if !allocation_fence_matches(&fence, lease, &ctx.namespace) {
        return Ok(AllocationFence::Quarantine(
            "allocation_fence_identity_changed",
        ));
    }
    let Some(fence_uid) = fence.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(AllocationFence::Quarantine("allocation_fence_uid_missing"));
    };
    if let Some(recorded) = status.allocation_fence.as_ref()
        && recorded.uid != fence_uid
    {
        return Ok(AllocationFence::Quarantine(
            "allocation_fence_identity_changed",
        ));
    }
    if status.allocation_fence.is_none() {
        let mut next = status;
        next.allocation_fence = Some(crate::crd::SandboxObjectReference {
            api_version: "coordination.k8s.io/v1".into(),
            kind: "Lease".into(),
            namespace: Some(ctx.namespace.clone()),
            name: fence.name_any(),
            uid: fence_uid,
            generation: None,
        });
        let _ = patch_lease_status_fenced(ctx, lease, &next).await?;
        return Ok(AllocationFence::Checkpointed);
    }

    let Some(created_at) = fence
        .metadata
        .creation_timestamp
        .as_ref()
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(&time.0.to_string()).ok())
        .map(|time| time.with_timezone(&chrono::Utc))
    else {
        return Ok(AllocationFence::Quarantine(
            "allocation_fence_timestamp_missing",
        ));
    };
    let drain = SANDBOX_CLAIM_CREATE_TIMEOUT + SANDBOX_ALLOCATION_DRAIN_MARGIN;
    let elapsed = (chrono::Utc::now() - created_at)
        .to_std()
        .unwrap_or_default();
    if elapsed < drain {
        return Ok(AllocationFence::Draining(drain - elapsed));
    }
    Ok(AllocationFence::Ready)
}

async fn allocation_fence_is_absent_for_create(
    fences: &Api<k8s_openapi::api::coordination::v1::Lease>,
    lease: &SandboxLease,
    namespace: &str,
) -> Result<bool, SandboxPlacementError> {
    match fences.get(&allocation_fence_name(&lease.name_any())).await {
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(true),
        Ok(fence) if allocation_fence_matches(&fence, lease, namespace) => Ok(false),
        Ok(_) => Err(SandboxPlacementError::Invalid(format!(
            "foreign allocation fence occupies SandboxLease {}",
            lease.name_any()
        ))),
        Err(error) => Err(error.into()),
    }
}

async fn exact_outer_lease_still_exists(
    leases: &Api<SandboxLease>,
    name: &str,
    uid: &str,
) -> Result<bool, kube::Error> {
    match leases.get(name).await {
        Ok(lease) => Ok(lease.uid().as_deref() == Some(uid)),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) => Err(error),
    }
}

fn retention_deadline_elapsed(
    annotations: &std::collections::BTreeMap<String, String>,
    key: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    annotations
        .get(key)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|deadline| deadline.with_timezone(&chrono::Utc) <= now)
}

/// Reap allocation fences only after their own durable retention deadlines.
///
/// Both object kinds are independent of the outer SandboxLease so direct
/// deletion cannot GC them. Every deletion is fenced on listed UID+RV and is
/// withheld while the exact outer UID still exists, even if a malformed early
/// deadline was written by an older build.
pub(crate) async fn sweep_sandbox_allocation_tombstones(
    client: &Client,
    namespace: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    let claims: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        namespace,
        &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
    );
    let claim_selector = format!("{SANDBOX_CLAIM_TOMBSTONE_LABEL}=true");
    match claims
        .list(&ListParams::default().labels(&claim_selector))
        .await
    {
        Ok(list) => {
            for claim in list {
                let labels = claim.labels();
                let annotations = claim.annotations();
                let Some(outer_uid) = labels
                    .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
                    .filter(|uid| !uid.is_empty())
                else {
                    continue;
                };
                let Some(outer_name) = annotations
                    .get(SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION)
                    .filter(|name| !name.is_empty())
                else {
                    continue;
                };
                if !metadata_has_no_owner_references(&claim.metadata)
                    || claim.name_any() != claim_name(outer_name)
                    || claim.namespace().as_deref() != Some(namespace)
                    || labels
                        .get("app.kubernetes.io/managed-by")
                        .is_none_or(|value| value != crate::sandbox::KOBE_MANAGED_BY)
                    || !retention_deadline_elapsed(
                        annotations,
                        SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION,
                        now,
                    )
                    || claim
                        .data
                        .pointer("/spec/lifecycle/shutdownPolicy")
                        .and_then(serde_json::Value::as_str)
                        != Some("Retain")
                    || claim
                        .data
                        .pointer("/spec/lifecycle/shutdownTime")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .is_none_or(|shutdown| shutdown.with_timezone(&chrono::Utc) > now)
                {
                    continue;
                }
                match exact_outer_lease_still_exists(&leases, outer_name, outer_uid).await {
                    Ok(true) => continue,
                    Err(error) => {
                        warn!(claim = %claim.name_any(), error = %error, "could not verify outer lease before Claim tombstone reap");
                        continue;
                    }
                    Ok(false) => {}
                }
                let (Some(uid), Some(resource_version)) = (claim.uid(), claim.resource_version())
                else {
                    continue;
                };
                let finalizers = claim.metadata.finalizers.clone().unwrap_or_default();
                if finalizers
                    .iter()
                    .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
                {
                    let retained: Vec<_> = finalizers
                        .iter()
                        .filter(|finalizer| {
                            finalizer.as_str() != crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER
                        })
                        .cloned()
                        .collect();
                    let patch = crate::controllers::lease::json_patch(serde_json::json!([
                        { "op": "test", "path": "/metadata/uid", "value": uid },
                        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
                        { "op": "test", "path": "/metadata/finalizers", "value": finalizers },
                        { "op": "replace", "path": "/metadata/finalizers", "value": retained }
                    ]));
                    match claims
                        .patch(
                            &claim.name_any(),
                            &PatchParams::default(),
                            &Patch::Json::<()>(patch),
                        )
                        .await
                    {
                        Ok(_) => {
                            info!(claim = %claim.name_any(), "released retained SandboxClaim cleanup finalizer")
                        }
                        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {}
                        Err(error) => {
                            warn!(claim = %claim.name_any(), error = %error, "could not release retained SandboxClaim cleanup finalizer")
                        }
                    }
                    continue;
                }
                let params = DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: Some(uid),
                        resource_version: Some(resource_version),
                    }),
                    ..Default::default()
                };
                match claims.delete(&claim.name_any(), &params).await {
                    Ok(_) => {
                        info!(claim = %claim.name_any(), "reaped retained SandboxClaim tombstone")
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
                    Err(error) => {
                        warn!(claim = %claim.name_any(), error = %error, "could not reap SandboxClaim tombstone")
                    }
                }
            }
        }
        Err(error) => warn!(error = %error, "could not list SandboxClaim tombstones"),
    }

    let fences: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(client.clone(), namespace);
    let fence_selector = format!("{SANDBOX_ALLOCATION_FENCE_LABEL}=true");
    let listed = match fences
        .list(&ListParams::default().labels(&fence_selector))
        .await
    {
        Ok(listed) => listed,
        Err(error) => {
            warn!(error = %error, "could not list Sandbox allocation fences");
            return;
        }
    };
    for fence in listed {
        let labels = fence.labels();
        let annotations = fence.annotations();
        let Some(outer_uid) = labels
            .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
            .filter(|uid| !uid.is_empty())
        else {
            continue;
        };
        let Some(outer_name) = annotations
            .get(SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let expected_holder = format!("{SANDBOX_ALLOCATION_FENCE_HOLDER_PREFIX}{outer_uid}");
        if fence
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| !owners.is_empty())
            || labels
                .get("app.kubernetes.io/managed-by")
                .is_none_or(|value| value != crate::sandbox::KOBE_MANAGED_BY)
            || fence.name_any() != allocation_fence_name(outer_name)
            || fence.namespace().as_deref() != Some(namespace)
            || fence
                .spec
                .as_ref()
                .and_then(|spec| spec.holder_identity.as_deref())
                != Some(expected_holder.as_str())
            || !retention_deadline_elapsed(
                annotations,
                SANDBOX_ALLOCATION_FENCE_RETAIN_UNTIL_ANNOTATION,
                now,
            )
        {
            continue;
        }
        match exact_outer_lease_still_exists(&leases, outer_name, outer_uid).await {
            Ok(true) => continue,
            Err(error) => {
                warn!(fence = %fence.name_any(), error = %error, "could not verify outer lease before allocation-fence reap");
                continue;
            }
            Ok(false) => {}
        }
        let (Some(uid), Some(resource_version)) = (fence.uid(), fence.resource_version()) else {
            continue;
        };
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid),
                resource_version: Some(resource_version),
            }),
            ..Default::default()
        };
        match fences.delete(&fence.name_any(), &params).await {
            Ok(_) => info!(fence = %fence.name_any(), "reaped Sandbox allocation fence"),
            Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
            Err(error) => {
                warn!(fence = %fence.name_any(), error = %error, "could not reap Sandbox allocation fence")
            }
        }
    }

    let handles: Api<crate::crd::ClusterLease> = Api::namespaced(client.clone(), namespace);
    let selector = format!(
        "{}=true",
        crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL
    );
    let listed = match handles.list(&ListParams::default().labels(&selector)).await {
        Ok(listed) => listed,
        Err(error) => {
            warn!(error = %error, "could not list retained Sandbox child handles");
            return;
        }
    };
    for handle in listed {
        let labels = handle.labels();
        let annotations = handle.annotations();
        let Some(outer_uid) = labels
            .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
            .filter(|uid| !uid.is_empty())
        else {
            continue;
        };
        let Some(outer_name) = annotations
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let status = handle.status.as_ref().cloned().unwrap_or_default();
        let receipt_token = status
            .teardown_receipt
            .as_ref()
            .and_then(|receipt| validated_retained_receipt_token(&handle, receipt));
        let receipt_verified = receipt_token.is_some();
        let receipt_evidence_is_authoritative = match status.teardown_receipt.as_ref() {
            Some(receipt) if crate::receipt_authority::is_separate() => {
                authoritative_child_receipt_matches(client, namespace, &handle, receipt)
                    .await
                    .ok()
                    .flatten()
            }
            _ => None,
        };
        let receipt_acked = receipt_token.as_ref().is_some_and(|token| {
            if crate::receipt_authority::is_separate() {
                return status.teardown_acknowledgement.as_ref().is_some_and(|ack| {
                    ack.consumer.kind == "SandboxLease"
                        && ack.consumer.namespace.as_deref() == Some(namespace)
                        && ack.consumer.name == *outer_name
                        && ack.consumer.uid == *outer_uid
                        && ack.proof.kind == crate::crd::TeardownAcknowledgedProofKind::Receipt
                        && ack.proof.receipt_token.as_deref() == Some(token.as_str())
                        && ack.proof.evidence.as_ref() == receipt_evidence_is_authoritative.as_ref()
                });
            }
            annotations.get(crate::crd::TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION) == Some(token)
        });
        let unbound_token =
            crate::controllers::lease::unbound_release_acknowledgement_token(&status);
        let unbound_verified = unbound_child_release_is_proven(&handle, None);
        let unbound_acked = unbound_verified
            && unbound_token.as_ref().is_some_and(|token| {
                if crate::receipt_authority::is_separate() {
                    return status.teardown_acknowledgement.as_ref().is_some_and(|ack| {
                        ack.consumer.kind == "SandboxLease"
                            && ack.consumer.namespace.as_deref() == Some(namespace)
                            && ack.consumer.name == *outer_name
                            && ack.consumer.uid == *outer_uid
                            && ack.proof.kind
                                == crate::crd::TeardownAcknowledgedProofKind::NeverBound
                            && status.teardown_attempt_id.as_ref() == Some(&ack.attempt_id)
                            && ack.proof.unbound_release_verified_at
                                == status.unbound_release_verified_at
                    });
                }
                annotations.get(crate::crd::UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION)
                    == Some(token)
            });
        let stale_rejected = annotations
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION)
            == Some(outer_uid);
        let proof_is_consumable = receipt_acked
            || unbound_acked
            || (!crate::receipt_authority::is_separate()
                && stale_rejected
                && (receipt_verified || unbound_verified));
        let finalizers = handle.metadata.finalizers.clone().unwrap_or_default();
        if handle.name_any() != crate::controllers::sandbox_child::internal_lease_name(outer_name)
            || handle.namespace().as_deref() != Some(namespace)
            || handle.metadata.deletion_timestamp.is_none()
            || handle
                .metadata
                .owner_references
                .as_ref()
                .is_some_and(|owners| !owners.is_empty())
            || labels
                .get("app.kubernetes.io/managed-by")
                .is_none_or(|value| value != crate::sandbox::KOBE_MANAGED_BY)
            || handle.spec.requester.requester_type != "kobe:sandbox-composition"
            || handle.spec.requester.identity != *outer_uid
            || handle.spec.cleanup_mode != Some(crate::crd::CleanupMode::VerifiedDestroy)
            || !retention_deadline_elapsed(
                annotations,
                crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION,
                now,
            )
            || !proof_is_consumable
            || !finalizers.iter().any(|finalizer| {
                finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
            })
        {
            continue;
        }
        match exact_outer_lease_still_exists(&leases, outer_name, outer_uid).await {
            Ok(true) => continue,
            Err(error) => {
                warn!(handle = %handle.name_any(), error = %error, "could not verify outer lease before child-handle reap");
                continue;
            }
            Ok(false) => {}
        }
        let (Some(uid), Some(resource_version)) = (handle.uid(), handle.resource_version()) else {
            continue;
        };
        let retained: Vec<_> = finalizers
            .iter()
            .filter(|finalizer| {
                finalizer.as_str()
                    != crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
            })
            .cloned()
            .collect();
        let patch = crate::controllers::lease::json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "test", "path": "/metadata/finalizers", "value": finalizers },
            { "op": "replace", "path": "/metadata/finalizers", "value": retained }
        ]));
        match handles
            .patch(
                &handle.name_any(),
                &PatchParams::default(),
                &Patch::Json::<()>(patch),
            )
            .await
        {
            Ok(_) => info!(handle = %handle.name_any(), "reaped retained Sandbox child handle"),
            Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {}
            Err(error) => {
                warn!(handle = %handle.name_any(), error = %error, "could not reap retained Sandbox child handle")
            }
        }
    }
}

fn current_outer_lease_authorizes_create(
    current: &SandboxLease,
    expected: &SandboxLease,
) -> Result<bool, SandboxPlacementError> {
    if current.uid() != expected.uid()
        || current.metadata.generation != expected.metadata.generation
        || current.spec.pool_ref != expected.spec.pool_ref
        || current.spec.placement_authority != expected.spec.placement_authority
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {} changed identity before allocation",
            expected.name_any()
        )));
    }
    Ok(sandbox_lease_authorizes_allocation(current))
}

/// Consumer-side equivalent of the producer's final create gate.
///
/// The ClusterLease controller calls this before a composition handle can enter
/// its allocation queue, closing POSTs whose apiserver commit arrives after the
/// creating HTTP future was cancelled.
pub(crate) fn sandbox_lease_authorizes_allocation(current: &SandboxLease) -> bool {
    let status = current.status.clone().unwrap_or_default();
    current.metadata.deletion_timestamp.is_none()
        && current
            .annotations()
            .get(SANDBOX_ADMISSION_ANNOTATION)
            .map(String::as_str)
            == Some(SANDBOX_ADMISSION_ADMITTED)
        && sandbox_finalizer_present(current)
        && status.phase == crate::crd::SandboxLeasePhase::Provisioning
        && status.allocation_fence.is_none()
        && !footprint_absence_proven(&status)
        && release_reason(current).is_none()
}

/// Final authorization and POST are one bounded future. Release waits longer
/// than this bound after publishing its fence, so a task paused anywhere after
/// the first read either observes the fence or expires before absence proof.
async fn create_internal_cluster_lease_fenced(
    expected: &SandboxLease,
    ctx: &SandboxContext,
    internal: &Api<crate::crd::ClusterLease>,
    desired: &crate::crd::ClusterLease,
    placement_authority: &crate::crd::SandboxPlacementAuthority,
) -> Result<Option<crate::crd::ClusterLease>, SandboxPlacementError> {
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let fences: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let cluster_pools: Api<crate::crd::ClusterPool> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let attempt = async {
        let current = leases.get(&expected.name_any()).await?;
        if !current_outer_lease_authorizes_create(&current, expected)? {
            return Ok(None);
        }
        let Some(current_pool) = current_sandbox_pool_for_create(&current, &pools).await? else {
            return Ok(None);
        };
        if !allocation_fence_is_absent_for_create(&fences, &current, &ctx.namespace).await? {
            return Ok(None);
        }
        // This strong read is deliberately the last external observation before
        // POST. A same-named ClusterPool recreated after HTTP admission is not
        // the capacity that admission authorized.
        let current_cluster_pool = cluster_pools.get(&placement_authority.name).await?;
        if !crate::controllers::sandbox_child::child_placement_authority_matches(
            placement_authority,
            &current_pool,
            &current_cluster_pool,
            &ctx.namespace,
        )? {
            return Err(SandboxPlacementError::Invalid(format!(
                "ClusterPool {} changed identity before child allocation",
                placement_authority.name
            )));
        }
        match internal.create(&PostParams::default(), desired).await {
            Ok(created) => Ok(Some(created)),
            Err(kube::Error::Api(error)) if error.code == 409 => {
                Ok(Some(internal.get(&desired.name_any()).await?))
            }
            Err(error) => Err(error.into()),
        }
    };
    match tokio::time::timeout(SANDBOX_CLAIM_CREATE_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Ok(None),
    }
}

async fn create_sandbox_claim_fenced(
    expected: &SandboxLease,
    ctx: &SandboxContext,
    claims: &Api<DynamicObject>,
    desired: &DynamicObject,
) -> Result<bool, SandboxPlacementError> {
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let fences: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let attempt = async {
        let current = leases.get(&expected.name_any()).await?;
        if !current_outer_lease_authorizes_create(&current, expected)? {
            return Ok(false);
        }
        let Some(current_pool) = current_sandbox_pool_for_create(&current, &pools).await? else {
            return Ok(false);
        };
        if matches!(current_pool.spec.placement, SandboxPlacement::Management {}) {
            let templates: Api<DynamicObject> = Api::namespaced_with(
                ctx.client.clone(),
                &ctx.namespace,
                &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
            );
            let warm_pools: Api<DynamicObject> = Api::namespaced_with(
                ctx.client.clone(),
                &ctx.namespace,
                &upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
            );
            let template = templates
                .get(&template_name(&current_pool.name_any()))
                .await?;
            let warm_pool = warm_pools
                .get(&warm_pool_name(&current_pool.name_any()))
                .await?;
            let provenance = current
                .status
                .as_ref()
                .and_then(|status| status.target.as_ref())
                .ok_or_else(|| {
                    SandboxPlacementError::Invalid(format!(
                        "SandboxLease {} has no target provenance at its final Claim gate",
                        current.name_any()
                    ))
                })?;
            if let Err(error) =
                crate::controllers::sandbox_pool_certification::revalidate_certified_management_pool(
                    &ctx.client,
                    &ctx.namespace,
                    &current_pool,
                    &template,
                    &warm_pool,
                    provenance.sandbox_template.as_ref(),
                    provenance.sandbox_warm_pool.as_ref(),
                )
                .await
            {
                debug!(
                    lease = %current.name_any(),
                    pool = %current_pool.name_any(),
                    error,
                    "SandboxClaim creation withheld after final live pool certification"
                );
                return Ok(false);
            }
        }
        if !allocation_fence_is_absent_for_create(&fences, &current, &ctx.namespace).await? {
            return Ok(false);
        }
        match claims.create(&PostParams::default(), desired).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(true),
            Err(error) => Err(error.into()),
        }
    };
    match tokio::time::timeout(SANDBOX_CLAIM_CREATE_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Ok(false),
    }
}

/// Occupy the deterministic management Claim name with an exact inert object.
///
/// `target.sandboxClaim` remains the immutable identity of the workload Claim.
/// If that Claim is already 404, this helper creates a same-named expired
/// `Retain` Claim and checkpoints its different UID in
/// `status.sandboxClaimTombstone`. A late active POST then loses with 409. If
/// the active POST won first, its exact lease label and immutable request shape
/// let release convert that object into the tombstone instead.
pub(super) async fn ensure_management_claim_tombstone(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    claims: &Api<DynamicObject>,
) -> Result<ManagementClaimTombstone, SandboxPlacementError> {
    let status = lease.status.clone().unwrap_or_default();
    let name = claim_name(&lease.name_any());
    let lease_uid = lease.uid().filter(|uid| !uid.is_empty()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no UID to fence management cleanup",
            lease.name_any()
        ))
    })?;
    let prior = status
        .target
        .as_ref()
        .and_then(|target| target.sandbox_claim.as_ref());
    if prior.is_some_and(|reference| {
        !claim_reference_has_expected_shape(reference, &ctx.namespace, &name)
    }) {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_provenance_invalid",
        ));
    }
    let recorded = status.sandbox_claim_tombstone.as_ref();
    if recorded.is_some_and(|reference| {
        !claim_reference_has_expected_shape(reference, &ctx.namespace, &name)
    }) {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_tombstone_provenance_invalid",
        ));
    }

    let observed = match claims.get(&name).await {
        Ok(observed) => observed,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            if recorded.is_some() {
                return Ok(ManagementClaimTombstone::Quarantine(
                    "claim_tombstone_missing",
                ));
            }
            let now = chrono::Utc::now();
            let tombstone = build_management_claim_tombstone(
                lease,
                &ctx.namespace,
                prior.map(|reference| reference.uid.as_str()),
                now,
            )?;
            return match tokio::time::timeout(
                SANDBOX_CLAIM_CREATE_TIMEOUT,
                claims.create(&PostParams::default(), &tombstone),
            )
            .await
            {
                Ok(Ok(_)) => Ok(ManagementClaimTombstone::Retry(
                    std::time::Duration::from_secs(1),
                )),
                Ok(Err(kube::Error::Api(error))) if error.code == 409 => Ok(
                    ManagementClaimTombstone::Retry(std::time::Duration::from_secs(1)),
                ),
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Ok(ManagementClaimTombstone::Retry(
                    std::time::Duration::from_secs(10),
                )),
            };
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return Ok(ManagementClaimTombstone::Quarantine(
                "claim_tombstone_unverifiable",
            ));
        }
        Err(error) => return Err(error.into()),
    };

    if observed.metadata.deletion_timestamp.is_some()
        && !observed
            .metadata
            .finalizers
            .as_ref()
            .is_some_and(|finalizers| {
                finalizers
                    .iter()
                    .any(|finalizer| finalizer == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
            })
    {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_tombstone_deleting_without_cleanup_fence",
        ));
    }
    if !claim_matches_release_shape(
        &observed,
        &lease_uid,
        &warm_pool_name(&lease.spec.pool_ref.name),
    ) {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_tombstone_identity_unverifiable",
        ));
    }
    if let Some(recorded) = recorded
        && observed.uid().as_deref() != Some(recorded.uid.as_str())
    {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_tombstone_identity_changed",
        ));
    }

    if !metadata_has_no_owner_references(&observed.metadata)
        && !exact_legacy_claim_owner(lease, &observed)
    {
        return Ok(ManagementClaimTombstone::Quarantine(
            "claim_ownerref_legacy_unverifiable",
        ));
    }
    if !sandbox_claim_has_tombstone_shape(&observed)
        && observed.metadata.deletion_timestamp.is_none()
    {
        match ensure_management_claim_fenced(claims, &observed, lease, &ctx.namespace).await? {
            ManagementClaimFence::Ready => {}
            ManagementClaimFence::Patched => {
                info!(lease = %lease.name_any(), claim = %name, "migrated exact legacy Claim cleanup fence before tombstone conversion");
                return Ok(ManagementClaimTombstone::Retry(
                    std::time::Duration::from_secs(1),
                ));
            }
            ManagementClaimFence::Foreign => {
                return Ok(ManagementClaimTombstone::Quarantine(
                    "claim_ownerref_legacy_unverifiable",
                ));
            }
        }
    }

    let reference = target_reference(
        AGENT_SANDBOX_API_VERSION,
        SANDBOX_CLAIM_KIND,
        &ctx.namespace,
        &observed,
    )?;
    if recorded.is_none() {
        let mut next = status;
        next.sandbox_claim_tombstone = Some(reference);
        let _ = patch_lease_status_fenced(ctx, lease, &next).await?;
        return Ok(ManagementClaimTombstone::Checkpointed);
    }

    let now = chrono::Utc::now();
    if !claim_is_expired_retain_tombstone(&observed, now)
        || !claim_tombstone_covers_provisioning_deadline(&observed, lease)
    {
        let _ = patch_management_claim_tombstone(
            claims,
            &observed,
            lease,
            prior.map(|reference| reference.uid.as_str()),
            now,
        )
        .await?;
        return Ok(ManagementClaimTombstone::Retry(
            std::time::Duration::from_secs(1),
        ));
    }

    Ok(ManagementClaimTombstone::Ready {
        claim: Box::new(observed),
        tombstone_ref: recorded.expect("checked above").clone(),
        prior_claim_uid: prior.map(|reference| reference.uid.clone()),
    })
}

/// Tear one lease down and give its capacity back — but only against proof.
///
/// The order is the point. The upstream Claim name is first occupied by an
/// exact expired `Retain` tombstone, every recorded or discoverable descendant
/// is then proven absent, and only then are quota and alias reservations
/// released. Releasing reservations first would let the freed slot be handed
/// to the next caller while the previous Sandbox was still running, which is
/// precisely the over-subscription the ledger exists to prevent.
///
/// Uncertainty quarantines rather than releases. A lease whose teardown cannot
/// be verified keeps consuming its slot: under-counting capacity is recoverable
/// by an operator, silently double-booking a Sandbox host is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetFootprintCheck {
    Verified,
    Retry(&'static str),
    Quarantine(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactObjectAbsence {
    Absent,
    Present,
    Replaced,
    Unverifiable,
    Transient,
}

const UPSTREAM_CLAIM_UID_LABEL: &str = "agents.x-k8s.io/claim-uid";

/// Validate one recorded namespaced object identity before it is trusted as
/// teardown evidence. Corrupt status must withhold capacity, not redirect an
/// absence check into another namespace or kind.
fn recorded_reference_is_exact(
    reference: &SandboxObjectReference,
    api_version: &str,
    kind: &str,
    namespace: &str,
) -> bool {
    reference.api_version == api_version
        && reference.kind == kind
        && reference.namespace.as_deref() == Some(namespace)
        && !reference.name.is_empty()
        && !reference.uid.is_empty()
}

/// Determine whether an absent Service reference is legitimate.
///
/// New exposed-port leases checkpoint the exact Service UID before Ready. For
/// an older lease that lacks it, the exact Pool generation is the only durable
/// source for whether a Service was required. A missing/replaced/stale Pool
/// cannot prove the negative and therefore fails closed.
async fn missing_service_provenance_is_allowed(
    lease: &SandboxLease,
    ctx: &SandboxContext,
) -> TargetFootprintCheck {
    // A cancelled Provisioning lease may legitimately never have reached the
    // point where the upstream controller created a Service. Label-scoped
    // enumeration behind the inert Claim tombstone proves that negative. Once Ready was
    // reached, however, exposed ports imply a Service existed and its exact
    // identity had to be checkpointed.
    if lease
        .status
        .as_ref()
        .and_then(|status| status.ready_at.as_ref())
        .is_none()
    {
        return TargetFootprintCheck::Verified;
    }
    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match pools.get(&lease.spec.pool_ref.name).await {
        Ok(pool)
            if pool.uid().as_deref() == Some(lease.spec.pool_ref.uid.as_str())
                && pool.metadata.generation == Some(lease.spec.pool_ref.generation) =>
        {
            if pool.spec.template.exposed_ports.is_empty() {
                TargetFootprintCheck::Verified
            } else {
                TargetFootprintCheck::Quarantine("required_service_provenance_missing")
            }
        }
        Ok(_) => TargetFootprintCheck::Quarantine("service_requirement_pool_identity_changed"),
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            TargetFootprintCheck::Quarantine("service_requirement_unverifiable")
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            TargetFootprintCheck::Quarantine("service_requirement_pool_missing")
        }
        Err(_) => TargetFootprintCheck::Retry("service_requirement_lookup_transient"),
    }
}

/// Require complete, exact management provenance before any destructive call.
///
/// The Claim is required once placement started. Descendants are optional
/// while Provisioning because cancellation may race their creation; when
/// present, each reference must still be exact and internally consistent.
/// Ready leases require the full Pod identity and an exact Service identity
/// when their exact Pool generation exposed ports.
async fn validate_management_target_provenance(
    lease: &SandboxLease,
    ctx: &SandboxContext,
) -> TargetFootprintCheck {
    let Some(target) = lease
        .status
        .as_ref()
        .and_then(|status| status.target.as_ref())
    else {
        return TargetFootprintCheck::Quarantine("management_target_provenance_missing");
    };
    if target.namespace != ctx.namespace {
        return TargetFootprintCheck::Quarantine("management_target_namespace_changed");
    }
    let Some(claim) = target.sandbox_claim.as_ref() else {
        return TargetFootprintCheck::Quarantine("claim_provenance_missing");
    };
    if !recorded_reference_is_exact(
        claim,
        AGENT_SANDBOX_API_VERSION,
        SANDBOX_CLAIM_KIND,
        &ctx.namespace,
    ) {
        return TargetFootprintCheck::Quarantine("management_target_provenance_invalid");
    }
    if target.sandbox.as_ref().is_some_and(|sandbox| {
        !recorded_reference_is_exact(
            sandbox,
            crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
            crate::controllers::sandbox_canary::SANDBOX_KIND,
            &ctx.namespace,
        )
    }) || target
        .pod
        .as_ref()
        .is_some_and(|pod| !recorded_reference_is_exact(pod, "v1", "Pod", &ctx.namespace))
        || (target.pod.is_some() && target.sandbox.is_none())
        || (target.service.is_some() && target.sandbox.is_none())
    {
        return TargetFootprintCheck::Quarantine("management_target_provenance_invalid");
    }
    if lease
        .status
        .as_ref()
        .and_then(|status| status.ready_at.as_ref())
        .is_some()
        && target.pod.is_none()
    {
        return TargetFootprintCheck::Quarantine("pod_provenance_missing");
    }
    match target.service.as_ref() {
        Some(service) if recorded_reference_is_exact(service, "v1", "Service", &ctx.namespace) => {
            TargetFootprintCheck::Verified
        }
        Some(_) => TargetFootprintCheck::Quarantine("service_provenance_invalid"),
        None => missing_service_provenance_is_allowed(lease, ctx).await,
    }
}

enum ManagementDescendantCheckpoint {
    Current,
    Updated(Box<crate::crd::SandboxTargetProvenance>),
    Check(TargetFootprintCheck),
}

/// Capture exact descendant identities while the Claim can still name them.
///
/// Cancellation during Provisioning is allowed to observe no assigned
/// Sandbox at all. If one is assigned and already exists, its UID and every
/// currently discoverable Pod/Service UID are checkpointed in lease status in
/// a separate reconcile before tombstone conversion. That closes the race
/// where the workload Claim disappears and only a descendant remains.
async fn checkpoint_management_descendants(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    claims: &Api<DynamicObject>,
) -> ManagementDescendantCheckpoint {
    let validation = validate_management_target_provenance(lease, ctx).await;
    if validation != TargetFootprintCheck::Verified {
        return ManagementDescendantCheckpoint::Check(validation);
    }
    let current_target = lease.status.as_ref().unwrap().target.as_ref().unwrap();
    let claim_ref = current_target.sandbox_claim.as_ref().unwrap();
    let claim = match claims.get(&claim_ref.name).await {
        Ok(claim) if claim.uid().as_deref() == Some(claim_ref.uid.as_str()) => claim,
        // The workload Claim may already be gone and a release tombstone (or
        // a delayed active POST) may now occupy the name. The tombstone helper
        // validates and checkpoints that distinct UID; descendant proof joins
        // both Claim identities afterward.
        Ok(_) => return ManagementDescendantCheckpoint::Current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return ManagementDescendantCheckpoint::Current;
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                "claim_absence_unverifiable",
            ));
        }
        Err(_) => {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Retry(
                "claim_lookup_transient",
            ));
        }
    };
    let Some(sandbox_name) = claim
        .data
        .get("status")
        .and_then(|status| status.get("sandbox"))
        .and_then(|sandbox| sandbox.get("name"))
        .and_then(|name| name.as_str())
        .filter(|name| !name.is_empty())
    else {
        return ManagementDescendantCheckpoint::Current;
    };

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &sandbox_resource());
    let sandbox = match sandboxes.get(sandbox_name).await {
        Ok(sandbox) => sandbox,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return ManagementDescendantCheckpoint::Current;
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                "sandbox_absence_unverifiable",
            ));
        }
        Err(_) => {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Retry(
                "sandbox_lookup_transient",
            ));
        }
    };
    if !metadata_is_controlled_by(
        &sandbox.metadata,
        &claim_ref.api_version,
        &claim_ref.kind,
        &claim_ref.name,
        &claim_ref.uid,
    ) {
        return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
            "sandbox_owner_identity_changed",
        ));
    }
    let sandbox_ref = match target_reference(
        crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
        crate::controllers::sandbox_canary::SANDBOX_KIND,
        &ctx.namespace,
        &sandbox,
    ) {
        Ok(reference) => reference,
        Err(_) => {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                "sandbox_identity_unverifiable",
            ));
        }
    };
    if current_target
        .sandbox
        .as_ref()
        .is_some_and(|recorded| recorded != &sandbox_ref)
    {
        return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
            "sandbox_identity_changed_during_teardown",
        ));
    }

    let mut proposed = current_target.clone();
    proposed.sandbox = Some(sandbox_ref.clone());

    if let Some(service_name) = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("service"))
        .and_then(|service| service.as_str())
        .filter(|service| !service.is_empty())
    {
        let services: Api<DynamicObject> = Api::namespaced_with(
            ctx.client.clone(),
            &ctx.namespace,
            &core_resource("Service", "services"),
        );
        match services.get(service_name).await {
            Ok(service)
                if metadata_is_controlled_by(
                    &service.metadata,
                    &sandbox_ref.api_version,
                    &sandbox_ref.kind,
                    &sandbox_ref.name,
                    &sandbox_ref.uid,
                ) =>
            {
                match target_reference("v1", "Service", &ctx.namespace, &service) {
                    Ok(reference) => proposed.service = Some(reference),
                    Err(_) => {
                        return ManagementDescendantCheckpoint::Check(
                            TargetFootprintCheck::Quarantine("service_identity_unverifiable"),
                        );
                    }
                }
            }
            Ok(_) => {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                    "service_owner_identity_changed",
                ));
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                    "service_absence_unverifiable",
                ));
            }
            Err(_) => {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Retry(
                    "service_lookup_transient",
                ));
            }
        }
    }

    if let Some(selector) = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("selector"))
        .and_then(|selector| selector.as_str())
        .filter(|selector| !selector.is_empty())
    {
        let pods: Api<DynamicObject> = Api::namespaced_with(
            ctx.client.clone(),
            &ctx.namespace,
            &core_resource("Pod", "pods"),
        );
        let matching = match pods.list(&ListParams::default().labels(selector)).await {
            Ok(pods) => pods,
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                    "pod_enumeration_unverifiable",
                ));
            }
            Err(_) => {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Retry(
                    "pod_enumeration_transient",
                ));
            }
        };
        if matching.items.len() > 1 {
            return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                "pod_selector_ambiguous",
            ));
        }
        if let Some(pod) = matching.items.into_iter().next() {
            if !metadata_is_controlled_by(
                &pod.metadata,
                &sandbox_ref.api_version,
                &sandbox_ref.kind,
                &sandbox_ref.name,
                &sandbox_ref.uid,
            ) {
                return ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(
                    "pod_owner_identity_changed",
                ));
            }
            match target_reference("v1", "Pod", &ctx.namespace, &pod) {
                Ok(reference) => proposed.pod = Some(reference),
                Err(_) => {
                    return ManagementDescendantCheckpoint::Check(
                        TargetFootprintCheck::Quarantine("pod_identity_unverifiable"),
                    );
                }
            }
        }
    }

    if &proposed == current_target {
        ManagementDescendantCheckpoint::Current
    } else {
        ManagementDescendantCheckpoint::Updated(Box::new(proposed))
    }
}

/// Observe whether one exact recorded object is absent.
///
/// A same-named replacement and an owner-chain change are durable identity
/// failures, not absence. Authorization failures are likewise durable; other
/// API failures are retried while the lease continues holding capacity.
async fn exact_object_absence(
    api: &Api<DynamicObject>,
    reference: &SandboxObjectReference,
    expected_owner: &SandboxObjectReference,
) -> ExactObjectAbsence {
    match api.get(&reference.name).await {
        Ok(object) if object.uid().as_deref() != Some(reference.uid.as_str()) => {
            ExactObjectAbsence::Replaced
        }
        Ok(object)
            if !metadata_is_controlled_by(
                &object.metadata,
                &expected_owner.api_version,
                &expected_owner.kind,
                &expected_owner.name,
                &expected_owner.uid,
            ) =>
        {
            ExactObjectAbsence::Replaced
        }
        Ok(_) => ExactObjectAbsence::Present,
        Err(kube::Error::Api(error)) if error.code == 404 => ExactObjectAbsence::Absent,
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            ExactObjectAbsence::Unverifiable
        }
        Err(_) => ExactObjectAbsence::Transient,
    }
}

fn classify_exact_absence(
    absence: ExactObjectAbsence,
    present: &'static str,
    replaced: &'static str,
    unverifiable: &'static str,
    transient: &'static str,
) -> TargetFootprintCheck {
    match absence {
        ExactObjectAbsence::Absent => TargetFootprintCheck::Verified,
        ExactObjectAbsence::Present => TargetFootprintCheck::Retry(present),
        ExactObjectAbsence::Replaced => TargetFootprintCheck::Quarantine(replaced),
        ExactObjectAbsence::Unverifiable => TargetFootprintCheck::Quarantine(unverifiable),
        ExactObjectAbsence::Transient => TargetFootprintCheck::Retry(transient),
    }
}

/// Enumerate persistent storage tied to the exact recorded Sandbox owner.
///
/// Kobe sets both upstream volume-claim policies to `Disallowed`, so the only
/// valid result is an empty set. Any exact-owned PVC is therefore a policy
/// violation and any PV whose `claimRef.uid` points to it is retained evidence
/// of the same unexpected tenant storage. Neither is deleted automatically:
/// quarantine preserves the evidence for an operator.
async fn exact_owned_storage_is_absent(
    client: &Client,
    namespace: &str,
    claim_uids: &[&str],
    sandbox: Option<&SandboxObjectReference>,
) -> TargetFootprintCheck {
    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let owned: Vec<_> = match pvcs.list(&ListParams::default()).await {
        Ok(pvcs) => pvcs
            .into_iter()
            .filter(|pvc| {
                sandbox.is_some_and(|sandbox| {
                    metadata_is_controlled_by(
                        &pvc.metadata,
                        &sandbox.api_version,
                        &sandbox.kind,
                        &sandbox.name,
                        &sandbox.uid,
                    )
                }) || pvc
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(UPSTREAM_CLAIM_UID_LABEL))
                    .is_some_and(|uid| claim_uids.contains(&uid.as_str()))
            })
            .collect(),
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return TargetFootprintCheck::Quarantine("pvc_enumeration_unverifiable");
        }
        Err(_) => return TargetFootprintCheck::Retry("pvc_enumeration_transient"),
    };
    let pvc_uids: Vec<_> = owned
        .iter()
        .filter_map(|pvc| pvc.uid().filter(|uid| !uid.is_empty()))
        .collect();

    let volumes: Api<PersistentVolume> = Api::all(client.clone());
    let associated_volumes = match volumes.list(&ListParams::default()).await {
        Ok(volumes) => volumes
            .into_iter()
            .filter(|volume| {
                volume
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.claim_ref.as_ref())
                    .and_then(|claim| claim.uid.as_ref())
                    .is_some_and(|uid| pvc_uids.iter().any(|pvc_uid| pvc_uid == uid))
            })
            .count(),
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return TargetFootprintCheck::Quarantine("pv_enumeration_unverifiable");
        }
        Err(_) => return TargetFootprintCheck::Retry("pv_enumeration_transient"),
    };

    if owned.is_empty() && associated_volumes == 0 {
        TargetFootprintCheck::Verified
    } else {
        warn!(
            sandbox = sandbox
                .map(|sandbox| sandbox.name.as_str())
                .unwrap_or("<unassigned>"),
            pvc_count = owned.len(),
            pv_count = associated_volumes,
            "unexpected persistent storage is still associated with a Sandbox"
        );
        TargetFootprintCheck::Quarantine("unexpected_persistent_storage")
    }
}

/// Preflight management teardown before converting the Claim to a tombstone.
///
/// Storage is enumerated before tombstone conversion so a retained PV cannot
/// outlive and erase the PVC identity needed to associate it with this exact
/// Sandbox.
async fn preflight_management_target(
    lease: &SandboxLease,
    ctx: &SandboxContext,
) -> TargetFootprintCheck {
    let validation = validate_management_target_provenance(lease, ctx).await;
    if validation != TargetFootprintCheck::Verified {
        return validation;
    }
    let target = lease.status.as_ref().unwrap().target.as_ref().unwrap();
    let claim = target.sandbox_claim.as_ref().unwrap();
    exact_owned_storage_is_absent(
        &ctx.client,
        &ctx.namespace,
        &[claim.uid.as_str()],
        target.sandbox.as_ref(),
    )
    .await
}

/// Require the upstream Claim-UID Sandbox index to be empty.
///
/// This closes the create-after-observe race for cancelled Provisioning
/// leases that never had a descendant UID to checkpoint. An unrecorded live
/// Sandbox quarantines because its children cannot be joined safely after it
/// disappears; a recorded live Sandbox is "not yet". Replacements and
/// authorization failures are durable uncertainty.
async fn claim_labelled_sandboxes_absent(
    api: &Api<DynamicObject>,
    claim_uid: &str,
    recorded: Option<&SandboxObjectReference>,
) -> TargetFootprintCheck {
    let selector = format!("{UPSTREAM_CLAIM_UID_LABEL}={claim_uid}");
    match api.list(&ListParams::default().labels(&selector)).await {
        Ok(objects) if objects.items.is_empty() => TargetFootprintCheck::Verified,
        Ok(objects) => match recorded {
            Some(recorded)
                if objects.items.len() == 1
                    && objects.items[0].name_any() == recorded.name
                    && objects.items[0].uid().as_deref() == Some(recorded.uid.as_str()) =>
            {
                TargetFootprintCheck::Retry("claim_labelled_sandbox_still_present")
            }
            Some(_) => TargetFootprintCheck::Quarantine("claim_labelled_sandbox_replaced"),
            None => TargetFootprintCheck::Quarantine("claim_labelled_sandbox_unrecorded"),
        },
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            TargetFootprintCheck::Quarantine("sandbox_enumeration_unverifiable")
        }
        Err(_) => TargetFootprintCheck::Retry("sandbox_enumeration_transient"),
    }
}

/// Enumerate children whose controller owner is the exact recorded Sandbox.
///
/// Agent Sandbox labels Services with a sandbox-name hash, not the Claim UID,
/// so label-only proof would miss a late Service. Owner UID is the stable join
/// shared by Pod, Service and PVC.
async fn exact_owned_objects_absent(
    api: &Api<DynamicObject>,
    sandbox: &SandboxObjectReference,
    recorded: Option<&SandboxObjectReference>,
    present: &'static str,
    replaced: &'static str,
    unverifiable: &'static str,
    transient: &'static str,
) -> TargetFootprintCheck {
    match api.list(&ListParams::default()).await {
        Ok(objects) => {
            let owned: Vec<_> = objects
                .items
                .into_iter()
                .filter(|object| {
                    metadata_is_controlled_by(
                        &object.metadata,
                        &sandbox.api_version,
                        &sandbox.kind,
                        &sandbox.name,
                        &sandbox.uid,
                    )
                })
                .collect();
            if owned.is_empty() {
                TargetFootprintCheck::Verified
            } else if recorded.is_some_and(|recorded| {
                owned.iter().any(|object| {
                    object.name_any() == recorded.name
                        && object.uid().as_deref() != Some(recorded.uid.as_str())
                })
            }) {
                TargetFootprintCheck::Quarantine(replaced)
            } else {
                TargetFootprintCheck::Retry(present)
            }
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            TargetFootprintCheck::Quarantine(unverifiable)
        }
        Err(_) => TargetFootprintCheck::Retry(transient),
    }
}

/// Resolve Agent Sandbox owner chains when cancellation happened before Kobe
/// could record a Sandbox UID.
///
/// A child whose owner Sandbox is already absent is deliberately treated as
/// unresolved rather than unrelated: it may be the orphan left by this Claim.
/// Live owners for another exact Claim can be excluded safely; everything else
/// retries or quarantines while capacity stays held.
async fn unresolved_sandbox_children_absent(
    api: &Api<DynamicObject>,
    sandboxes: &Api<DynamicObject>,
    claim: &SandboxObjectReference,
    present: &'static str,
    unverifiable: &'static str,
    transient: &'static str,
) -> TargetFootprintCheck {
    let objects = match api.list(&ListParams::default()).await {
        Ok(objects) => objects,
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return TargetFootprintCheck::Quarantine(unverifiable);
        }
        Err(_) => return TargetFootprintCheck::Retry(transient),
    };
    for owner in objects.items.iter().filter_map(|object| {
        object
            .metadata
            .owner_references
            .as_ref()
            .and_then(|owners| {
                owners.iter().find(|owner| {
                    owner.controller == Some(true)
                        && owner.api_version
                            == crate::controllers::sandbox_canary::SANDBOX_API_VERSION
                        && owner.kind == crate::controllers::sandbox_canary::SANDBOX_KIND
                })
            })
    }) {
        match sandboxes.get(&owner.name).await {
            Ok(sandbox) if sandbox.uid().as_deref() == Some(owner.uid.as_str()) => {
                if metadata_is_controlled_by(
                    &sandbox.metadata,
                    &claim.api_version,
                    &claim.kind,
                    &claim.name,
                    &claim.uid,
                ) || sandbox
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(UPSTREAM_CLAIM_UID_LABEL))
                    .is_some_and(|uid| uid == &claim.uid)
                {
                    return TargetFootprintCheck::Retry(present);
                }
            }
            // A replacement or absent owner cannot prove this orphan belongs
            // to another Claim; wait for garbage collection instead.
            Ok(_) => {
                return TargetFootprintCheck::Retry(present);
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return TargetFootprintCheck::Retry(present);
            }
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                return TargetFootprintCheck::Quarantine(unverifiable);
            }
            Err(_) => return TargetFootprintCheck::Retry(transient),
        }
    }
    TargetFootprintCheck::Verified
}

/// Prove every management descendant absent behind an exact inert Claim.
///
/// The retained expired Claim keeps its deterministic name occupied, fencing
/// delayed creates. The original workload Claim UID remains the join for
/// descendants created before teardown; a replacement tombstone UID is also
/// searched because a stale active POST may have won just before conversion.
async fn management_target_footprint_absent(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    tombstone: &SandboxObjectReference,
    prior_claim_uid: Option<&str>,
) -> TargetFootprintCheck {
    let validation = validate_management_target_provenance(lease, ctx).await;
    if validation != TargetFootprintCheck::Verified {
        return validation;
    }
    let target = lease.status.as_ref().unwrap().target.as_ref().unwrap();
    let claim = target.sandbox_claim.as_ref().unwrap();
    if lease
        .status
        .as_ref()
        .and_then(|status| status.sandbox_claim_tombstone.as_ref())
        != Some(tombstone)
        || prior_claim_uid != Some(claim.uid.as_str())
        || !recorded_reference_is_exact(
            tombstone,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &ctx.namespace,
        )
        || tombstone.name != claim.name
    {
        return TargetFootprintCheck::Quarantine("claim_tombstone_provenance_invalid");
    }
    let sandbox = target.sandbox.as_ref();

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &sandbox_resource());
    if let Some(sandbox) = sandbox {
        let check = classify_exact_absence(
            exact_object_absence(&sandboxes, sandbox, claim).await,
            "sandbox_still_present",
            "sandbox_identity_changed_during_teardown",
            "sandbox_absence_unverifiable",
            "sandbox_absence_transient",
        );
        if check != TargetFootprintCheck::Verified {
            return check;
        }
    }

    let pods: Api<DynamicObject> = Api::namespaced_with(
        ctx.client.clone(),
        &ctx.namespace,
        &core_resource("Pod", "pods"),
    );
    if let (Some(pod), Some(sandbox)) = (target.pod.as_ref(), sandbox) {
        let check = classify_exact_absence(
            exact_object_absence(&pods, pod, sandbox).await,
            "pod_still_present",
            "pod_identity_changed_during_teardown",
            "pod_absence_unverifiable",
            "pod_absence_transient",
        );
        if check != TargetFootprintCheck::Verified {
            return check;
        }
    }

    let services: Api<DynamicObject> = Api::namespaced_with(
        ctx.client.clone(),
        &ctx.namespace,
        &core_resource("Service", "services"),
    );
    if let (Some(service), Some(sandbox)) = (target.service.as_ref(), sandbox) {
        let check = classify_exact_absence(
            exact_object_absence(&services, service, sandbox).await,
            "service_still_present",
            "service_identity_changed_during_teardown",
            "service_absence_unverifiable",
            "service_absence_transient",
        );
        if check != TargetFootprintCheck::Verified {
            return check;
        }
    }

    let mut claim_refs = vec![claim];
    if tombstone.uid != claim.uid {
        claim_refs.push(tombstone);
    }
    for claim_ref in &claim_refs {
        let check = claim_labelled_sandboxes_absent(&sandboxes, &claim_ref.uid, sandbox).await;
        if check != TargetFootprintCheck::Verified {
            return check;
        }
    }

    if let Some(sandbox) = sandbox {
        for check in [
            exact_owned_objects_absent(
                &pods,
                sandbox,
                target.pod.as_ref(),
                "sandbox_owned_pod_still_present",
                "sandbox_owned_pod_replaced",
                "pod_enumeration_unverifiable",
                "pod_enumeration_transient",
            )
            .await,
            exact_owned_objects_absent(
                &services,
                sandbox,
                target.service.as_ref(),
                "sandbox_owned_service_still_present",
                "sandbox_owned_service_replaced",
                "service_enumeration_unverifiable",
                "service_enumeration_transient",
            )
            .await,
        ] {
            if check != TargetFootprintCheck::Verified {
                return check;
            }
        }
    } else {
        for claim_ref in &claim_refs {
            for check in [
                unresolved_sandbox_children_absent(
                    &pods,
                    &sandboxes,
                    claim_ref,
                    "unresolved_sandbox_owned_pod_present",
                    "pod_owner_chain_unverifiable",
                    "pod_owner_chain_transient",
                )
                .await,
                unresolved_sandbox_children_absent(
                    &services,
                    &sandboxes,
                    claim_ref,
                    "unresolved_sandbox_owned_service_present",
                    "service_owner_chain_unverifiable",
                    "service_owner_chain_transient",
                )
                .await,
            ] {
                if check != TargetFootprintCheck::Verified {
                    return check;
                }
            }
        }
    }

    let claim_uids: Vec<_> = claim_refs
        .iter()
        .map(|claim_ref| claim_ref.uid.as_str())
        .collect();
    exact_owned_storage_is_absent(&ctx.client, &ctx.namespace, &claim_uids, sandbox).await
}

/// Prove the empty footprint behind an admission-only release tombstone.
///
/// `AdmissionOnlyV1` was persisted in the same fenced write that changed the
/// exact fresh Pending status to Releasing. There is consequently no workload
/// Claim UID or target provenance to recover. The retained Claim only closes
/// the deterministic name; its UID is still scanned so a malformed descendant
/// cannot be mistaken for absence.
async fn admission_only_management_footprint_absent(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    tombstone: &SandboxObjectReference,
    prior_claim_uid: Option<&str>,
) -> TargetFootprintCheck {
    let status = lease.status.clone().unwrap_or_default();
    if status.claim_cleanup_fence != Some(crate::crd::SandboxClaimCleanupFence::AdmissionOnlyV1)
        || status.observed_generation.is_some()
        || status.ready_at.is_some()
        || status.expires_at.is_some()
        || status.placement.is_some()
        || status.target.is_some()
        || prior_claim_uid.is_some()
        || status.sandbox_claim_tombstone.as_ref() != Some(tombstone)
        || !recorded_reference_is_exact(
            tombstone,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &ctx.namespace,
        )
        || tombstone.name != claim_name(&lease.name_any())
    {
        return TargetFootprintCheck::Quarantine("admission_only_provenance_invalid");
    }

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &sandbox_resource());
    let check = claim_labelled_sandboxes_absent(&sandboxes, &tombstone.uid, None).await;
    if check != TargetFootprintCheck::Verified {
        return check;
    }

    for (api, present, unverifiable, transient) in [
        (
            Api::namespaced_with(
                ctx.client.clone(),
                &ctx.namespace,
                &core_resource("Pod", "pods"),
            ),
            "admission_only_sandbox_owned_pod_present",
            "pod_owner_chain_unverifiable",
            "pod_owner_chain_transient",
        ),
        (
            Api::namespaced_with(
                ctx.client.clone(),
                &ctx.namespace,
                &core_resource("Service", "services"),
            ),
            "admission_only_sandbox_owned_service_present",
            "service_owner_chain_unverifiable",
            "service_owner_chain_transient",
        ),
    ] {
        let check = unresolved_sandbox_children_absent(
            &api,
            &sandboxes,
            tombstone,
            present,
            unverifiable,
            transient,
        )
        .await;
        if check != TargetFootprintCheck::Verified {
            return check;
        }
    }

    exact_owned_storage_is_absent(&ctx.client, &ctx.namespace, &[tombstone.uid.as_str()], None)
        .await
}

/// Record the exact tombstone as the sole management Claim identity when the
/// pre-POST cleanup protocol proves no active Claim could have disappeared.
///
/// `AdmissionOnlyV1` is written with Releasing from an exact fresh Pending
/// shape, so no producer POST was authorised; the tombstone plus empty scans
/// prove that footprint stayed empty. `FinalizerV1` instead precedes create and
/// makes every active Claim non-GC-dependent. After allocation drain, observing
/// only the inert tombstone proves that active POST never committed. Leases
/// with neither checkpoint remain fail-closed.
async fn checkpoint_never_started_management_claim(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    tombstone: &SandboxObjectReference,
    prior_claim_uid: Option<&str>,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    let mut next = lease.status.clone().unwrap_or_default();
    if next.claim_cleanup_fence == Some(crate::crd::SandboxClaimCleanupFence::AdmissionOnlyV1) {
        return match admission_only_management_footprint_absent(
            lease,
            ctx,
            tombstone,
            prior_claim_uid,
        )
        .await
        {
            TargetFootprintCheck::Verified => finish_release(lease, ctx, reason).await,
            TargetFootprintCheck::Retry(check) => {
                debug!(lease = %lease.name_any(), check, "admission-only footprint proof will retry");
                Ok(Action::requeue(std::time::Duration::from_secs(10)))
            }
            TargetFootprintCheck::Quarantine(check) => quarantine_lease(lease, ctx, check).await,
        };
    }
    if next.claim_cleanup_fence != Some(crate::crd::SandboxClaimCleanupFence::FinalizerV1) {
        return quarantine_lease(lease, ctx, "claim_provenance_missing_after_absence").await;
    }
    let Some(target) = next.target.as_mut() else {
        return quarantine_lease(lease, ctx, "management_target_provenance_missing").await;
    };
    if target.namespace != ctx.namespace
        || target.sandbox_claim.is_some()
        || !recorded_reference_is_exact(
            tombstone,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            &ctx.namespace,
        )
        || tombstone.name != claim_name(&lease.name_any())
    {
        return quarantine_lease(lease, ctx, "claim_tombstone_provenance_invalid").await;
    }
    target.sandbox_claim = Some(tombstone.clone());
    if patch_lease_status_fenced(ctx, lease, &next).await? {
        info!(lease = %lease.name_any(), "checkpointed fenced management Claim as never started");
    } else {
        debug!(lease = %lease.name_any(), "never-started Claim checkpoint lost a status race");
    }
    Ok(Action::await_change())
}

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
        if admitted_pending_is_allocation_free(lease, &status) {
            next.claim_cleanup_fence = Some(crate::crd::SandboxClaimCleanupFence::AdmissionOnlyV1);
        }
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            info!(lease = %name, reason = reason.as_str(), "releasing Sandbox lease");
        } else {
            debug!(lease = %name, "Releasing checkpoint lost a status race");
        }
        return Ok(Action::await_change());
    }

    // Close the API-server gate before touching credentials or workload.
    // Every handler enters this exact gate before it resolves the target or
    // mints a Pod-bound token, and the close races entry under one
    // resourceVersion. Empty therefore proves that every replica has dropped
    // its registered operation; a local watch or a sleep cannot provide that
    // cross-replica ordering guarantee.
    if ctx.access_ledger_enabled {
        match crate::sandbox_access_ledger::close_and_drain(
            &ctx.client,
            &ctx.reservation_namespace,
            lease,
        )
        .await
        {
            Ok(crate::sandbox_access_ledger::AccessDrain::Drained) => {}
            Ok(
                crate::sandbox_access_ledger::AccessDrain::Checkpointed
                | crate::sandbox_access_ledger::AccessDrain::Waiting,
            ) => return Ok(Action::requeue(std::time::Duration::from_secs(2))),
            Err(
                crate::sandbox_access_ledger::AccessLedgerError::Invalid(_)
                | crate::sandbox_access_ledger::AccessLedgerError::Serialization(_),
            ) => return quarantine_lease(lease, ctx, "access_drain_unverifiable").await,
            Err(crate::sandbox_access_ledger::AccessLedgerError::Kubernetes(kube::Error::Api(
                response,
            ))) if response.code == 401 || response.code == 403 => {
                return quarantine_lease(lease, ctx, "access_drain_forbidden").await;
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not prove Sandbox access drained");
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
        }
    }

    // Close allocation before inspecting teardown. Every create path performs
    // its final outer/pool/fence reads and POST inside one bounded future; once
    // this durable fence has existed for that whole bound, no stale create can
    // still arrive after an absence proof.
    match ensure_allocation_fence(lease, ctx).await? {
        AllocationFence::Ready => {}
        AllocationFence::Checkpointed => return Ok(Action::await_change()),
        AllocationFence::Draining(delay) => return Ok(Action::requeue(delay)),
        AllocationFence::Quarantine(reason) if footprint_absence_proven(&status) => {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "AllocationFenceInvalid",
                reason,
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        AllocationFence::Quarantine(reason) => {
            return quarantine_lease(lease, ctx, reason).await;
        }
    }

    let child_placed = is_child_placed(lease, ctx).await;

    // Durable executions are capabilities plus process groups, not audit-only
    // records. On management placement, cancel/prove every exact runner group
    // before scoped credentials or the Claim disappear. A supervisor_lost
    // Unknown deliberately keeps its record and capacity; in that case Claim
    // destruction supplies the stronger process-absence proof and the record is
    // retired on the post-proof pass below. The closed access gate prevents any
    // new bind/spawn from racing either path.
    if ctx.access_ledger_enabled && !child_placed && !footprint_absence_proven(&status) {
        match execution_cleanup_advance(
            crate::api::sandbox_executions::cleanup_lease_executions(
                &ctx.client,
                &ctx.namespace,
                &ctx.reservation_namespace,
                lease,
                &ctx.client,
                &ctx.shutdown,
            )
            .await,
        ) {
            ExecutionCleanupAdvance::Continue | ExecutionCleanupAdvance::DestroyTarget => {}
            ExecutionCleanupAdvance::Checkpointed => {
                return Ok(execution_cleanup_checkpoint_action());
            }
            ExecutionCleanupAdvance::Retry => {
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
            ExecutionCleanupAdvance::Quarantine(reason) => {
                return quarantine_lease(lease, ctx, reason).await;
            }
        }
    }

    // Scoped identities are externally usable capabilities. Remove and prove
    // them absent before retiring the management workload, including when an old
    // controller already checkpointed footprint absence. A lease without Pod
    // provenance could never mint one, so there is nothing to clean.
    if !child_placed
        && let Some(target) = status.target.as_ref()
        && let Some(pod) = target.pod.as_ref()
    {
        let lease_uid = lease.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no UID to clean scoped identities"
            ))
        })?;
        if target.namespace != ctx.namespace || pod.name.is_empty() || pod.uid.is_empty() {
            return quarantine_lease(lease, ctx, "credential_provenance_invalid").await;
        }
        match crate::api::sandbox_credentials::cleanup_scoped_identities(
            &ctx.client,
            &target.namespace,
            &lease_uid,
            &pod.name,
            &pod.uid,
        )
        .await
        {
            crate::api::sandbox_credentials::CredentialCleanupOutcome::Clean => {}
            crate::api::sandbox_credentials::CredentialCleanupOutcome::Retry => {
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
            crate::api::sandbox_credentials::CredentialCleanupOutcome::Quarantine => {
                return quarantine_lease(lease, ctx, "credential_cleanup_unverifiable").await;
            }
        }
    }

    // Footprint absence is a durable linearization point. Once it wins its
    // fenced race against quarantine, every retry skips workload teardown and
    // completes only the idempotent reservation/terminal tail. Management
    // credentials were intentionally handled above because older proof
    // checkpoints did not include them.
    if footprint_absence_proven(&status) {
        if child_placed {
            return Box::pin(finish_child_release_after_proof(lease, ctx, reason)).await;
        }
        if ctx.access_ledger_enabled {
            match crate::api::sandbox_executions::cleanup_lease_executions_after_target_absence(
                &ctx.client,
                &ctx.namespace,
                &ctx.reservation_namespace,
                lease,
                &ctx.shutdown,
            )
            .await
            {
                crate::api::sandbox_executions::ExecutionCleanupOutcome::Clean => {}
                crate::api::sandbox_executions::ExecutionCleanupOutcome::Checkpointed => {
                    return Ok(execution_cleanup_checkpoint_action());
                }
                crate::api::sandbox_executions::ExecutionCleanupOutcome::Retry
                | crate::api::sandbox_executions::ExecutionCleanupOutcome::AwaitTargetDestruction =>
                {
                    return record_post_proof_cleanup_failure(
                        lease,
                        ctx,
                        "ManagementExecutionCleanupRetry",
                        "Target absence is proven, but exact execution retirement must be retried",
                        std::time::Duration::from_secs(15),
                    )
                    .await;
                }
                crate::api::sandbox_executions::ExecutionCleanupOutcome::Quarantine(_) => {
                    return record_post_proof_cleanup_failure(
                        lease,
                        ctx,
                        "ManagementExecutionCleanupInvalid",
                        "Target absence is proven, but execution provenance is contradictory",
                        std::time::Duration::from_secs(300),
                    )
                    .await;
                }
            }
        }
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
    if child_placed {
        // Keep the large, proof-carrying child state machine off this already
        // broad reconcile future. Besides bounding controller task frames,
        // this prevents test/runtime thread stacks from depending on how many
        // child teardown checkpoints are added over time.
        return Box::pin(release_child_composition(lease, ctx, reason)).await;
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
    // but no recorded UID. Recover only an object carrying this exact lease
    // UID and no GC owner, persist its identity, and end the pass before
    // deleting anything.
    let recorded_claim = if let Some(recorded) = recorded_claim {
        recorded
    } else {
        let observed = match claims.get(&claim).await {
            Ok(observed) => observed,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                // Close the name before quarantining missing provenance. A
                // POST whose response/commit was delayed can still win after
                // this 404; the Retain tombstone makes that race either a 409
                // or an exact object the next pass can recover and convert.
                match ensure_management_claim_tombstone(lease, ctx, &claims).await? {
                    ManagementClaimTombstone::Checkpointed => {
                        return Ok(Action::await_change());
                    }
                    ManagementClaimTombstone::Retry(after) => {
                        return Ok(Action::requeue(after));
                    }
                    ManagementClaimTombstone::Ready {
                        tombstone_ref,
                        prior_claim_uid,
                        ..
                    } => {
                        return checkpoint_never_started_management_claim(
                            lease,
                            ctx,
                            &tombstone_ref,
                            prior_claim_uid.as_deref(),
                            reason,
                        )
                        .await;
                    }
                    ManagementClaimTombstone::Quarantine(check) => {
                        return quarantine_lease(lease, ctx, check).await;
                    }
                }
            }
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                return quarantine_lease(lease, ctx, "claim_absence_unverifiable").await;
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not recover upstream claim identity");
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
        };
        let observed_is_tombstone = status.sandbox_claim_tombstone.is_some()
            || observed
                .labels()
                .get(SANDBOX_CLAIM_TOMBSTONE_LABEL)
                .is_some_and(|value| value == "true")
            || observed
                .annotations()
                .contains_key(SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION)
            || observed
                .data
                .pointer("/spec/lifecycle/shutdownPolicy")
                .and_then(serde_json::Value::as_str)
                == Some("Retain");
        if observed_is_tombstone {
            // A tombstone is not provenance for the Claim whose descendants
            // may have existed before it. Keep its separate UID checkpoint and
            // fail closed instead of promoting it into target.sandboxClaim.
            return match ensure_management_claim_tombstone(lease, ctx, &claims).await? {
                ManagementClaimTombstone::Checkpointed => Ok(Action::await_change()),
                ManagementClaimTombstone::Retry(after) => Ok(Action::requeue(after)),
                ManagementClaimTombstone::Ready {
                    tombstone_ref,
                    prior_claim_uid,
                    ..
                } => {
                    checkpoint_never_started_management_claim(
                        lease,
                        ctx,
                        &tombstone_ref,
                        prior_claim_uid.as_deref(),
                        reason,
                    )
                    .await
                }
                ManagementClaimTombstone::Quarantine(check) => {
                    quarantine_lease(lease, ctx, check).await
                }
            };
        }
        let lease_uid = lease.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no UID to recover claim provenance"
            ))
        })?;
        if !claim_is_for_lease(&observed, &lease_uid) {
            return quarantine_lease(lease, ctx, "claim_identity_unverifiable").await;
        }
        if observed.metadata.deletion_timestamp.is_some() {
            if !metadata_has_no_owner_references(&observed.metadata)
                || !sandbox_claim_cleanup_finalizer_present(&observed)
            {
                return quarantine_lease(lease, ctx, "claim_identity_unverifiable").await;
            }
        } else {
            match ensure_management_claim_fenced(&claims, &observed, lease, &ctx.namespace).await? {
                ManagementClaimFence::Ready => {}
                ManagementClaimFence::Patched => {
                    info!(lease = %name, claim = %observed.name_any(), "migrated exact legacy management Claim during release recovery");
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
                ManagementClaimFence::Foreign => {
                    return quarantine_lease(lease, ctx, "claim_identity_unverifiable").await;
                }
            }
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
                child_cluster_kubeconfig_secret: None,
                child_cluster_kubeconfig_sha256: None,
                sandbox_template: None,
                sandbox_warm_pool: None,
                sandbox_claim: None,
                sandbox: None,
                pod: None,
                service: None,
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

    match checkpoint_management_descendants(lease, ctx, &claims).await {
        ManagementDescendantCheckpoint::Current => {}
        ManagementDescendantCheckpoint::Updated(target) => {
            let mut next = status.clone();
            next.target = Some(*target);
            if patch_lease_status_fenced(ctx, lease, &next).await? {
                info!(lease = %name, "checkpointed management descendants before teardown");
            } else {
                debug!(lease = %name, "descendant checkpoint lost a status race");
            }
            return Ok(Action::await_change());
        }
        ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Retry(check)) => {
            debug!(lease = %name, check, "management descendant checkpoint will retry");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }
        ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Quarantine(check)) => {
            return quarantine_lease(lease, ctx, check).await;
        }
        ManagementDescendantCheckpoint::Check(TargetFootprintCheck::Verified) => {}
    }

    match preflight_management_target(lease, ctx).await {
        TargetFootprintCheck::Verified => {}
        TargetFootprintCheck::Retry(check) => {
            debug!(lease = %name, check, "management teardown preflight will retry");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }
        TargetFootprintCheck::Quarantine(check) => {
            return quarantine_lease(lease, ctx, check).await;
        }
    }

    // Keep the deterministic Claim name occupied by an exact expired `Retain`
    // tombstone. Deleting it would reopen the name for a delayed stale POST,
    // allowing workload to resurrect after FootprintAbsent was checkpointed.
    let (tombstone, prior_claim_uid) =
        match ensure_management_claim_tombstone(lease, ctx, &claims).await? {
            ManagementClaimTombstone::Checkpointed => return Ok(Action::await_change()),
            ManagementClaimTombstone::Ready {
                claim: current,
                tombstone_ref,
                prior_claim_uid,
            } => {
                if require_exact_reference(
                    &tombstone_ref,
                    AGENT_SANDBOX_API_VERSION,
                    SANDBOX_CLAIM_KIND,
                    &ctx.namespace,
                    &claim,
                    &current,
                )
                .is_err()
                {
                    return quarantine_lease(lease, ctx, "claim_tombstone_identity_changed").await;
                }
                (tombstone_ref, prior_claim_uid)
            }
            ManagementClaimTombstone::Retry(after) => return Ok(Action::requeue(after)),
            ManagementClaimTombstone::Quarantine(check) => {
                return quarantine_lease(lease, ctx, check).await;
            }
        };

    match management_target_footprint_absent(lease, ctx, &tombstone, prior_claim_uid.as_deref())
        .await
    {
        TargetFootprintCheck::Verified => {}
        TargetFootprintCheck::Retry(check) => {
            debug!(lease = %name, check, "recorded management footprint is not absent yet");
            return Ok(Action::requeue(std::time::Duration::from_secs(10)));
        }
        TargetFootprintCheck::Quarantine(check) => {
            return quarantine_lease(lease, ctx, check).await;
        }
    }

    // The footprint is gone. Now, and only now, the slot goes back.
    finish_release(lease, ctx, reason).await
}

/// Atomically consume a verified child receipt into the outer absence proof.
///
/// Execution cleanup has completed before this call. Recording the exact
/// receipt hash and `FootprintAbsent=True` together prevents either checkpoint
/// from being replayed with different receipt bytes after a restart.
async fn checkpoint_child_receipt_absence(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    token: &str,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();
    if let Some(existing) = status.child_teardown_receipt_acknowledgement.as_deref() {
        if existing != token {
            return quarantine_lease(lease, ctx, "child_receipt_acknowledgement_changed").await;
        }
        if footprint_absence_proven(&status) {
            return Ok(Action::await_change());
        }
    }
    let mut next = status.clone();
    next.child_teardown_receipt_acknowledgement = Some(token.to_string());
    next.conditions = with_condition_for_status(
        &status,
        lease.metadata.generation,
        FOOTPRINT_ABSENT_CONDITION,
        crate::crd::SandboxConditionStatus::True,
        "ChildReceiptConsumed",
        "Exact child teardown receipt and execution cleanup were verified",
    );
    if patch_lease_status_fenced(ctx, lease, &next).await? {
        info!(lease = %name, "child receipt and footprint absence checkpointed");
    } else {
        debug!(lease = %name, "child receipt checkpoint lost a status race");
    }
    Ok(Action::await_change())
}

/// Atomically persist the exact evidence identity and `FootprintAbsent` after
/// execution cleanup, before asking the authority to acknowledge it.
///
/// Receipt bytes without the immutable evidence reference are not durable
/// proof, while evidence without the same absence checkpoint could be replayed
/// across a crash into a different capacity-release decision.
async fn checkpoint_child_receipt_handoff(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    token: &str,
    evidence: &crate::crd::TeardownEvidenceReference,
) -> Result<bool, SandboxPlacementError> {
    let status = lease.status.clone().unwrap_or_default();
    let exact_handoff = status.child_teardown_receipt_acknowledgement.as_deref() == Some(token)
        && status.child_teardown_evidence.as_ref() == Some(evidence);
    if exact_handoff && footprint_absence_proven(&status) {
        return Ok(true);
    }
    if !exact_handoff
        && (status.child_teardown_receipt_acknowledgement.is_some()
            || status.child_teardown_evidence.is_some()
            || status.child_unbound_release_proof.is_some())
    {
        return Ok(false);
    }
    let mut next = status.clone();
    next.child_teardown_receipt_acknowledgement = Some(token.to_string());
    next.child_teardown_evidence = Some(evidence.clone());
    next.conditions = with_condition_for_status(
        &status,
        lease.metadata.generation,
        FOOTPRINT_ABSENT_CONDITION,
        crate::crd::SandboxConditionStatus::True,
        "ChildAuthorityEvidenceConsumed",
        "Exact child teardown evidence and execution cleanup were verified",
    );
    patch_lease_status_fenced(ctx, lease, &next).await
}

/// Release the admission reservations and reach the terminal phase.
///
/// Only ever called once the footprint has been *proven* absent — by an exact
/// Claim tombstone plus descendant scans for management placement, or by the
/// child cluster for a composition. Both placements share this tail so their
/// release semantics cannot drift apart, which is the equivalence #76 sets
/// out to prove.
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
        Api::namespaced(ctx.client.clone(), &ctx.reservation_namespace);
    if let Err(error) =
        crate::api::sandbox::release_reservations_for_lease(&reservations, lease, &uid).await
    {
        // The Sandbox is gone but the slot is still booked. Retry rather than
        // finish: a lease marked terminal with a live reservation leaks that
        // slot with nothing left to reconcile it.
        warn!(lease = %name, error = %error, "could not release admission reservations");
        return record_post_proof_cleanup_failure(
            lease,
            ctx,
            "ReservationReleaseRetry",
            "Workload absence is proven, but admission reservations are still held",
            std::time::Duration::from_secs(15),
        )
        .await;
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

/// Persist cleanup failure after `FootprintAbsent=True` without attempting an
/// impossible transition to `Quarantined`.
///
/// The lease remains `Releasing`, so it still consumes capacity while a live
/// reservation or unretired handle exists. Recording `CleanupVerified=False`
/// makes the stalled tail observable across restarts; retrying the same reason
/// does not rewrite status or advance `lastTransitionTime`.
async fn record_post_proof_cleanup_failure(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: &str,
    message: &str,
    retry: std::time::Duration,
) -> Result<Action, SandboxPlacementError> {
    let status = lease.status.clone().unwrap_or_default();
    debug_assert!(footprint_absence_proven(&status));
    let already_recorded = status.conditions.iter().any(|condition| {
        condition.condition_type == CLEANUP_VERIFIED_CONDITION
            && condition.status == crate::crd::SandboxConditionStatus::False
            && condition.reason == reason
            && condition.message == message
    });
    if already_recorded {
        return Ok(Action::requeue(retry));
    }

    let mut next = status.clone();
    next.conditions = with_condition_for_status(
        &status,
        lease.metadata.generation,
        CLEANUP_VERIFIED_CONDITION,
        crate::crd::SandboxConditionStatus::False,
        reason,
        message,
    );
    if !patch_lease_status_fenced(ctx, lease, &next).await? {
        debug!(lease = %lease.name_any(), reason, "post-proof cleanup failure checkpoint lost a status race");
        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
    }
    warn!(lease = %lease.name_any(), reason, "post-proof cleanup remains incomplete");
    Ok(Action::requeue(retry))
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
/// this lease's derived name. Exact label/UID validation happens before any
/// mutation; even a foreign same-named object selects the conservative child
/// path and is quarantined there instead of letting a management 404 release
/// capacity. The artifact exists from the moment a cluster is allocated and,
/// unlike the pool spec, survives the pool being edited or deleted.
async fn is_child_placed(lease: &SandboxLease, ctx: &SandboxContext) -> bool {
    let status = lease.status.clone().unwrap_or_default();
    match status.placement {
        Some(crate::crd::ResolvedSandboxPlacement::Management {}) => return false,
        Some(crate::crd::ResolvedSandboxPlacement::ChildCluster { .. }) => return true,
        None => {}
    }
    if status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
        .is_some()
    {
        return true;
    }

    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let name = crate::controllers::sandbox_child::internal_lease_name(&lease.name_any());
    match internal.get(&name).await {
        // Existence selects the conservative child path. Exact durable identity
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

enum RecordedChildAccess {
    Reachable(Client),
    /// Management-cluster or child API state may recover without destruction.
    Retry(&'static str),
    /// Only a child Hyper/Service transport failure selects receipt fallback.
    TransportUnreachable,
    /// Identity, authentication, or credential ambiguity is not unreachability.
    Quarantine(&'static str),
}

/// Re-authenticate one bound child through the exact Secret checkpoint.
///
/// Management API failures are classified before a child client exists and can
/// therefore never select destroy fallback. Missing/replaced/malformed Secret
/// data and child 401/403 responses quarantine. Only an actual Hyper/Service
/// error from an exact child API probe is durable grounds for the
/// `VerifiedDestroyFallbackV1` path.
async fn recorded_child_access(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    instance: &crate::crd::SandboxObjectReference,
) -> RecordedChildAccess {
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    let Some(recorded_secret) = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_kubeconfig_secret.as_ref())
    else {
        return RecordedChildAccess::Quarantine("child_kubeconfig_provenance_missing");
    };
    let Some(recorded_digest) = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_kubeconfig_sha256.as_deref())
    else {
        return RecordedChildAccess::Quarantine("child_kubeconfig_provenance_missing");
    };
    let secret_name = crate::backend::kubeconfig_secret_name(&instance.name);
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let secret = match secrets.get(&secret_name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return RecordedChildAccess::Quarantine("child_kubeconfig_secret_missing");
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return RecordedChildAccess::Quarantine("child_kubeconfig_secret_forbidden");
        }
        Err(_) => {
            return RecordedChildAccess::Retry("child_kubeconfig_management_read_retry");
        }
    };
    let observation = match child_kubeconfig_secret_observation(&secret, &ctx.namespace, instance) {
        Ok(observation) => observation,
        Err(_) => {
            return RecordedChildAccess::Quarantine("child_kubeconfig_secret_malformed");
        }
    };
    if require_exact_child_kubeconfig_secret(recorded_secret, recorded_digest, &observation)
        .is_err()
    {
        return RecordedChildAccess::Quarantine("child_kubeconfig_secret_replaced");
    }
    let kubeconfig = match String::from_utf8(observation.kubeconfig_payload) {
        Ok(kubeconfig) => kubeconfig,
        Err(_) => {
            return RecordedChildAccess::Quarantine("child_kubeconfig_payload_invalid");
        }
    };
    let child = match crate::backend::virtual_client_from_kubeconfig(&kubeconfig).await {
        Ok(child) => child,
        Err(_) => {
            return RecordedChildAccess::Quarantine("child_kubeconfig_client_invalid");
        }
    };
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return RecordedChildAccess::Quarantine("child_parent_uid_missing");
    };
    let namespaces: Api<Namespace> = Api::all(child.clone());
    match namespaces.get(CHILD_SANDBOX_NAMESPACE).await {
        Ok(namespace)
            if child_namespace_matches_lease(&namespace, &lease.name_any(), &lease_uid) =>
        {
            RecordedChildAccess::Reachable(child)
        }
        Ok(_) => RecordedChildAccess::Quarantine("child_namespace_identity_changed"),
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            RecordedChildAccess::Quarantine("child_api_authentication_failed")
        }
        Err(kube::Error::Api(error)) if (500..=599).contains(&error.code) => {
            RecordedChildAccess::Retry("child_api_server_retry")
        }
        Err(kube::Error::HyperError(_) | kube::Error::Service(_)) => {
            RecordedChildAccess::TransportUnreachable
        }
        Err(kube::Error::Api(_)) => RecordedChildAccess::Quarantine("child_namespace_unverifiable"),
        Err(_) => RecordedChildAccess::Quarantine("child_api_response_unverifiable"),
    }
}

/// Persist the cleanup interpretation before the internal ClusterLease can be
/// released. A crash after this status write may retry the same mode; it may
/// never switch reachable cleanup into receipt fallback or vice versa.
async fn checkpoint_child_teardown_mode(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    mode: crate::crd::SandboxChildTeardownMode,
) -> Result<Action, SandboxPlacementError> {
    let mut next = lease.status.clone().unwrap_or_default();
    if let Some(current) = next.child_teardown_mode {
        if current != mode {
            return quarantine_lease(lease, ctx, "child_teardown_mode_changed").await;
        }
        return Ok(Action::await_change());
    }
    next.child_teardown_mode = Some(mode);
    if patch_lease_status_fenced(ctx, lease, &next).await? {
        info!(lease = %lease.name_any(), mode = ?mode, "checkpointed child teardown mode");
    } else {
        debug!(lease = %lease.name_any(), "child teardown mode checkpoint lost a status race");
    }
    Ok(Action::await_change())
}

#[derive(Debug, Clone, Copy)]
enum ChildTargetAbsenceProof {
    VerifiedDestroyReceipt,
    NeverBound,
}

enum ChildProofAcknowledgement {
    Receipt {
        receipt: Box<crate::crd::TeardownReceipt>,
        token: String,
        evidence: crate::crd::TeardownEvidenceReference,
    },
    NeverBound {
        attempt_id: String,
        verified_at: String,
        token: String,
    },
}

impl ChildProofAcknowledgement {
    fn annotation(&self) -> &'static str {
        match self {
            Self::Receipt { .. } => crate::crd::TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION,
            Self::NeverBound { .. } => crate::crd::UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION,
        }
    }

    fn token(&self) -> &str {
        match self {
            Self::Receipt { token, .. } | Self::NeverBound { token, .. } => token,
        }
    }

    fn absence_proof(&self) -> ChildTargetAbsenceProof {
        match self {
            Self::Receipt { .. } => ChildTargetAbsenceProof::VerifiedDestroyReceipt,
            Self::NeverBound { .. } => ChildTargetAbsenceProof::NeverBound,
        }
    }
}

/// Retire execution authority before `FootprintAbsent` is allowed to become
/// durable. Receipt-backed cleanup may mark an exact running record cancelled
/// because the whole target is gone; NeverBound requires an empty manifest and
/// rejects any contradictory bound record instead.
async fn cleanup_child_executions_after_proof(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    proof: ChildTargetAbsenceProof,
) -> Result<Option<Action>, SandboxPlacementError> {
    if !ctx.access_ledger_enabled {
        return Ok(None);
    }
    let outcome = match proof {
        ChildTargetAbsenceProof::VerifiedDestroyReceipt => {
            crate::api::sandbox_executions::cleanup_lease_executions_after_target_absence(
                &ctx.client,
                &ctx.namespace,
                &ctx.reservation_namespace,
                lease,
                &ctx.shutdown,
            )
            .await
        }
        ChildTargetAbsenceProof::NeverBound => {
            crate::api::sandbox_executions::prove_never_bound_execution_footprint_empty(
                &ctx.client,
                &ctx.namespace,
                &ctx.reservation_namespace,
                lease,
                &ctx.shutdown,
            )
            .await
        }
    };
    match outcome {
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Clean => Ok(None),
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Checkpointed => {
            Ok(Some(execution_cleanup_checkpoint_action()))
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::AwaitTargetDestruction => {
            // This function runs only after exact target-absence proof. Reaching
            // this state means the proof was not consumed and must be retried.
            Ok(Some(Action::requeue(std::time::Duration::from_secs(15))))
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Retry => {
            Ok(Some(Action::requeue(std::time::Duration::from_secs(15))))
        }
        crate::api::sandbox_executions::ExecutionCleanupOutcome::Quarantine(reason) => {
            quarantine_lease(lease, ctx, reason).await.map(Some)
        }
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
/// The internal lease is first **released, not deleted**, because deletion
/// would destroy the receipt at exactly the moment the evidence matters. Once
/// that receipt has been consumed into the outer lease's durable
/// `FootprintAbsent` checkpoint, [`finish_child_release_after_proof`] deletes
/// the exact internal lease explicitly and verifies its 404 before the outer
/// finalizer can be removed.
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

    // Older objects may have been created before their identity checkpoint. A
    // release landing in that window must recover and persist the exact UID
    // before it requests teardown; absence of a RECORD is not absence of a
    // CLUSTER.
    let recorded = match status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
    {
        Some(recorded) => recorded.clone(),
        None => match internal_api.get(&derived).await {
            Ok(unrecorded) => {
                match ensure_internal_lease_fenced(&internal_api, &unrecorded, lease).await? {
                    InternalHandleFence::Ready => {}
                    InternalHandleFence::Patched => {
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    }
                    InternalHandleFence::Foreign => {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_composition_identity_unverifiable",
                        )
                        .await;
                    }
                }
                let Some(unrecorded_uid) = unrecorded.uid().filter(|uid| !uid.is_empty()) else {
                    return quarantine_lease(lease, ctx, "child_composition_uid_missing").await;
                };
                let Some(unrecorded_generation) = unrecorded.metadata.generation else {
                    return quarantine_lease(lease, ctx, "child_composition_generation_missing")
                        .await;
                };
                warn!(
                    lease = %name,
                    cluster_lease = %derived,
                    "releasing a child composition that was allocated but never recorded"
                );
                let reference = crate::crd::SandboxObjectReference {
                    api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                    kind: "ClusterLease".into(),
                    namespace: Some(ctx.namespace.clone()),
                    name: derived.clone(),
                    uid: unrecorded_uid,
                    generation: Some(unrecorded_generation),
                };
                let unrecorded_status = unrecorded.status.clone().unwrap_or_default();
                let recorded_instance = status
                    .target
                    .as_ref()
                    .and_then(|target| target.child_cluster_instance.as_ref());
                let recorded_pool = recorded_child_pool(&status, &ctx.namespace);

                // A proof-bearing handle can be recovered without consulting
                // a live pool: its receipt names the exact pool/instance UIDs,
                // while NeverBound proves no allocation identity ever existed.
                let proof_is_exact =
                    unrecorded_status
                        .teardown_receipt
                        .as_ref()
                        .is_some_and(|receipt| {
                            recorded_pool.is_some_and(|pool| {
                                validated_child_receipt_token(
                                    &unrecorded,
                                    receipt,
                                    &reference,
                                    recorded_instance,
                                    pool,
                                )
                                .is_some()
                            })
                        })
                        || unbound_child_release_is_proven(&unrecorded, recorded_instance);
                if unrecorded_status.teardown_receipt.is_some() && !proof_is_exact {
                    return quarantine_lease(lease, ctx, "child_receipt_does_not_match").await;
                }

                let mut next = status.clone();
                if unrecorded_status.binding.is_some() && !proof_is_exact {
                    // A bound pre-checkpoint handle is not safe to describe from
                    // its display name. Recover the reciprocal lease, instance,
                    // and pool tuple first, then checkpoint all identities in
                    // one outer-status write.
                    let resolution = {
                        let client = ctx.client.clone();
                        let namespace = ctx.namespace.clone();
                        let lease_name = reference.name.clone();
                        let lease_uid = reference.uid.clone();
                        // Resolution is read-only. Run it as its own task so
                        // its three typed Kubernetes responses do not deepen
                        // this already broad teardown poll frame; cancellation
                        // can at worst leave harmless GETs in flight.
                        tokio::spawn(async move {
                            crate::lease_binding::resolve_lease_binding(
                                &client,
                                &namespace,
                                &lease_name,
                                &lease_uid,
                                crate::lease_binding::BindingResolveMode::Lifecycle,
                            )
                            .await
                        })
                        .await
                    };
                    let resolved = match resolution {
                        Ok(Ok(resolved)) => resolved,
                        Ok(Err(error)) => {
                            warn!(lease = %name, reason = error.reason_code(), "unrecorded child binding is not reciprocally valid");
                            return quarantine_lease(
                                lease,
                                ctx,
                                "child_binding_identity_unverifiable",
                            )
                            .await;
                        }
                        Err(error) => {
                            warn!(lease = %name, error = %error, "child binding resolver task did not complete");
                            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                        }
                    };
                    if resolved.lease.metadata.generation != reference.generation {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_composition_generation_changed",
                        )
                        .await;
                    }
                    let placement = crate::sandbox::record_placement_once(
                        status.placement.as_ref(),
                        crate::crd::ResolvedSandboxPlacement::ChildCluster {
                            cluster_pool: crate::crd::SandboxObjectReference {
                                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                                kind: "ClusterPool".into(),
                                namespace: Some(ctx.namespace.clone()),
                                name: resolved.pool.name_any(),
                                uid: resolved.pool.uid().unwrap_or_default(),
                                generation: resolved.pool.metadata.generation,
                            },
                        },
                        &ctx.namespace,
                    )
                    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
                    let mut proposed =
                        status
                            .target
                            .clone()
                            .unwrap_or(crate::crd::SandboxTargetProvenance {
                                namespace: CHILD_SANDBOX_NAMESPACE.to_string(),
                                child_cluster_lease: None,
                                child_cluster_instance: None,
                                child_cluster_kubeconfig_secret: None,
                                child_cluster_kubeconfig_sha256: None,
                                sandbox_template: None,
                                sandbox_warm_pool: None,
                                sandbox_claim: None,
                                sandbox: None,
                                pod: None,
                                service: None,
                            });
                    proposed.namespace = CHILD_SANDBOX_NAMESPACE.to_string();
                    proposed.child_cluster_lease = Some(reference);
                    proposed.child_cluster_instance = Some(crate::crd::SandboxObjectReference {
                        api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                        kind: "ClusterInstance".into(),
                        namespace: Some(ctx.namespace.clone()),
                        name: resolved.binding.instance.name.clone(),
                        uid: resolved.binding.instance.uid.clone(),
                        generation: Some(resolved.binding.instance.observed_generation),
                    });
                    next.placement = Some(placement.clone());
                    next.target = Some(
                        crate::sandbox::merge_target_provenance(
                            status.target.as_ref(),
                            proposed,
                            &placement,
                            &ctx.namespace,
                        )
                        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?,
                    );
                } else {
                    if !proof_is_exact
                        && (unrecorded_status.binding.is_some()
                            || unrecorded_status.cluster_name.is_some()
                            || !matches!(
                                unrecorded_status.phase,
                                crate::crd::LeasePhase::Pending
                                    | crate::crd::LeasePhase::Released
                                    | crate::crd::LeasePhase::Expired
                            ))
                    {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_precheckpoint_state_unverifiable",
                        )
                        .await;
                    }
                    // Pending and exact proof recovery persist only identities
                    // actually observed. In particular, do not invent a pool or
                    // instance for a handle that NeverBound will prove absent.
                    let target =
                        next.target
                            .get_or_insert_with(|| crate::crd::SandboxTargetProvenance {
                                namespace: CHILD_SANDBOX_NAMESPACE.to_string(),
                                child_cluster_lease: None,
                                child_cluster_instance: None,
                                child_cluster_kubeconfig_secret: None,
                                child_cluster_kubeconfig_sha256: None,
                                sandbox_template: None,
                                sandbox_warm_pool: None,
                                sandbox_claim: None,
                                sandbox: None,
                                pod: None,
                                service: None,
                            });
                    if target.namespace != CHILD_SANDBOX_NAMESPACE {
                        return quarantine_lease(lease, ctx, "child_target_namespace_changed")
                            .await;
                    }
                    target.child_cluster_lease = Some(reference);
                }
                if patch_lease_status_fenced(ctx, lease, &next).await? {
                    info!(lease = %name, "recovered exact child provenance before teardown");
                } else {
                    debug!(lease = %name, "child lease recovery checkpoint lost a status race");
                }
                return Ok(Action::await_change());
            }
            // An explicit ChildCluster placement proves composition was
            // selected. Losing both its durable handle reference and the
            // deterministic object is provenance loss, not proof that no
            // cluster was allocated; keep the slot withheld.
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return quarantine_lease(lease, ctx, "child_composition_provenance_missing").await;
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
    if recorded.api_version != "kobe.kunobi.ninja/v1alpha1"
        || recorded.kind != "ClusterLease"
        || recorded.namespace.as_deref() != Some(ctx.namespace.as_str())
        || recorded.name != derived
        || recorded.uid.is_empty()
        || recorded.generation.is_none()
    {
        return quarantine_lease(lease, ctx, "child_composition_provenance_invalid").await;
    }
    let recorded_instance = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_instance.as_ref());

    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match internal.get(&recorded.name).await {
        Ok(current) if current.uid().as_deref() == Some(recorded.uid.as_str()) => {
            match ensure_internal_lease_fenced(&internal, &current, lease).await? {
                InternalHandleFence::Ready => {}
                InternalHandleFence::Patched => {
                    info!(lease = %name, "fenced exact child handle before release");
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
                InternalHandleFence::Foreign => {
                    return quarantine_lease(lease, ctx, "child_composition_identity_changed")
                        .await;
                }
            }
            let recorded_pool = recorded_child_pool(&status, &ctx.namespace);
            let child_status = current.status.clone().unwrap_or_default();

            // Receipt status is only a mirror. Before consuming it, bind it to
            // the immutable evidence object created by the isolated authority.
            if let Some(receipt) = child_status.teardown_receipt.as_ref() {
                let Some(recorded_pool) = recorded_pool else {
                    return quarantine_lease(lease, ctx, "child_pool_provenance_invalid").await;
                };
                // Keep the immutable-evidence lookup off this already broad
                // child teardown future. The controller is spawned on normal
                // Tokio worker stacks, so adding proof checkpoints must not
                // make stack size part of the lifecycle contract.
                let evidence = match Box::pin(authoritative_child_receipt_matches(
                    &ctx.client,
                    &ctx.namespace,
                    &current,
                    receipt,
                ))
                .await
                {
                    Ok(Some(evidence)) => evidence,
                    Ok(None) => {
                        return quarantine_lease(lease, ctx, "child_receipt_authority_unverified")
                            .await;
                    }
                    Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                        return quarantine_lease(lease, ctx, "child_receipt_authority_unavailable")
                            .await;
                    }
                    Err(error) => {
                        warn!(lease = %name, error = %error, "could not read authoritative teardown evidence");
                        return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                    }
                };
                let Some(token) = validated_child_receipt_token(
                    &current,
                    receipt,
                    recorded,
                    recorded_instance,
                    recorded_pool,
                ) else {
                    return quarantine_lease(lease, ctx, "child_receipt_does_not_match").await;
                };
                if status.child_teardown_receipt_acknowledgement.as_deref() != Some(token.as_str())
                    || status.child_teardown_evidence.as_ref() != Some(&evidence)
                {
                    if status.child_teardown_receipt_acknowledgement.is_some()
                        || status.child_teardown_evidence.is_some()
                        || status.child_unbound_release_proof.is_some()
                    {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_receipt_acknowledgement_changed",
                        )
                        .await;
                    }
                    if let Some(action) = cleanup_child_executions_after_proof(
                        lease,
                        ctx,
                        ChildTargetAbsenceProof::VerifiedDestroyReceipt,
                    )
                    .await?
                    {
                        return Ok(action);
                    }
                    if !Box::pin(checkpoint_child_receipt_handoff(
                        lease, ctx, &token, &evidence,
                    ))
                    .await?
                    {
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    }
                    info!(lease = %name, "child teardown receipt, evidence, and footprint absence checkpointed");
                    return Ok(Action::await_change());
                }
                if crate::receipt_authority::is_separate()
                    && !child_receipt_authority_acknowledged(
                        lease, &current, receipt, &token, &evidence,
                    )
                {
                    debug!(lease = %name, "waiting for receipt authority acknowledgement");
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
                return Ok(Action::await_change());
            }

            // #80 could not prove the cluster's own teardown. A complete
            // receipt is deliberately checked first: backend retry may have
            // repaired evidence while the handle still carries its earlier
            // Quarantined phase.
            if child_status.phase == crate::crd::LeasePhase::Quarantined {
                return quarantine_lease(lease, ctx, "child_teardown_quarantined").await;
            }

            // A terminal handle that never acquired either binding identity is
            // itself durable NeverBound proof. The ClusterLease controller
            // retains it until the outer FootprintAbsent checkpoint is ACKed.
            if child_status.binding.is_none() {
                if let Some(proof) =
                    validated_child_unbound_release_proof(&current, recorded_instance)
                {
                    if status.child_unbound_release_proof.as_ref() != Some(&proof) {
                        if status.child_unbound_release_proof.is_some()
                            || status.child_teardown_receipt_acknowledgement.is_some()
                            || status.child_teardown_evidence.is_some()
                        {
                            return quarantine_lease(
                                lease,
                                ctx,
                                "child_unbound_proof_checkpoint_changed",
                            )
                            .await;
                        }
                        let mut next = status.clone();
                        next.child_unbound_release_proof = Some(proof.clone());
                        if !patch_lease_status_fenced(ctx, lease, &next).await? {
                            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                        }
                        info!(lease = %name, "child NeverBound proof checkpointed");
                        return Ok(Action::await_change());
                    }
                    if crate::receipt_authority::is_separate()
                        && !child_never_bound_authority_acknowledged(lease, &current, &proof)
                    {
                        debug!(lease = %name, "waiting for NeverBound authority acknowledgement");
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    }
                    if let Some(action) = cleanup_child_executions_after_proof(
                        lease,
                        ctx,
                        ChildTargetAbsenceProof::NeverBound,
                    )
                    .await?
                    {
                        return Ok(action);
                    }
                    info!(lease = %name, "child allocation absence verified as NeverBound");
                    return finish_release(lease, ctx, reason).await;
                }
                if child_status.cluster_name.is_some() || recorded_instance.is_some() {
                    return quarantine_lease(lease, ctx, "child_binding_identity_unverifiable")
                        .await;
                }
                if matches!(
                    child_status.phase,
                    crate::crd::LeasePhase::Released | crate::crd::LeasePhase::Expired
                ) {
                    debug!(lease = %name, "waiting for durable NeverBound proof");
                    return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                }
                request_child_release(&internal, &current).await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }

            Box::pin(release_bound_child_composition(
                lease, ctx, &internal, &current, recorded,
            ))
            .await
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

/// Validate and prepare an actively bound child allocation for release.
///
/// This state machine is kept separate from receipt/NeverBound consumption so
/// each controller poll has a bounded stack frame. It still preserves the
/// ordering invariant: reciprocal identity, child access cleanup, and the
/// teardown-mode checkpoint all precede the release status mutation.
async fn release_bound_child_composition(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    internal: &Api<crate::crd::ClusterLease>,
    current: &crate::crd::ClusterLease,
    recorded: &crate::crd::SandboxObjectReference,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();
    let child_status = current.status.clone().unwrap_or_default();
    let recorded_instance = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_instance.as_ref());

    if !crate::controllers::sandbox_child::internal_lease_has_secret_uid_protocol(current) {
        return quarantine_lease(lease, ctx, "child_kubeconfig_protocol_missing").await;
    }

    let Some(recorded_pool) = recorded_child_pool(&status, &ctx.namespace) else {
        return quarantine_lease(lease, ctx, "child_pool_provenance_invalid").await;
    };

    // A durable receipt/NeverBound proof is self-contained. The live pool is
    // required only while Kobe is about to initiate teardown of an actively
    // bound allocation.
    let cluster_pools: Api<crate::crd::ClusterPool> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let live_pool = match cluster_pools.get(&recorded_pool.name).await {
        Ok(pool) => pool,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return quarantine_lease(lease, ctx, "child_pool_provenance_unavailable").await;
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return quarantine_lease(lease, ctx, "child_pool_provenance_unverifiable").await;
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "could not validate recorded child pool");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }
    };
    if !live_child_pool_matches_recorded(&live_pool, recorded_pool) {
        return quarantine_lease(lease, ctx, "child_pool_identity_changed").await;
    }

    // Resolve the reciprocal live lease/instance/pool tuple before release,
    // even when no Pod credential exists.
    let resolution = {
        let client = ctx.client.clone();
        let namespace = ctx.namespace.clone();
        let lease_name = recorded.name.clone();
        let lease_uid = recorded.uid.clone();
        // This task performs GET-only reciprocal resolution. Separating its
        // typed response frame bounds the controller worker stack without
        // allowing a detached task to mutate lifecycle state.
        tokio::spawn(async move {
            crate::lease_binding::resolve_lease_binding(
                &client,
                &namespace,
                &lease_name,
                &lease_uid,
                crate::lease_binding::BindingResolveMode::Lifecycle,
            )
            .await
        })
        .await
    };
    let resolved = match resolution {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(error)) => {
            warn!(lease = %name, reason = error.reason_code(), "child reciprocal binding is not valid for release");
            return quarantine_lease(lease, ctx, "child_binding_identity_unverifiable").await;
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "child binding resolver task did not complete");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }
    };
    if !resolved_child_binding_matches_recorded(
        &resolved,
        &status,
        &ctx.namespace,
        recorded_instance.is_some(),
    ) {
        return quarantine_lease(lease, ctx, "child_binding_provenance_changed").await;
    }

    // Binding may win after the handle checkpoint. Persist the exact validated
    // instance before release so the eventual receipt has a durable UID to
    // match.
    if recorded_instance.is_none() {
        let mut next = status.clone();
        let Some(target) = next.target.as_mut() else {
            return quarantine_lease(lease, ctx, "child_target_provenance_missing").await;
        };
        if target.namespace != CHILD_SANDBOX_NAMESPACE {
            return quarantine_lease(lease, ctx, "child_target_namespace_changed").await;
        }
        target.child_cluster_instance = Some(crate::crd::SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterInstance".into(),
            namespace: Some(ctx.namespace.clone()),
            name: resolved.binding.instance.name.clone(),
            uid: resolved.binding.instance.uid.clone(),
            generation: Some(resolved.binding.instance.observed_generation),
        });
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            info!(lease = %name, "recovered validated child instance provenance before teardown");
        } else {
            debug!(lease = %name, "child instance recovery checkpoint lost a status race");
        }
        return Ok(Action::await_change());
    }

    let internal_release_started = matches!(
        child_status.phase,
        crate::crd::LeasePhase::Released
            | crate::crd::LeasePhase::Expired
            | crate::crd::LeasePhase::Recycling
    );
    if internal_release_started && status.child_teardown_mode.is_none() {
        // Never reinterpret missing credentials after destruction started.
        return quarantine_lease(lease, ctx, "child_teardown_mode_missing").await;
    }

    if status.child_teardown_mode.is_none() {
        let Some(expected_instance) = recorded_instance else {
            return quarantine_lease(lease, ctx, "child_credential_target_unverifiable").await;
        };
        let target = match status.target.as_ref() {
            Some(target)
                if target.namespace == CHILD_SANDBOX_NAMESPACE
                    && resolved.binding.instance.name == expected_instance.name
                    && resolved.binding.instance.uid == expected_instance.uid =>
            {
                target
            }
            _ => {
                return quarantine_lease(lease, ctx, "child_credential_target_unverifiable").await;
            }
        };
        match recorded_child_access(lease, ctx, expected_instance).await {
            RecordedChildAccess::Reachable(child_client) => {
                // Inspect durable runner groups before scoped credentials.
                // Proven-absent groups retire here; a lost supervisor selects
                // receipt-backed cluster destruction while retaining its
                // record and capacity.
                if ctx.access_ledger_enabled {
                    match execution_cleanup_advance(
                        crate::api::sandbox_executions::cleanup_lease_executions(
                            &ctx.client,
                            &ctx.namespace,
                            &ctx.reservation_namespace,
                            lease,
                            &child_client,
                            &ctx.shutdown,
                        )
                        .await,
                    ) {
                        ExecutionCleanupAdvance::Continue => {}
                        ExecutionCleanupAdvance::Checkpointed => {
                            return Ok(execution_cleanup_checkpoint_action());
                        }
                        ExecutionCleanupAdvance::DestroyTarget => {
                            // Preserve Unknown and its capacity, but do not
                            // deadlock before cluster destruction. The exact
                            // destroy receipt will retire both.
                            return checkpoint_child_teardown_mode(
                                lease,
                                ctx,
                                crate::crd::SandboxChildTeardownMode::VerifiedDestroyFallbackV1,
                            )
                            .await;
                        }
                        ExecutionCleanupAdvance::Retry => {
                            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                        }
                        ExecutionCleanupAdvance::Quarantine(reason) => {
                            return quarantine_lease(lease, ctx, reason).await;
                        }
                    }
                }

                if let Some(pod) = target.pod.as_ref() {
                    let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_credential_target_unverifiable",
                        )
                        .await;
                    };
                    if pod.name.is_empty() || pod.uid.is_empty() {
                        return quarantine_lease(
                            lease,
                            ctx,
                            "child_credential_target_unverifiable",
                        )
                        .await;
                    }
                    match crate::api::sandbox_credentials::cleanup_scoped_identities(
                        &child_client,
                        &target.namespace,
                        &lease_uid,
                        &pod.name,
                        &pod.uid,
                    )
                    .await
                    {
                        crate::api::sandbox_credentials::CredentialCleanupOutcome::Clean => {}
                        crate::api::sandbox_credentials::CredentialCleanupOutcome::Retry => {
                            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                        }
                        crate::api::sandbox_credentials::CredentialCleanupOutcome::Quarantine => {
                            return quarantine_lease(
                                lease,
                                ctx,
                                "child_credential_cleanup_unverifiable",
                            )
                            .await;
                        }
                    }
                }
                return checkpoint_child_teardown_mode(
                    lease,
                    ctx,
                    crate::crd::SandboxChildTeardownMode::ReachableCleanupV1,
                )
                .await;
            }
            RecordedChildAccess::TransportUnreachable => {
                return checkpoint_child_teardown_mode(
                    lease,
                    ctx,
                    crate::crd::SandboxChildTeardownMode::VerifiedDestroyFallbackV1,
                )
                .await;
            }
            RecordedChildAccess::Retry(reason) => {
                debug!(lease = %name, reason, "child access classification will retry");
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
            RecordedChildAccess::Quarantine(reason) => {
                return quarantine_lease(lease, ctx, reason).await;
            }
        }
    }

    // The exact cleanup interpretation is durable before this mutation.
    if !internal_release_started {
        request_child_release(internal, current).await?;
    }
    debug!(lease = %name, "waiting for the child teardown receipt");
    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

fn child_receipt_authority_acknowledged(
    consumer: &SandboxLease,
    child: &crate::crd::ClusterLease,
    receipt: &crate::crd::TeardownReceipt,
    token: &str,
    evidence: &crate::crd::TeardownEvidenceReference,
) -> bool {
    let Some(consumer_uid) = consumer.uid() else {
        return false;
    };
    child
        .status
        .as_ref()
        .and_then(|status| status.teardown_acknowledgement.as_ref())
        .is_some_and(|ack| {
            ack.attempt_id == receipt.attempt_id
                && ack.consumer.api_version == "kobe.kunobi.ninja/v1alpha1"
                && ack.consumer.kind == "SandboxLease"
                && ack.consumer.namespace == consumer.namespace()
                && ack.consumer.name == consumer.name_any()
                && ack.consumer.uid == consumer_uid
                && ack.proof.kind == crate::crd::TeardownAcknowledgedProofKind::Receipt
                && ack.proof.receipt_token.as_deref() == Some(token)
                && ack.proof.evidence.as_ref() == Some(evidence)
        })
}

fn validated_child_unbound_release_proof(
    child: &crate::crd::ClusterLease,
    recorded_instance: Option<&crate::crd::SandboxObjectReference>,
) -> Option<crate::crd::ChildUnboundReleaseProof> {
    if !unbound_child_release_is_proven(child, recorded_instance) {
        return None;
    }
    let status = child.status.as_ref()?;
    Some(crate::crd::ChildUnboundReleaseProof {
        attempt_id: status.teardown_attempt_id.clone()?,
        verified_at: status.unbound_release_verified_at.clone()?,
    })
}

fn child_never_bound_authority_acknowledged(
    consumer: &SandboxLease,
    child: &crate::crd::ClusterLease,
    proof: &crate::crd::ChildUnboundReleaseProof,
) -> bool {
    let Some(consumer_uid) = consumer.uid() else {
        return false;
    };
    child
        .status
        .as_ref()
        .and_then(|status| status.teardown_acknowledgement.as_ref())
        .is_some_and(|ack| {
            ack.attempt_id == proof.attempt_id
                && ack.consumer.api_version == "kobe.kunobi.ninja/v1alpha1"
                && ack.consumer.kind == "SandboxLease"
                && ack.consumer.namespace == consumer.namespace()
                && ack.consumer.name == consumer.name_any()
                && ack.consumer.uid == consumer_uid
                && ack.proof.kind == crate::crd::TeardownAcknowledgedProofKind::NeverBound
                && ack.proof.unbound_release_verified_at.as_deref()
                    == Some(proof.verified_at.as_str())
        })
}

/// Require the immutable receipt object written by the isolated teardown
/// authority. Exact CRD UID, generation and resourceVersion are all part of
/// the handoff; mutable ClusterLease status is only a mirror.
async fn authoritative_child_receipt_matches(
    client: &Client,
    namespace: &str,
    lease: &crate::crd::ClusterLease,
    receipt: &crate::crd::TeardownReceipt,
) -> Result<Option<crate::crd::TeardownEvidenceReference>, kube::Error> {
    let Some(status) = lease.status.as_ref() else {
        return Ok(None);
    };
    let Some(reference) = status.teardown_evidence.as_ref() else {
        return Ok(None);
    };
    let Some(lease_uid) = lease.uid().filter(|uid| !uid.trim().is_empty()) else {
        return Ok(None);
    };
    let expected_name =
        crate::crd::verified_teardown_evidence_name(&lease_uid, &receipt.attempt_id);
    if reference.name != expected_name || reference.generation < 1 {
        return Ok(None);
    }
    let evidence_api: Api<crate::crd::VerifiedTeardownEvidence> =
        Api::namespaced(client.clone(), namespace);
    let evidence = evidence_api.get(&reference.name).await?;
    let expected_labels =
        crate::crd::verified_teardown_evidence_labels(&lease_uid, &receipt.attempt_id);
    let labels_match = expected_labels.iter().all(|(key, value)| {
        evidence
            .metadata
            .labels
            .as_ref()
            .and_then(|live| live.get(key))
            == Some(value)
    });
    let identity_matches = evidence.uid().as_deref() == Some(reference.uid.as_str())
        && evidence.metadata.generation == Some(reference.generation)
        && evidence.resource_version().as_deref() == Some(reference.resource_version.as_str())
        && evidence.namespace().as_deref() == Some(namespace)
        && evidence.metadata.deletion_timestamp.is_none()
        && evidence
            .metadata
            .owner_references
            .as_ref()
            .is_none_or(|owners| owners.is_empty())
        && labels_match;
    let content_matches = evidence.spec.lease.name == lease.name_any()
        && evidence.spec.lease.uid.as_deref() == Some(lease_uid.as_str())
        && evidence.spec.attempt_id == receipt.attempt_id
        && evidence.spec.receipt == *receipt;
    Ok((identity_matches && content_matches).then(|| reference.clone()))
}

/// ACK and retire the receipt-bearing internal lease after evidence is durable.
///
/// The outer `FootprintAbsent=True` checkpoint is the linearization point: a
/// crash before it leaves the proof available for recovery. ACK and delete are
/// UID/resourceVersion-fenced, but the retention finalizer deliberately keeps
/// the object terminating—and its deterministic name occupied—until the outer
/// lease itself has outlived retention. That is the barrier against a stale
/// pre-fence POST recreating an allocation after teardown.
async fn finish_child_release_after_proof(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: ReleaseReason,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();
    let status = lease.status.clone().unwrap_or_default();
    debug_assert!(footprint_absence_proven(&status));

    let derived = crate::controllers::sandbox_child::internal_lease_name(&name);
    let internal: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let Some(recorded) = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
    else {
        return match internal.get(&derived).await {
            Err(kube::Error::Api(error)) if error.code == 404 => record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleProvenanceMissing",
                "Workload absence is proven, but the child handle identity was never checkpointed",
                std::time::Duration::from_secs(300),
            )
            .await,
            Ok(_) => record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleProvenanceMissing",
                "Workload absence is proven, but a child handle exists without exact provenance",
                std::time::Duration::from_secs(300),
            )
            .await,
            Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
                record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildHandleAbsenceUnverifiable",
                    "Workload absence is proven, but child handle absence cannot be verified",
                    std::time::Duration::from_secs(300),
                )
                .await
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not check unrecorded child handle");
                record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildHandleReadRetry",
                    "Workload absence is proven, but the child handle read must be retried",
                    std::time::Duration::from_secs(15),
                )
                .await
            }
        };
    };

    if recorded.api_version != "kobe.kunobi.ninja/v1alpha1"
        || recorded.kind != "ClusterLease"
        || recorded.namespace.as_deref() != Some(ctx.namespace.as_str())
        || recorded.name != derived
        || recorded.uid.is_empty()
        || recorded.generation.is_none()
    {
        return record_post_proof_cleanup_failure(
            lease,
            ctx,
            "ChildHandleProvenanceInvalid",
            "Workload absence is proven, but recorded child handle provenance is invalid",
            std::time::Duration::from_secs(300),
        )
        .await;
    }

    let recorded_pool = recorded_child_pool(&status, &ctx.namespace);
    let mut current = match internal.get(&recorded.name).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleMissingAfterProof",
                "Workload absence is proven, but the retained child-handle name is no longer occupied",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleAbsenceUnverifiable",
                "Workload absence is proven, but child handle absence cannot be verified",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "could not read verified child handle");
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleReadRetry",
                "Workload absence is proven, but the child handle read must be retried",
                std::time::Duration::from_secs(15),
            )
            .await;
        }
    };
    // Identity is the UID. metadata.generation advances when we ACK via
    // annotations, so requiring the checkpointed generation here strands
    // every verified child teardown as Releasing and fills the admission
    // quota.
    if current.uid().as_deref() != Some(recorded.uid.as_str()) {
        return record_post_proof_cleanup_failure(
            lease,
            ctx,
            "ChildHandleIdentityChanged",
            "Workload absence is proven, but the child handle no longer matches recorded identity",
            std::time::Duration::from_secs(300),
        )
        .await;
    }
    let recorded_instance = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_instance.as_ref());
    let proof = if let Some(receipt) = current
        .status
        .as_ref()
        .and_then(|status| status.teardown_receipt.as_ref())
    {
        let Some(recorded_pool) = recorded_pool else {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildPoolProvenanceMissing",
                "Workload absence is proven, but exact child pool provenance is missing",
                std::time::Duration::from_secs(300),
            )
            .await;
        };
        let Some(token) = validated_child_receipt_token(
            &current,
            receipt,
            recorded,
            recorded_instance,
            recorded_pool,
        ) else {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildReceiptChangedAfterCheckpoint",
                "Workload absence is proven, but the exact child receipt no longer validates",
                std::time::Duration::from_secs(300),
            )
            .await;
        };
        let evidence = match authoritative_child_receipt_matches(
            &ctx.client,
            &ctx.namespace,
            &current,
            receipt,
        )
        .await
        {
            Ok(Some(evidence)) => evidence,
            Ok(None) => {
                return record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildReceiptEvidenceChangedAfterCheckpoint",
                    "Workload absence is proven, but immutable teardown evidence no longer validates",
                    std::time::Duration::from_secs(300),
                )
                .await;
            }
            Err(error) => {
                warn!(lease = %name, error = %error, "could not re-read immutable child teardown evidence");
                return record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildReceiptEvidenceReadRetry",
                    "Workload absence is proven, but immutable teardown evidence must be re-read",
                    std::time::Duration::from_secs(15),
                )
                .await;
            }
        };
        if status.child_teardown_receipt_acknowledgement.as_deref() != Some(token.as_str())
            || status.child_teardown_evidence.as_ref() != Some(&evidence)
        {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildReceiptCheckpointChanged",
                "Workload absence is proven, but its exact receipt checkpoint changed",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        if crate::receipt_authority::is_separate()
            && !child_receipt_authority_acknowledged(lease, &current, receipt, &token, &evidence)
        {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildReceiptAuthorityAckMissing",
                "Workload absence is proven, but the isolated receipt acknowledgement is missing",
                std::time::Duration::from_secs(15),
            )
            .await;
        }
        ChildProofAcknowledgement::Receipt {
            receipt: Box::new(receipt.clone()),
            token,
            evidence,
        }
    } else if let Some(checkpoint) =
        validated_child_unbound_release_proof(&current, recorded_instance)
    {
        if status.child_unbound_release_proof.as_ref() != Some(&checkpoint)
            || (crate::receipt_authority::is_separate()
                && !child_never_bound_authority_acknowledged(lease, &current, &checkpoint))
        {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildNeverBoundCheckpointChanged",
                "Workload absence is proven, but its attempt-bound NeverBound acknowledgement changed",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        let child_status = current
            .status
            .as_ref()
            .expect("verified NeverBound proof has status");
        ChildProofAcknowledgement::NeverBound {
            attempt_id: child_status
                .teardown_attempt_id
                .clone()
                .expect("verified NeverBound proof has an attempt"),
            verified_at: child_status
                .unbound_release_verified_at
                .clone()
                .expect("verified NeverBound proof has a timestamp"),
            token: crate::controllers::lease::unbound_release_acknowledgement_token(child_status)
                .expect("verified NeverBound proof has an attempt-bound token"),
        }
    } else {
        return record_post_proof_cleanup_failure(
            lease,
            ctx,
            "ChildProofChangedAfterCheckpoint",
            "Workload absence is proven, but the exact child teardown proof is no longer present",
            std::time::Duration::from_secs(300),
        )
        .await;
    };

    // Older controllers could checkpoint FootprintAbsent before #82 execution
    // retirement was integrated. Revalidate and finish that durable cleanup
    // now, while the exact receipt/NeverBound handle is still retained and
    // before ACK, handle deletion, reservation release, or terminal status.
    if ctx.access_ledger_enabled {
        let outcome = match proof.absence_proof() {
            ChildTargetAbsenceProof::VerifiedDestroyReceipt => {
                crate::api::sandbox_executions::cleanup_lease_executions_after_target_absence(
                    &ctx.client,
                    &ctx.namespace,
                    &ctx.reservation_namespace,
                    lease,
                    &ctx.shutdown,
                )
                .await
            }
            ChildTargetAbsenceProof::NeverBound => {
                crate::api::sandbox_executions::prove_never_bound_execution_footprint_empty(
                    &ctx.client,
                    &ctx.namespace,
                    &ctx.reservation_namespace,
                    lease,
                    &ctx.shutdown,
                )
                .await
            }
        };
        match outcome {
            crate::api::sandbox_executions::ExecutionCleanupOutcome::Clean => {}
            crate::api::sandbox_executions::ExecutionCleanupOutcome::Checkpointed => {
                return Ok(execution_cleanup_checkpoint_action());
            }
            crate::api::sandbox_executions::ExecutionCleanupOutcome::Retry
            | crate::api::sandbox_executions::ExecutionCleanupOutcome::AwaitTargetDestruction => {
                return record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildExecutionCleanupRetry",
                    "Target absence is proven, but exact child execution retirement must be retried",
                    std::time::Duration::from_secs(15),
                )
                .await;
            }
            crate::api::sandbox_executions::ExecutionCleanupOutcome::Quarantine(_) => {
                return record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildExecutionCleanupInvalid",
                    "Target absence is proven, but child execution provenance is contradictory",
                    std::time::Duration::from_secs(300),
                )
                .await;
            }
        }
    }

    if let ChildProofAcknowledgement::Receipt { token, .. } = &proof {
        match status.child_teardown_receipt_acknowledgement.as_deref() {
            Some(checkpoint) if checkpoint == token => {}
            Some(_) => {
                return record_post_proof_cleanup_failure(
                    lease,
                    ctx,
                    "ChildReceiptCheckpointChanged",
                    "Workload absence is proven, but its receipt checkpoint changed",
                    std::time::Duration::from_secs(300),
                )
                .await;
            }
            None => return checkpoint_child_receipt_absence(lease, ctx, token).await,
        }
    }

    let ack_is_exact = |handle: &crate::crd::ClusterLease| {
        if crate::receipt_authority::is_separate() {
            return match &proof {
                ChildProofAcknowledgement::Receipt {
                    receipt,
                    token,
                    evidence,
                } => child_receipt_authority_acknowledged(lease, handle, receipt, token, evidence),
                ChildProofAcknowledgement::NeverBound {
                    attempt_id,
                    verified_at,
                    ..
                } => child_never_bound_authority_acknowledged(
                    lease,
                    handle,
                    &crate::crd::ChildUnboundReleaseProof {
                        attempt_id: attempt_id.clone(),
                        verified_at: verified_at.clone(),
                    },
                ),
            };
        }
        handle
            .annotations()
            .get(proof.annotation())
            .is_some_and(|ack| ack == proof.token())
    };
    let stale_rejection_is_exact = |handle: &crate::crd::ClusterLease| {
        lease.uid().is_some_and(|outer_uid| {
            handle
                .annotations()
                .get(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION)
                == Some(&outer_uid)
        })
    };

    if current.metadata.deletion_timestamp.is_some() {
        if !internal_handle_retention_fence_matches(&current, lease, chrono::Utc::now(), true) {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleTombstoneInvalid",
                "Workload absence is proven, but the terminating child-handle tombstone is invalid",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        // The receipt finalizer keeps a directly-deleted handle patchable. ACK
        // it here after exact proof revalidation; the producer may remove that
        // finalizer only after observing this token. A stale-rejected Pending
        // handle already carries the equivalent exact outer-UID fence.
        if !ack_is_exact(&current)
            && !stale_rejection_is_exact(&current)
            && !crate::receipt_authority::is_separate()
        {
            let Some(_) = acknowledge_child_proof(&internal, &current, &proof).await? else {
                return Ok(Action::requeue(std::time::Duration::from_secs(5)));
            };
            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
        }
        return finish_release(lease, ctx, reason).await;
    }

    match ensure_internal_lease_fenced(&internal, &current, lease).await {
        Ok(InternalHandleFence::Ready) => {}
        Ok(InternalHandleFence::Patched) => {
            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
        }
        Ok(InternalHandleFence::Foreign) => {
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleFenceInvalid",
                "Workload absence is proven, but child-handle retention metadata is unsafe",
                std::time::Duration::from_secs(300),
            )
            .await;
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "could not fence child handle after proof");
            return record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleFenceRetry",
                "Workload absence is proven, but child-handle retention fencing must be retried",
                std::time::Duration::from_secs(15),
            )
            .await;
        }
    }

    if !ack_is_exact(&current) && !crate::receipt_authority::is_separate() {
        let Some(updated) = acknowledge_child_proof(&internal, &current, &proof).await? else {
            debug!(lease = %name, "child proof ACK lost an object race");
            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
        };
        current = updated;
    }

    let Some(resource_version) = current.resource_version() else {
        return record_post_proof_cleanup_failure(
            lease,
            ctx,
            "ChildHandleResourceVersionMissing",
            "Workload absence is proven, but the ACKed child handle has no delete fence",
            std::time::Duration::from_secs(300),
        )
        .await;
    };
    let delete = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        preconditions: Some(Preconditions {
            uid: Some(recorded.uid.clone()),
            resource_version: Some(resource_version),
        }),
        ..Default::default()
    };
    match internal.delete(&recorded.name, &delete).await {
        Ok(_) => {
            info!(lease = %name, "child proof ACKed; retained handle is terminating");
            Ok(Action::requeue(std::time::Duration::from_secs(5)))
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleMissingAfterAck",
                "Workload absence is proven, but the ACKed handle vanished before retention",
                std::time::Duration::from_secs(300),
            )
            .await
        }
        Err(kube::Error::Api(error)) if error.code == 409 => {
            Ok(Action::requeue(std::time::Duration::from_secs(5)))
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleDeleteForbidden",
                "Workload absence is proven, but the exact child handle cannot be deleted",
                std::time::Duration::from_secs(300),
            )
            .await
        }
        Err(error) => {
            warn!(lease = %name, error = %error, "could not delete verified child handle");
            record_post_proof_cleanup_failure(
                lease,
                ctx,
                "ChildHandleDeleteRetry",
                "Workload absence is proven, but the exact child handle delete must be retried",
                std::time::Duration::from_secs(15),
            )
            .await
        }
    }
}

/// Validate a child producer's receipt against controller-owned bind-time
/// scope and return its exact acknowledgement token.
///
/// No expected field is reconstructed from the receipt. The reciprocal
/// binding supplies cleanup mode, creation manifest, connect-token UID and
/// durable attempt; the outer Sandbox supplies the exact handle, pool and
/// instance identities it checkpointed before release.
fn validated_child_receipt_token(
    lease: &crate::crd::ClusterLease,
    receipt: &crate::crd::TeardownReceipt,
    recorded_lease: &crate::crd::SandboxObjectReference,
    recorded_instance: Option<&crate::crd::SandboxObjectReference>,
    recorded_pool: &crate::crd::SandboxObjectReference,
) -> Option<String> {
    let namespace = recorded_lease.namespace.as_deref()?;
    let status = lease.status.as_ref()?;
    let binding = status.binding.as_ref()?;
    if lease.name_any() != recorded_lease.name
        || lease.uid().as_deref() != Some(recorded_lease.uid.as_str())
        || binding.lease.name != recorded_lease.name
        || binding.lease.uid.as_deref() != Some(recorded_lease.uid.as_str())
        || binding.pool.name != recorded_pool.name
        || binding.pool.uid.as_deref() != Some(recorded_pool.uid.as_str())
    {
        return None;
    }
    let expected = recorded_instance?;
    if expected.uid.is_empty()
        || binding.instance.name != expected.name
        || binding.instance.uid != expected.uid
        || binding.instance.observed_generation != expected.generation?
    {
        return None;
    }

    validated_binding_receipt_token(lease, receipt, namespace)
}

/// Validate the producer-owned half of a retained receipt.
///
/// The outer consumer additionally checks its independently checkpointed
/// handle, pool and instance references in [`validated_child_receipt_token`].
/// The tombstone sweep can still revalidate this controller-owned reciprocal
/// binding after the outer Sandbox has legitimately disappeared.
fn validated_binding_receipt_token(
    lease: &crate::crd::ClusterLease,
    receipt: &crate::crd::TeardownReceipt,
    namespace: &str,
) -> Option<String> {
    let status = lease.status.as_ref()?;
    let binding = status.binding.as_ref()?;
    let durable_attempt = status.teardown_attempt_id.as_deref()?;
    if status.phase != crate::crd::LeasePhase::Recycling
        || lease.spec.cleanup_mode != Some(crate::crd::CleanupMode::VerifiedDestroy)
        || binding.cleanup_mode != crate::crd::CleanupMode::VerifiedDestroy
        || receipt.attempt_id != durable_attempt
    {
        return None;
    }
    let manifest = binding.creation_manifest.as_ref()?;
    if manifest.validate().is_err()
        || manifest.namespace != namespace
        || manifest.instance.name != binding.instance.name
        || manifest.instance.uid.as_deref() != Some(binding.instance.uid.as_str())
        || manifest.backend_type != binding.backend.backend_type
        || manifest.config_digest != binding.backend.config_digest
    {
        return None;
    }
    let manifest_digest = manifest.digest().ok()?;
    if binding.creation_manifest_digest.as_deref() != Some(manifest_digest.as_str()) {
        return None;
    }
    let connect_token = binding.connect_token.as_ref()?;
    if crate::api::connect::require_connect_token_identity_shape(
        connect_token,
        namespace,
        &binding.lease.name,
    )
    .is_err()
    {
        return None;
    }
    let mut required_subjects = manifest.required_subjects();
    required_subjects.push(crate::crd::TeardownSubject::ConnectTokenSecret);
    let mut recorded_identities = manifest.recorded_identities();
    recorded_identities.push(connect_token.canonical_id());
    let backend_type = format!("{:?}", binding.backend.backend_type).to_lowercase();
    let scope = crate::crd::TeardownScope {
        lease: &binding.lease,
        instance: &manifest.instance,
        pool: &binding.pool,
        backend_type: &backend_type,
        config_digest: &binding.backend.config_digest,
        instance_spec_digest: &binding.instance_spec_digest,
        creation_manifest_digest: &manifest_digest,
        cleanup_mode: binding.cleanup_mode,
        attempt_id: durable_attempt,
        creation_manifest: Some(manifest),
        connect_token_identity: Some(connect_token),
        required_subjects: &required_subjects,
        instance_name: &binding.instance.name,
        recorded_identities: &recorded_identities,
    };
    receipt
        .permits_release_for(&scope)
        .then(|| receipt.acknowledgement_token())
        .flatten()
}

/// Revalidate a retained producer receipt using only its controller-owned
/// reciprocal binding. This is used by the post-retention tombstone sweep,
/// after the outer Sandbox may no longer exist to supply duplicate references.
fn validated_retained_receipt_token(
    lease: &crate::crd::ClusterLease,
    receipt: &crate::crd::TeardownReceipt,
) -> Option<String> {
    let namespace = lease.namespace()?;
    validated_binding_receipt_token(lease, receipt, &namespace)
}

fn recorded_child_pool<'a>(
    status: &'a crate::crd::SandboxLeaseStatus,
    management_namespace: &str,
) -> Option<&'a crate::crd::SandboxObjectReference> {
    let crate::crd::ResolvedSandboxPlacement::ChildCluster { cluster_pool } =
        status.placement.as_ref()?
    else {
        return None;
    };
    (cluster_pool.api_version == "kobe.kunobi.ninja/v1alpha1"
        && cluster_pool.kind == "ClusterPool"
        && cluster_pool.namespace.as_deref() == Some(management_namespace)
        && !cluster_pool.name.is_empty()
        && !cluster_pool.uid.is_empty()
        && cluster_pool.generation.is_some())
    .then_some(cluster_pool)
}

fn live_child_pool_matches_recorded(
    pool: &crate::crd::ClusterPool,
    recorded: &crate::crd::SandboxObjectReference,
) -> bool {
    pool.name_any() == recorded.name
        && pool.uid().as_deref() == Some(recorded.uid.as_str())
        && pool.metadata.generation == recorded.generation
        && pool.metadata.deletion_timestamp.is_none()
}

/// Validate the complete reciprocal tuple against the immutable outer status.
/// The shared resolver proves that the live lease, instance and pool agree with
/// each other; this adds the boundary it cannot know — that every one is the
/// exact identity the composing Sandbox previously checkpointed.
fn resolved_child_binding_matches_recorded(
    resolved: &crate::lease_binding::ResolvedLeaseBinding,
    status: &crate::crd::SandboxLeaseStatus,
    management_namespace: &str,
    require_recorded_instance: bool,
) -> bool {
    let Some(target) = status.target.as_ref() else {
        return false;
    };
    let Some(recorded_lease) = target.child_cluster_lease.as_ref() else {
        return false;
    };
    let Some(recorded_pool) = recorded_child_pool(status, management_namespace) else {
        return false;
    };
    let lease_matches = recorded_lease.api_version == "kobe.kunobi.ninja/v1alpha1"
        && recorded_lease.kind == "ClusterLease"
        && recorded_lease.namespace.as_deref() == Some(management_namespace)
        && recorded_lease.name == resolved.lease.name_any()
        && resolved.lease.uid().as_deref() == Some(recorded_lease.uid.as_str())
        && resolved.lease.metadata.generation == recorded_lease.generation
        && resolved.binding.lease.name == recorded_lease.name
        && resolved.binding.lease.uid.as_deref() == Some(recorded_lease.uid.as_str());
    let pool_matches = live_child_pool_matches_recorded(&resolved.pool, recorded_pool)
        && resolved.binding.pool.name == recorded_pool.name
        && resolved.binding.pool.uid.as_deref() == Some(recorded_pool.uid.as_str());
    if !lease_matches || !pool_matches {
        return false;
    }

    let Some(recorded_instance) = target.child_cluster_instance.as_ref() else {
        return !require_recorded_instance;
    };
    recorded_instance.api_version == "kobe.kunobi.ninja/v1alpha1"
        && recorded_instance.kind == "ClusterInstance"
        && recorded_instance.namespace.as_deref() == Some(management_namespace)
        && recorded_instance.name == resolved.binding.instance.name
        && recorded_instance.uid == resolved.binding.instance.uid
        && recorded_instance.generation == Some(resolved.binding.instance.observed_generation)
        && resolved.instance.name_any() == recorded_instance.name
        && resolved.instance.uid().as_deref() == Some(recorded_instance.uid.as_str())
        && resolved.instance.metadata.generation == recorded_instance.generation
}

fn unbound_child_release_is_proven(
    current: &crate::crd::ClusterLease,
    recorded_instance: Option<&crate::crd::SandboxObjectReference>,
) -> bool {
    let status = current.status.as_ref().cloned().unwrap_or_default();
    let allocation_identity_is_safe = status.binding.is_none()
        || crate::controllers::lease::retained_unstarted_binding_matches_lease(current, &status);
    matches!(
        status.phase,
        crate::crd::LeasePhase::Released | crate::crd::LeasePhase::Expired
    ) && allocation_identity_is_safe
        && status.cluster_name.is_none()
        && status.teardown_receipt.is_none()
        && recorded_instance.is_none()
        && crate::controllers::lease::unbound_release_acknowledgement_token(&status).is_some()
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

/// ACK the exact receipt or NeverBound proof after the outer checkpoint.
///
/// Receipt ACK tests the complete receipt and binding, not only its attempt
/// nonce. NeverBound ACK tests both the durable attempt and absence timestamp.
async fn acknowledge_child_proof(
    internal: &Api<crate::crd::ClusterLease>,
    current: &crate::crd::ClusterLease,
    proof: &ChildProofAcknowledgement,
) -> Result<Option<crate::crd::ClusterLease>, SandboxPlacementError> {
    let (Some(uid), Some(resource_version)) = (current.uid(), current.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(
            "child proof handle has no UID or resourceVersion to ACK".into(),
        ));
    };
    let mut annotations = current.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(proof.annotation().into(), proof.token().to_string());
    let mut operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": resource_version }),
    ];
    match proof {
        ChildProofAcknowledgement::Receipt { receipt, .. } => {
            operations.extend([
                serde_json::json!({ "op": "test", "path": "/spec/cleanupMode", "value": "VerifiedDestroy" }),
                serde_json::json!({ "op": "test", "path": "/status/binding", "value": current.status.as_ref().and_then(|status| status.binding.as_ref()) }),
                serde_json::json!({ "op": "test", "path": "/status/teardownAttemptId", "value": receipt.attempt_id }),
                serde_json::json!({ "op": "test", "path": "/status/teardownReceipt", "value": receipt }),
            ]);
        }
        ChildProofAcknowledgement::NeverBound {
            attempt_id,
            verified_at,
            ..
        } => {
            operations.extend([
                serde_json::json!({ "op": "test", "path": "/status/teardownAttemptId", "value": attempt_id }),
                serde_json::json!({ "op": "test", "path": "/status/unboundReleaseVerifiedAt", "value": verified_at }),
            ]);
        }
    }
    operations.push(serde_json::json!({
        "op": "add",
        "path": "/metadata/annotations",
        "value": annotations
    }));
    let patch = crate::controllers::lease::json_patch(serde_json::Value::Array(operations));
    match internal
        .patch(
            &current.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(updated) => Ok(Some(updated)),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => Ok(None),
        Err(error) => Err(error.into()),
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
    quarantine_lease_with_cause(lease, ctx, reason, None).await
}

/// Quarantine a live lease whose own admission gate could not be verified.
///
/// These are the only quarantines that fire before any release decision, so
/// the lease carries no durable release cause — and [`release_reason`] maps a
/// cause-less quarantine to `None`, which wedged finalizer and quota forever:
/// the Quarantined reconcile arm returned before any evidence retry. Stamping
/// [`crate::crd::SandboxReleaseCause::Unverifiable`] in the same fenced write
/// makes the intended path reachable: the next reconcile drives the ordinary
/// evidence-gated teardown, which tears the workload down once it can prove
/// what it must, or keeps retrying while it cannot.
async fn quarantine_unverifiable_gate(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: &str,
) -> Result<Action, SandboxPlacementError> {
    quarantine_lease_with_cause(
        lease,
        ctx,
        reason,
        Some(crate::crd::SandboxReleaseCause::Unverifiable),
    )
    .await
}

async fn quarantine_lease_with_cause(
    lease: &SandboxLease,
    ctx: &SandboxContext,
    reason: &str,
    stamp_cause: Option<crate::crd::SandboxReleaseCause>,
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
    // The first cause wins forever; stamping never overwrites one that a
    // decided teardown already persisted.
    if next.release_cause.is_none() {
        next.release_cause = stamp_cause;
    }
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

/// Whether teardown and reservation cleanup both reached their durable
/// success checkpoint. A terminal phase alone is not enough to remove the
/// finalizer: old or corrupted objects may claim a clean phase without proof.
fn cleanup_verified(status: &crate::crd::SandboxLeaseStatus) -> bool {
    status.conditions.iter().any(|condition| {
        condition.condition_type == CLEANUP_VERIFIED_CONDITION
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

/// Whether metadata carries one exact controller owner reference.
///
/// Shared with Sandbox-to-Pod resolution so every adoption boundary uses the
/// same name+UID+GVK rule.
pub(super) fn metadata_is_controlled_by(
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

/// Whether metadata has no garbage-collection dependency at all.
///
/// Management claims and internal child leases are cleaned explicitly under
/// the outer lease finalizer. Accepting even a non-controller owner reference
/// would let Kubernetes delete them independently and turn a 404 into false
/// teardown evidence.
fn metadata_has_no_owner_references(metadata: &kube::api::ObjectMeta) -> bool {
    metadata.owner_references.as_ref().is_none_or(Vec::is_empty)
}

fn owner_identity_matches_instance(
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
    instance: &crate::crd::SandboxObjectReference,
) -> bool {
    owner.api_version == instance.api_version
        && owner.kind == instance.kind
        && owner.name == instance.name
        && owner.uid == instance.uid
}

/// k3s reserves `{instance}-kubeconfig` under the ClusterInstance controller
/// owner before the publisher writes `data.kubeconfig`. The publisher path
/// (`kubectl apply` of an ownerless dry-run Secret) may leave that controller
/// owner in place, drop the controller bit, or add non-controller metadata
/// owners. Composition is safe when:
///
/// * there are no owners (publisher created the name), or
/// * the unique `controller: true` owner is this ClusterInstance, or
/// * the sole owner is this ClusterInstance even if `controller` was dropped.
///
/// A foreign controller owner cannot be a composition credential.
fn child_kubeconfig_secret_control_is_safe(
    metadata: &kube::api::ObjectMeta,
    instance: &crate::crd::SandboxObjectReference,
) -> bool {
    let owners = metadata.owner_references.as_deref().unwrap_or(&[]);
    if owners.is_empty() {
        return true;
    }
    let controllers = owners
        .iter()
        .filter(|owner| owner.controller == Some(true))
        .collect::<Vec<_>>();
    match controllers.as_slice() {
        [] => {
            matches!(owners, [owner] if owner_identity_matches_instance(owner, instance))
        }
        [owner] => owner_identity_matches_instance(owner, instance),
        _ => false,
    }
}

fn child_kubeconfig_secret_control_error(
    metadata: &kube::api::ObjectMeta,
    instance: &crate::crd::SandboxObjectReference,
) -> String {
    let owners = metadata.owner_references.as_deref().unwrap_or(&[]);
    let summary = owners
        .iter()
        .map(|owner| {
            format!(
                "{}/{} {} uid {} controller={}",
                owner.api_version,
                owner.kind,
                owner.name,
                owner.uid,
                owner
                    .controller
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".into()),
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "owners [{summary}] are not the ClusterInstance {} uid {}",
        instance.name, instance.uid
    )
}

/// Exact outer-lease identity fence for an upstream claim.
///
/// Management claims intentionally have no owner reference, while a
/// child-cluster object cannot carry a reference to the outer management
/// cluster. The controller-owned UID label therefore has to match before Kobe
/// adopts, observes, or mutates either; the Claim name is checked separately
/// against its deterministic derived name.
fn claim_is_for_lease(claim: &DynamicObject, lease_uid: &str) -> bool {
    let labels = claim.labels();
    labels
        .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
        .is_some_and(|value| value == lease_uid)
        && labels
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
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

struct ChildKubeconfigObservation {
    reference: crate::crd::SandboxObjectReference,
    payload_sha256: String,
    kubeconfig_payload: Vec<u8>,
}

/// Observe the write-once identity and payload checkpoint for the management
/// Secret that authenticates one exact child instance.
///
/// k3s reserves the Secret name under the ClusterInstance controller owner
/// before the publisher writes `data.kubeconfig`. Composition still uses a
/// trust-on-first-use boundary: the first read only computes the checkpoint,
/// then returns. A foreign controller owner fails closed. Every later use
/// re-GETs the same UID and payload digest. Existing child placements that
/// already consumed an uncheckpointed Secret cannot be backfilled safely.
fn child_kubeconfig_secret_observation(
    secret: &Secret,
    management_namespace: &str,
    instance: &crate::crd::SandboxObjectReference,
) -> Result<ChildKubeconfigObservation, SandboxPlacementError> {
    use sha2::{Digest as _, Sha256};

    let expected_name = crate::backend::kubeconfig_secret_name(&instance.name);
    let secret_ns = secret.namespace();
    let provenance_error = |reason: String| {
        SandboxPlacementError::Invalid(format!(
            "child kubeconfig Secret {management_namespace}/{expected_name} has unsafe provenance: {reason}"
        ))
    };
    if instance.api_version != "kobe.kunobi.ninja/v1alpha1" || instance.kind != "ClusterInstance" {
        return Err(provenance_error(format!(
            "recorded instance is {}/{}",
            instance.api_version, instance.kind
        )));
    }
    if instance.namespace.as_deref() != Some(management_namespace) {
        return Err(provenance_error(format!(
            "recorded instance namespace is {}",
            instance.namespace.as_deref().unwrap_or("<none>")
        )));
    }
    if instance.uid.is_empty() {
        return Err(provenance_error("recorded instance UID is empty".into()));
    }
    if secret.name_any() != expected_name {
        return Err(provenance_error(format!(
            "live name is {}",
            secret.name_any()
        )));
    }
    // Namespaced GET may omit metadata.namespace because it is implied by the
    // request path. Treat a missing namespace as the namespace we fetched from.
    if secret_ns
        .as_deref()
        .is_some_and(|namespace| namespace != management_namespace)
    {
        return Err(provenance_error(format!(
            "live namespace is {}",
            secret_ns.unwrap_or_else(|| "<none>".into())
        )));
    }
    let uid = secret
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| provenance_error("Secret has no UID".into()))?;
    if secret
        .metadata
        .resource_version
        .as_deref()
        .is_none_or(str::is_empty)
    {
        return Err(provenance_error("Secret has no resourceVersion".into()));
    }
    if secret.metadata.deletion_timestamp.is_some() {
        return Err(provenance_error("Secret is deleting".into()));
    }
    if !child_kubeconfig_secret_control_is_safe(&secret.metadata, instance) {
        return Err(provenance_error(child_kubeconfig_secret_control_error(
            &secret.metadata,
            instance,
        )));
    }
    let kubeconfig_payload =
        crate::backend::checkpointed_kubeconfig_payload(secret).map_err(|_| {
            SandboxPlacementError::Invalid("child kubeconfig payload is ambiguous".into())
        })?;
    let payload_sha256 = format!("{:x}", Sha256::digest(&kubeconfig_payload));
    Ok(ChildKubeconfigObservation {
        reference: crate::crd::SandboxObjectReference {
            api_version: "v1".into(),
            kind: "Secret".into(),
            namespace: Some(management_namespace.into()),
            name: expected_name,
            uid,
            generation: None,
        },
        payload_sha256,
        kubeconfig_payload,
    })
}

/// Require that one GET response is still the exact checkpointed child
/// credential before its bytes can be parsed or used.
fn require_exact_child_kubeconfig_secret(
    recorded: &crate::crd::SandboxObjectReference,
    recorded_digest: &str,
    observed: &ChildKubeconfigObservation,
) -> Result<(), SandboxPlacementError> {
    if recorded != &observed.reference || recorded_digest != observed.payload_sha256 {
        return Err(SandboxPlacementError::Invalid(format!(
            "recorded child kubeconfig Secret provenance cannot change: expected {}/{} uid {}",
            recorded.namespace.as_deref().unwrap_or_default(),
            recorded.name,
            recorded.uid
        )));
    }
    Ok(())
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

/// Strongly re-read the exact admitted pool before an allocation side effect.
/// A stale informer object or a Ready certificate for another generation never
/// authorizes creation.
async fn current_sandbox_pool_for_create(
    lease: &SandboxLease,
    pools: &Api<SandboxPool>,
) -> Result<Option<SandboxPool>, SandboxPlacementError> {
    let pool = pools.get(&lease.spec.pool_ref.name).await?;
    if pool.uid().as_deref() != Some(lease.spec.pool_ref.uid.as_str())
        || pool.metadata.generation != Some(lease.spec.pool_ref.generation)
        || pool.metadata.deletion_timestamp.is_some()
    {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxPool {} changed identity before allocation",
            lease.spec.pool_ref.name
        )));
    }
    if crate::sandbox::require_current_sandbox_pool_ready(&pool).is_err() {
        let Some(authority) = crate::sandbox::current_child_pool_allocation_authority(&pool) else {
            return Ok(None);
        };
        if lease.spec.placement_authority.as_ref() != Some(authority) {
            return Err(SandboxPlacementError::Invalid(format!(
                "SandboxPool {} changed child placement authority before allocation",
                lease.spec.pool_ref.name
            )));
        }
    }
    Ok(Some(pool))
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
            child_cluster_kubeconfig_secret: None,
            child_cluster_kubeconfig_sha256: None,
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
            service: None,
        });
    proposed.sandbox_template = Some(observed.remove(0));
    proposed.sandbox_warm_pool = Some(observed.remove(0));
    Ok(Some(proposed))
}

/// A workload can advance only after every object the selected pool can create
/// has an exact persisted identity. Pools without exposed ports legitimately
/// have no Service; pools with ports must never infer one later by name.
fn workload_provenance_is_complete(
    status: &crate::crd::SandboxLeaseStatus,
    service_required: bool,
) -> bool {
    status.target.as_ref().is_some_and(|target| {
        target.sandbox_claim.is_some()
            && target.sandbox.is_some()
            && target.pod.is_some()
            && (!service_required || target.service.is_some())
    })
}

fn management_provenance_is_complete(
    status: &crate::crd::SandboxLeaseStatus,
    service_required: bool,
) -> bool {
    status.target.as_ref().is_some_and(|target| {
        target.sandbox_template.is_some() && target.sandbox_warm_pool.is_some()
    }) && workload_provenance_is_complete(status, service_required)
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
    service_required: bool,
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
    if service_required && resolved.service_uid.is_none() {
        return Ok(None);
    }

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
        child_cluster_kubeconfig_secret: existing
            .as_ref()
            .and_then(|existing| existing.child_cluster_kubeconfig_secret.clone()),
        child_cluster_kubeconfig_sha256: existing
            .as_ref()
            .and_then(|existing| existing.child_cluster_kubeconfig_sha256.clone()),
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
        service: resolved
            .service_name
            .as_deref()
            .zip(resolved.service_uid.as_deref())
            .map(|(name, uid)| reference("v1", "Service", name, uid)),
    }))
}

/// Where one lease's Sandbox is placed.
struct Target {
    client: Client,
    namespace: String,
    /// Whether this is the management target. Its pool objects use the
    /// SandboxPool owner, while child pool objects use the remote Namespace.
    /// Claims are handled separately by `claim_owner`.
    owned: bool,
    /// Exact same-cluster controller for a child Claim. Management leaves this
    /// empty so its Claim survives GC until explicit teardown proof.
    claim_owner: Option<Box<OwnerReference>>,
}

/// A child cluster is either usable now, or it is not there yet.
enum ChildTarget {
    Ready(Target),
    /// Composition is in progress; the action says when to look again.
    Pending(Action),
}

const CHILD_LEASE_NAME_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-lease-name";

fn child_namespace_matches_lease(namespace: &Namespace, lease_name: &str, lease_uid: &str) -> bool {
    let labels = namespace.labels();
    let annotations = namespace.annotations();
    namespace.metadata.deletion_timestamp.is_none()
        && labels
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
        && labels
            .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
            .is_some_and(|value| value == lease_uid)
        && annotations
            .get(CHILD_LEASE_NAME_ANNOTATION)
            .is_some_and(|value| value == lease_name)
        && namespace.uid().is_some_and(|uid| !uid.is_empty())
}

/// Create or adopt the fixed target namespace inside one exclusive child.
///
/// The outer lease lives in another Kubernetes cluster and cannot be an owner
/// reference here. Exact lease-UID metadata fences adoption, while the
/// namespace itself becomes the same-cluster controller owner for every
/// upstream object Kobe creates below it.
async fn ensure_child_namespace(
    client: &Client,
    lease_name: &str,
    lease_uid: &str,
) -> Result<Namespace, SandboxPlacementError> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let desired = Namespace {
        metadata: kube::api::ObjectMeta {
            name: Some(CHILD_SANDBOX_NAMESPACE.to_string()),
            labels: Some(
                [
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        crate::sandbox::KOBE_MANAGED_BY.to_string(),
                    ),
                    (
                        crate::sandbox::SANDBOX_LEASE_UID_LABEL.to_string(),
                        lease_uid.to_string(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            annotations: Some(
                [(
                    CHILD_LEASE_NAME_ANNOTATION.to_string(),
                    lease_name.to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        },
        ..Default::default()
    };

    let namespace = match namespaces.get(CHILD_SANDBOX_NAMESPACE).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            match namespaces.create(&PostParams::default(), &desired).await {
                Ok(created) => created,
                Err(kube::Error::Api(error)) if error.code == 409 => {
                    namespaces.get(CHILD_SANDBOX_NAMESPACE).await?
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };

    if !child_namespace_matches_lease(&namespace, lease_name, lease_uid) {
        return Err(SandboxPlacementError::Invalid(format!(
            "namespace {CHILD_SANDBOX_NAMESPACE} is not owned by SandboxLease {lease_name} uid {lease_uid}"
        )));
    }
    Ok(namespace)
}

const CHILD_RUNTIME_CANARY_NAME: &str = "kobe-runtime-canary-v1-0-0";
const CHILD_RUNTIME_RECEIPT_NAME: &str = "kobe-runtime-certified-v1-0-0";

/// Certify one disposable child runtime with a restart-safe create/delete
/// canary. The receipt is local to the exclusive child and binds the exact
/// ClusterInstance UID plus the pinned managed manifest.
async fn ensure_child_runtime_certified(
    client: &Client,
    namespace_owner: &OwnerReference,
    pool: &SandboxPool,
    warm_pool_name: &str,
    instance_uid: &str,
    provisioning_deadline: chrono::DateTime<chrono::Utc>,
    identity: &crate::sandbox_runtime::ManagedRuntimeIdentity,
) -> Result<bool, SandboxPlacementError> {
    let namespace = CHILD_SANDBOX_NAMESPACE;
    let receipts: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let receipt = match receipts.get(CHILD_RUNTIME_RECEIPT_NAME).await {
        Ok(receipt) => Some(receipt),
        Err(kube::Error::Api(error)) if error.code == 404 => None,
        Err(error) => return Err(error.into()),
    };

    if let Some(mut receipt) = receipt {
        if !metadata_is_controlled_by(
            &receipt.metadata,
            &namespace_owner.api_version,
            &namespace_owner.kind,
            &namespace_owner.name,
            &namespace_owner.uid,
        ) {
            return Err(SandboxPlacementError::Invalid(
                "child runtime certification receipt has foreign ownership".into(),
            ));
        }
        let data = receipt.data.as_mut().ok_or_else(|| {
            SandboxPlacementError::Invalid("child runtime certification receipt has no data".into())
        })?;
        if data.get("instanceUid").map(String::as_str) != Some(instance_uid)
            || data.get("owner").map(String::as_str) != Some(identity.owner.as_str())
            || data.get("manifestSha256").map(String::as_str)
                != Some(identity.manifest_sha256.as_str())
        {
            return Err(SandboxPlacementError::Invalid(
                "child runtime certification receipt does not match the exact instance and managed runtime".into(),
            ));
        }
        match data.get("phase").map(String::as_str) {
            Some("Certified") => return Ok(true),
            Some("Deleting") => {
                let required = |key: &str| {
                    data.get(key)
                        .cloned()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            SandboxPlacementError::Invalid(format!(
                                "child runtime certification receipt lacks {key}"
                            ))
                        })
                };
                let claim_uid = required("claimUid")?;
                let sandbox_name = required("sandboxName")?;
                let sandbox_uid = required("sandboxUid")?;
                let pod_name = required("podName")?;
                let pod_uid = required("podUid")?;
                let claims: Api<DynamicObject> = Api::namespaced_with(
                    client.clone(),
                    namespace,
                    &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
                );
                match claims.get(CHILD_RUNTIME_CANARY_NAME).await {
                    Ok(claim) => {
                        if claim.uid().as_deref() != Some(&claim_uid) {
                            return Err(SandboxPlacementError::Invalid(
                                "child runtime canary Claim was replaced".into(),
                            ));
                        }
                        let params = DeleteParams {
                            propagation_policy: Some(PropagationPolicy::Foreground),
                            preconditions: Some(Preconditions {
                                uid: Some(claim_uid),
                                resource_version: claim.resource_version(),
                            }),
                            ..Default::default()
                        };
                        match claims.delete(CHILD_RUNTIME_CANARY_NAME, &params).await {
                            Ok(_) => return Ok(false),
                            Err(kube::Error::Api(error))
                                if error.code == 404 || error.code == 409 =>
                            {
                                return Ok(false);
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => return Err(error.into()),
                }

                let sandboxes: Api<DynamicObject> =
                    Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
                match sandboxes.get(&sandbox_name).await {
                    Ok(sandbox) if sandbox.uid().as_deref() == Some(&sandbox_uid) => {
                        return Ok(false);
                    }
                    Ok(_) => {
                        return Err(SandboxPlacementError::Invalid(
                            "child runtime canary Sandbox was replaced".into(),
                        ));
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => return Err(error.into()),
                }
                let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
                match pods.get(&pod_name).await {
                    Ok(pod) if pod.uid().as_deref() == Some(&pod_uid) => return Ok(false),
                    Ok(_) => {
                        return Err(SandboxPlacementError::Invalid(
                            "child runtime canary Pod was replaced".into(),
                        ));
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => return Err(error.into()),
                }

                data.insert("phase".into(), "Certified".into());
                let resource_version = receipt.resource_version().ok_or_else(|| {
                    SandboxPlacementError::Invalid(
                        "child runtime certification receipt has no resourceVersion".into(),
                    )
                })?;
                receipt.metadata.resource_version = Some(resource_version);
                match receipts
                    .replace(CHILD_RUNTIME_RECEIPT_NAME, &PostParams::default(), &receipt)
                    .await
                {
                    Ok(_) => return Ok(false),
                    Err(kube::Error::Api(error)) if error.code == 409 => return Ok(false),
                    Err(error) => return Err(error.into()),
                }
            }
            _ => {
                return Err(SandboxPlacementError::Invalid(
                    "child runtime certification receipt has an invalid phase".into(),
                ));
            }
        }
    }

    let claim = build_sandbox_claim(
        CHILD_RUNTIME_CANARY_NAME,
        namespace,
        warm_pool_name,
        instance_uid,
        provisioning_deadline,
        false,
        Some(namespace_owner),
    );
    let claim = apply_upstream(
        client,
        namespace,
        &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
        &claim,
        namespace_owner,
    )
    .await?;
    if !upstream_claim_is_ready(&claim) {
        return Ok(false);
    }
    let resolved =
        crate::controllers::sandbox_canary::resolve_sandbox_pod(client, namespace, &claim)
            .await
            .map_err(SandboxPlacementError::Invalid)?;
    let Some(resolved) = resolved else {
        return Ok(false);
    };
    match crate::controllers::sandbox_canary::run_canary(
        client,
        namespace,
        &resolved,
        &pool.spec.template.default_container,
        &pool.spec.readiness.canary,
    )
    .await
    {
        crate::controllers::sandbox_canary::CanaryOutcome::Passed => {}
        outcome => {
            debug!(
                reason = outcome.reason_code(),
                "child runtime execution canary did not pass"
            );
            return Ok(false);
        }
    }
    let claim_uid = claim.uid().ok_or_else(|| {
        SandboxPlacementError::Invalid("child runtime canary Claim has no UID".into())
    })?;
    let data = BTreeMap::from([
        ("phase".into(), "Deleting".into()),
        ("instanceUid".into(), instance_uid.into()),
        ("owner".into(), identity.owner.clone()),
        ("manifestSha256".into(), identity.manifest_sha256.clone()),
        ("claimUid".into(), claim_uid),
        ("sandboxName".into(), resolved.sandbox_name),
        ("sandboxUid".into(), resolved.sandbox_uid),
        ("podName".into(), resolved.pod_name),
        ("podUid".into(), resolved.pod_uid),
    ]);
    let marker = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(CHILD_RUNTIME_RECEIPT_NAME.into()),
            namespace: Some(namespace.into()),
            owner_references: Some(vec![namespace_owner.clone()]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    match receipts.create(&PostParams::default(), &marker).await {
        Ok(_) => Ok(false),
        Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
        Err(error) => Err(error.into()),
    }
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
    let placement_authority = lease.spec.placement_authority.as_ref().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "SandboxLease {name} has no immutable child placementAuthority"
        ))
    })?;
    if placement_authority.name != cluster_pool_ref {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {name} placementAuthority does not match ClusterPool {cluster_pool_ref}"
        )));
    }
    let cluster_pools: Api<crate::crd::ClusterPool> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let cluster_pool = cluster_pools.get(cluster_pool_ref).await?;

    // Backend capability first: a pool that cannot prove teardown must never
    // back an exclusive tenant cluster, and finding that out after allocating
    // one helps nobody.
    if !child::child_placement_authority_matches(
        placement_authority,
        pool,
        &cluster_pool,
        &ctx.namespace,
    )? {
        return Err(SandboxPlacementError::Invalid(format!(
            "ClusterPool {cluster_pool_ref} no longer matches SandboxLease {name} placementAuthority"
        )));
    }
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
    let recorded_internal = lease
        .status
        .as_ref()
        .and_then(|status| status.target.as_ref())
        .and_then(|target| target.child_cluster_lease.as_ref());
    let internal_lease = match internal.get(&internal_name).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 && recorded_internal.is_some() => {
            return Err(SandboxPlacementError::Invalid(format!(
                "recorded ClusterLease {internal_name} is absent; refusing to allocate a same-named replacement"
            )));
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            let composed = child::build_internal_cluster_lease(lease, cluster_pool_ref, lifetime)
                .ok_or_else(|| {
                SandboxPlacementError::Invalid(format!("lease {name} has no UID to own a child"))
            })?;
            match create_internal_cluster_lease_fenced(
                lease,
                ctx,
                &internal,
                &composed,
                placement_authority,
            )
            .await?
            {
                Some(created) => {
                    info!(lease = %name, cluster_lease = %internal_name, "composed child cluster lease behind final allocation fence");
                    created
                }
                None => {
                    return Ok(ChildTarget::Pending(Action::requeue(
                        std::time::Duration::from_secs(5),
                    )));
                }
            }
        }
        Err(error) => return Err(error.into()),
    };

    // Adoption is fenced. A same-named object without this exact durable
    // identity is
    // somebody else's cluster, and placing a tenant's Sandbox into it would be
    // the worst possible outcome of a name collision.
    let lease_uid = lease.uid().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxLease {name} has no UID to own a child"))
    })?;
    if !child::internal_lease_matches_composition_identity(
        &internal_lease,
        lease,
        cluster_pool_ref,
        lifetime,
    ) {
        return Err(SandboxPlacementError::Invalid(format!(
            "ClusterLease {internal_name} exists but does not match SandboxLease {name} uid {lease_uid}"
        )));
    }
    match ensure_internal_lease_fenced(&internal, &internal_lease, lease).await? {
        InternalHandleFence::Ready => {}
        InternalHandleFence::Patched => {
            info!(lease = %name, cluster_lease = %internal_name, "fenced exact child handle");
            return Ok(ChildTarget::Pending(Action::requeue(
                std::time::Duration::from_secs(5),
            )));
        }
        InternalHandleFence::Foreign => {
            return Err(SandboxPlacementError::Invalid(format!(
                "ClusterLease {internal_name} has foreign or unsafe ownerReferences"
            )));
        }
    }
    if !child::internal_lease_has_secret_uid_protocol(&internal_lease) {
        return Err(SandboxPlacementError::Invalid(format!(
            "ClusterLease {internal_name} predates child kubeconfig UID provenance and cannot resume placement"
        )));
    }
    if !child::internal_lease_matches_composition(
        &internal_lease,
        lease,
        cluster_pool_ref,
        lifetime,
    ) {
        return Err(SandboxPlacementError::Invalid(format!(
            "ClusterLease {internal_name} exists but does not match SandboxLease {name} uid {lease_uid}"
        )));
    }

    let internal_uid = internal_lease
        .uid()
        .ok_or_else(|| SandboxPlacementError::Invalid("child lease has no UID".into()))?;
    let internal_generation = internal_lease.metadata.generation.ok_or_else(|| {
        SandboxPlacementError::Invalid("child lease has no generation to fence".into())
    })?;

    // Persist the exact internal lease identity before waiting for a binding.
    // Cluster provisioning can take minutes; a release or controller crash in
    // that interval must still have a UID-fenced handle it can explicitly
    // release without relying on garbage collection.
    let status = lease.status.clone().unwrap_or_default();
    let placement = crate::sandbox::record_placement_once(
        status.placement.as_ref(),
        crate::crd::ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: crate::crd::SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterPool".into(),
                namespace: Some(placement_authority.namespace.clone()),
                name: placement_authority.name.clone(),
                uid: placement_authority.uid.clone(),
                generation: Some(placement_authority.generation),
            },
        },
        &ctx.namespace,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    let mut proposed = status
        .target
        .clone()
        .unwrap_or(crate::crd::SandboxTargetProvenance {
            namespace: CHILD_SANDBOX_NAMESPACE.to_string(),
            child_cluster_lease: None,
            child_cluster_instance: None,
            child_cluster_kubeconfig_secret: None,
            child_cluster_kubeconfig_sha256: None,
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
            service: None,
        });
    proposed.namespace = CHILD_SANDBOX_NAMESPACE.to_string();
    proposed.child_cluster_lease = Some(crate::crd::SandboxObjectReference {
        api_version: "kobe.kunobi.ninja/v1alpha1".into(),
        kind: "ClusterLease".into(),
        namespace: Some(ctx.namespace.clone()),
        name: internal_name.clone(),
        uid: internal_uid.clone(),
        generation: Some(internal_generation),
    });
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
            debug!(lease = %name, "recorded internal child lease before binding");
        } else {
            debug!(lease = %name, "internal child lease checkpoint lost a status race");
        }
        return Ok(ChildTarget::Pending(Action::await_change()));
    }

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
    if !resolved_child_binding_matches_recorded(&binding, &status, &ctx.namespace, false) {
        return Err(SandboxPlacementError::Invalid(format!(
            "resolved child binding for SandboxLease {name} does not match its recorded ClusterLease/ClusterPool identity"
        )));
    }

    // Record what was composed before using it. Teardown has to be able to name
    // the exact instance it must prove absent, and provenance written only
    // after a successful placement would be missing in precisely the case that
    // matters — a crash partway through.
    let child_provenance = child::child_provenance(
        &ctx.namespace,
        CHILD_SANDBOX_NAMESPACE,
        &binding.lease,
        &binding.binding.instance.name,
        &binding.binding.instance.uid,
        Some(binding.binding.instance.observed_generation),
    );
    let status = lease.status.clone().unwrap_or_default();
    let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
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
        placement,
        &ctx.namespace,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    if status.target.as_ref() != Some(&provenance) {
        let mut next = status;
        next.target = Some(provenance);
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            debug!(lease = %name, "recorded child composition provenance");
        } else {
            debug!(lease = %name, "child composition provenance write lost a status race");
        }
        return Ok(ChildTarget::Pending(Action::await_change()));
    }
    if !resolved_child_binding_matches_recorded(&binding, &status, &ctx.namespace, true) {
        return Err(SandboxPlacementError::Invalid(format!(
            "resolved child binding for SandboxLease {name} does not match its recorded ClusterLease/Instance/ClusterPool provenance"
        )));
    }

    // Checkpoint the exact management Secret UID and canonical payload digest
    // before parsing it into a client or sending one authenticated request.
    // The publisher creates an ownerless deterministic name, so an older child
    // that already consumed an unrecorded Secret cannot later prove which UID
    // and bytes authenticated that use. New composition records the boundary,
    // returns, and re-GETs that same object on the next pass.
    let recorded_instance = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_instance.as_ref())
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no child instance provenance"
            ))
        })?;
    let secret_name = crate::backend::kubeconfig_secret_name(&recorded_instance.name);
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let secret = match secrets.get(&secret_name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(error))
            if error.code == 404
                && status
                    .target
                    .as_ref()
                    .and_then(|target| target.child_cluster_kubeconfig_secret.as_ref())
                    .is_none() =>
        {
            debug!(lease = %name, "waiting for child kubeconfig Secret before provenance checkpoint");
            return Ok(ChildTarget::Pending(Action::requeue(
                std::time::Duration::from_secs(5),
            )));
        }
        Err(error) => return Err(error.into()),
    };
    let observation =
        child_kubeconfig_secret_observation(&secret, &ctx.namespace, recorded_instance)?;
    let recorded_secret = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_kubeconfig_secret.as_ref());
    let recorded_digest = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_kubeconfig_sha256.as_deref());
    if recorded_secret.is_none() && recorded_digest.is_none() {
        let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let mut proposed = status.target.clone().ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no child target provenance"
            ))
        })?;
        proposed.child_cluster_kubeconfig_secret = Some(observation.reference.clone());
        proposed.child_cluster_kubeconfig_sha256 = Some(observation.payload_sha256.clone());
        let provenance = crate::sandbox::merge_target_provenance(
            status.target.as_ref(),
            proposed,
            placement,
            &ctx.namespace,
        )
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
        let mut next = status;
        next.target = Some(provenance);
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            debug!(lease = %name, "checkpointed exact child kubeconfig Secret before use");
        } else {
            debug!(lease = %name, "child kubeconfig Secret checkpoint lost a status race");
        }
        return Ok(ChildTarget::Pending(Action::await_change()));
    }
    let (Some(recorded_secret), Some(recorded_digest)) = (recorded_secret, recorded_digest) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {name} has a partial child kubeconfig provenance checkpoint"
        )));
    };
    require_exact_child_kubeconfig_secret(recorded_secret, recorded_digest, &observation)?;

    // Kubeconfig bytes remain in memory and never enter status, API responses,
    // error text, or logs. Client construction uses the same exact GET response
    // whose UID and digest were checked above, avoiding a second name-based
    // read race.
    let kubeconfig = String::from_utf8(observation.kubeconfig_payload).map_err(|_| {
        child::ChildPlacementError::ChildCredentialUnusable {
            cluster: binding.binding.instance.name.clone(),
        }
    })?;
    let child_client = crate::backend::virtual_client_from_kubeconfig(&kubeconfig)
        .await
        .map_err(|_| child::ChildPlacementError::ChildCredentialUnusable {
            cluster: binding.binding.instance.name.clone(),
        })?;

    // Authenticate the exact chart-owned child installation before writing a
    // Sandbox object. The live create/delete proof follows after the child-side
    // pool identities have been checkpointed.
    let managed_identity = ctx.managed_runtime_identity.as_ref().ok_or_else(|| {
        SandboxPlacementError::Invalid("managed child runtime identity is unavailable".into())
    })?;
    child::validate_child_runtime(
        &child_client,
        &binding.binding.instance.name,
        managed_identity,
    )
    .await?;

    let target_namespace = ensure_child_namespace(&child_client, &name, &lease_uid).await?;
    let namespace_owner = target_namespace.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!(
            "namespace {CHILD_SANDBOX_NAMESPACE} has no UID to own child Sandbox objects"
        ))
    })?;

    // The pool's template and warm pool have to exist inside the child; nothing
    // else reconciles them there.
    let (template, warm_pool) = ensure_upstream_pool_objects(
        &child_client,
        CHILD_SANDBOX_NAMESPACE,
        &pool.name_any(),
        &pool.spec,
        &namespace_owner,
    )
    .await?;

    // Record the exact child-side pool objects before creating a Claim. A
    // restart after Claim creation must already know which Template/WarmPool
    // identities it is authorised to observe and later verify.
    let status = lease.status.clone().unwrap_or_default();
    let mut proposed = status.target.clone().ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("lease {name} has no child composition provenance"))
    })?;
    proposed.sandbox_template = Some(target_reference(
        AGENT_SANDBOX_API_VERSION,
        SANDBOX_TEMPLATE_KIND,
        CHILD_SANDBOX_NAMESPACE,
        &template,
    )?);
    proposed.sandbox_warm_pool = Some(target_reference(
        AGENT_SANDBOX_API_VERSION,
        SANDBOX_WARM_POOL_KIND,
        CHILD_SANDBOX_NAMESPACE,
        &warm_pool,
    )?);
    let placement = crate::sandbox::require_resolved_placement(&status, &ctx.namespace)
        .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    let provenance = crate::sandbox::merge_target_provenance(
        status.target.as_ref(),
        proposed,
        placement,
        &ctx.namespace,
    )
    .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
    if status.target.as_ref() != Some(&provenance) {
        let mut next = status;
        next.target = Some(provenance);
        if patch_lease_status_fenced(ctx, lease, &next).await? {
            debug!(lease = %name, "recorded child pool provenance");
        } else {
            debug!(lease = %name, "child pool provenance write lost a status race");
        }
        return Ok(ChildTarget::Pending(Action::await_change()));
    }

    let provisioning_deadline = status
        .provisioning_deadline
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "SandboxLease {name} has no valid provisioning deadline for child certification"
            ))
        })?;
    if !ensure_child_runtime_certified(
        &child_client,
        &namespace_owner,
        pool,
        &warm_pool.name_any(),
        &binding.binding.instance.uid,
        provisioning_deadline,
        managed_identity,
    )
    .await?
    {
        debug!(lease = %name, "waiting for exact child runtime create/delete certification");
        return Ok(ChildTarget::Pending(Action::requeue(
            std::time::Duration::from_secs(5),
        )));
    }

    Ok(ChildTarget::Ready(Target {
        client: child_client,
        namespace: CHILD_SANDBOX_NAMESPACE.to_string(),
        owned: false,
        claim_owner: Some(Box::new(namespace_owner)),
    }))
}

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

/// Add or remove only Kobe's Sandbox cleanup finalizer under exact UID/RV
/// tests. Replacing the complete finalizer list preserves other controllers'
/// entries while preventing a stale reconcile from touching a replacement.
async fn patch_sandbox_finalizer(
    ctx: &SandboxContext,
    lease: &SandboxLease,
    present: bool,
) -> Result<bool, SandboxPlacementError> {
    let mut finalizers = lease.metadata.finalizers.clone().unwrap_or_default();
    let had_finalizer = finalizers
        .iter()
        .any(|finalizer| finalizer == crate::sandbox::SANDBOX_LEASE_FINALIZER);
    if had_finalizer == present {
        return Ok(true);
    }
    if present {
        finalizers.push(crate::sandbox::SANDBOX_LEASE_FINALIZER.to_string());
    } else {
        finalizers.retain(|finalizer| finalizer != crate::sandbox::SANDBOX_LEASE_FINALIZER);
    }
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(format!(
            "SandboxLease {} has no UID or resourceVersion to fence finalizer",
            lease.name_any()
        )));
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/metadata/finalizers", "value": finalizers }
    ]));
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match leases
        .patch(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn sandbox_finalizer_present(lease: &SandboxLease) -> bool {
    lease
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|finalizers| {
            finalizers
                .iter()
                .any(|finalizer| finalizer == crate::sandbox::SANDBOX_LEASE_FINALIZER)
        })
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

#[derive(Clone)]
struct ReceiptAckAuthorityContext {
    client: Client,
    namespace: String,
}

/// Watch durable Sandbox consumer checkpoints and publish producer ACKs under
/// the dedicated teardown-authority identity.
///
/// The general lifecycle controller may copy a proof into the exact outer UID
/// status, but it cannot acknowledge the child directly. This loop re-reads
/// both objects and immutable evidence before writing the single receipt-gated
/// exit acknowledged by the retained child handle.
pub async fn run_receipt_ack_authority_controller(
    client: Client,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    let context = Arc::new(ReceiptAckAuthorityContext {
        client,
        namespace: namespace.to_string(),
    });
    info!("Starting isolated teardown acknowledgement authority");
    Controller::new(leases, Config::default())
        .graceful_shutdown_on(async move { shutdown.cancelled().await })
        .run(
            reconcile_receipt_ack_authority,
            receipt_ack_authority_error_policy,
            context,
        )
        .for_each(|result| async move {
            if let Err(error) = result {
                error!(
                    ?error,
                    "receipt acknowledgement authority reconciliation error"
                );
            }
        })
        .await;
}

async fn reconcile_receipt_ack_authority(
    consumer: Arc<SandboxLease>,
    ctx: Arc<ReceiptAckAuthorityContext>,
) -> Result<Action, SandboxPlacementError> {
    let status = consumer.status.clone().unwrap_or_default();
    let Some(recorded) = status
        .target
        .as_ref()
        .and_then(|target| target.child_cluster_lease.as_ref())
    else {
        return Ok(Action::requeue(std::time::Duration::from_secs(60)));
    };
    if recorded.namespace.as_deref() != Some(ctx.namespace.as_str())
        || recorded.uid.trim().is_empty()
    {
        return Ok(Action::requeue(std::time::Duration::from_secs(60)));
    }
    let children: Api<crate::crd::ClusterLease> =
        Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let child = match children.get(&recorded.name).await {
        Ok(child) if composition_handle_matches_consumer(&child, &consumer, recorded) => child,
        Ok(_) => {
            return Ok(Action::requeue(std::time::Duration::from_secs(60)));
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Ok(Action::requeue(std::time::Duration::from_secs(60)));
        }
        Err(error) => return Err(error.into()),
    };

    let child_status = child.status.as_ref().cloned().unwrap_or_default();
    let acknowledgement = if let (Some(token), Some(checkpoint), Some(receipt)) = (
        status.child_teardown_receipt_acknowledgement.as_deref(),
        status.child_teardown_evidence.as_ref(),
        child_status.teardown_receipt.as_ref(),
    ) {
        let Some(authoritative) =
            authoritative_child_receipt_matches(&ctx.client, &ctx.namespace, &child, receipt)
                .await?
        else {
            return Ok(Action::requeue(std::time::Duration::from_secs(30)));
        };
        let Some(recorded_pool) = recorded_child_pool(&status, &ctx.namespace) else {
            return Ok(Action::requeue(std::time::Duration::from_secs(60)));
        };
        let expected = validated_child_receipt_token(
            &child,
            receipt,
            recorded,
            status
                .target
                .as_ref()
                .and_then(|target| target.child_cluster_instance.as_ref()),
            recorded_pool,
        );
        if authoritative != *checkpoint || expected.as_deref() != Some(token) {
            return Ok(Action::requeue(std::time::Duration::from_secs(60)));
        }
        crate::crd::TeardownAcknowledgement {
            attempt_id: receipt.attempt_id.clone(),
            consumer: sandbox_consumer_identity(&consumer)?,
            proof: crate::crd::TeardownAcknowledgedProof::receipt(
                token.to_string(),
                checkpoint.clone(),
            ),
            acknowledged_at: chrono::Utc::now().to_rfc3339(),
        }
    } else if let Some(checkpoint) = status.child_unbound_release_proof.as_ref() {
        let recorded_instance = status
            .target
            .as_ref()
            .and_then(|target| target.child_cluster_instance.as_ref());
        if validated_child_unbound_release_proof(&child, recorded_instance).as_ref()
            != Some(checkpoint)
        {
            return Ok(Action::requeue(std::time::Duration::from_secs(60)));
        }
        crate::crd::TeardownAcknowledgement {
            attempt_id: checkpoint.attempt_id.clone(),
            consumer: sandbox_consumer_identity(&consumer)?,
            proof: crate::crd::TeardownAcknowledgedProof::never_bound(
                checkpoint.verified_at.clone(),
            ),
            acknowledged_at: chrono::Utc::now().to_rfc3339(),
        }
    } else {
        return Ok(Action::requeue(std::time::Duration::from_secs(60)));
    };

    if let Some(existing) = child_status.teardown_acknowledgement.as_ref() {
        if existing.attempt_id == acknowledgement.attempt_id
            && existing.consumer == acknowledgement.consumer
            && existing.proof == acknowledgement.proof
        {
            return Ok(Action::requeue(std::time::Duration::from_secs(300)));
        }
        return Err(SandboxPlacementError::Invalid(
            "child teardown acknowledgement changed after authority publication".into(),
        ));
    }
    persist_authority_acknowledgement(&children, &child, &acknowledgement).await?;
    Ok(Action::requeue(std::time::Duration::from_secs(1)))
}

fn sandbox_consumer_identity(
    consumer: &SandboxLease,
) -> Result<crate::crd::KubernetesResourceIdentity, SandboxPlacementError> {
    Ok(crate::crd::KubernetesResourceIdentity {
        api_version: "kobe.kunobi.ninja/v1alpha1".into(),
        kind: "SandboxLease".into(),
        namespace: consumer.namespace(),
        name: consumer.name_any(),
        uid: consumer.uid().ok_or_else(|| {
            SandboxPlacementError::Invalid("SandboxLease consumer has no UID".into())
        })?,
    })
}

/// Authenticate an ownerless child handle without trusting mutable metadata as
/// the root of authority. The outer UID is recorded in immutable requester
/// spec; label and annotation are independent consistency checks.
fn composition_handle_matches_consumer(
    child: &crate::crd::ClusterLease,
    consumer: &SandboxLease,
    recorded: &crate::crd::SandboxObjectReference,
) -> bool {
    let Some(consumer_uid) = consumer.uid().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    child.uid().as_deref() == Some(recorded.uid.as_str())
        && child.name_any() == recorded.name
        && child.namespace() == recorded.namespace
        && crate::controllers::sandbox_child::internal_lease_is_for_sandbox(child, consumer)
        && child.spec.requester.identity == consumer_uid
        && child
            .annotations()
            .get(crate::controllers::sandbox_child::SANDBOX_COMPOSITION_NAME_ANNOTATION)
            == Some(&consumer.name_any())
}

async fn persist_authority_acknowledgement(
    leases: &Api<crate::crd::ClusterLease>,
    lease: &crate::crd::ClusterLease,
    acknowledgement: &crate::crd::TeardownAcknowledgement,
) -> Result<(), SandboxPlacementError> {
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Err(SandboxPlacementError::Invalid(
            "child ClusterLease has no UID or resourceVersion for authority ACK".into(),
        ));
    };
    let mut operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": resource_version }),
        serde_json::json!({ "op": "test", "path": "/status/teardownAttemptId", "value": acknowledgement.attempt_id }),
    ];
    match acknowledgement.proof.kind {
        crate::crd::TeardownAcknowledgedProofKind::Receipt => {
            operations.push(serde_json::json!({
                "op": "test", "path": "/status/teardownReceipt",
                "value": lease.status.as_ref().and_then(|status| status.teardown_receipt.as_ref())
            }));
            operations.push(serde_json::json!({
                "op": "test", "path": "/status/teardownEvidence",
                "value": acknowledgement.proof.evidence
            }));
        }
        crate::crd::TeardownAcknowledgedProofKind::NeverBound => {
            operations.push(serde_json::json!({
                "op": "test", "path": "/status/unboundReleaseVerifiedAt",
                "value": acknowledgement.proof.unbound_release_verified_at
            }));
        }
    }
    operations.push(serde_json::json!({
        "op": "add", "path": "/status/teardownAcknowledgement", "value": acknowledgement
    }));
    let patch = crate::controllers::lease::json_patch(serde_json::Value::Array(operations));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn receipt_ack_authority_error_policy(
    _lease: Arc<SandboxLease>,
    error: &SandboxPlacementError,
    _ctx: Arc<ReceiptAckAuthorityContext>,
) -> Action {
    warn!(%error, "teardown acknowledgement authority reconcile failed");
    Action::requeue(std::time::Duration::from_secs(15))
}

/// The independently running half of the Sandbox controller pair that ended.
///
/// Returning either value while shutdown is not cancelled is fatal: pool
/// placement without lease cleanup can strand or overbook work, while lease
/// cleanup without pool reconciliation can certify stale capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxControllerExit {
    Pool,
    Lease,
}

/// Wait for the first critical Sandbox controller loop to end.
///
/// Enabled mode races the pool and lease loops so one clean early return is
/// observable by the process supervisor. Cleanup-only mode intentionally does
/// not poll the synthetic pool future; only the always-required lease loop may
/// complete it.
async fn first_sandbox_controller_exit<P, L>(
    placement_enabled: bool,
    pool_loop: P,
    lease_loop: L,
) -> SandboxControllerExit
where
    P: std::future::Future<Output = ()>,
    L: std::future::Future<Output = ()>,
{
    tokio::pin!(pool_loop);
    tokio::pin!(lease_loop);

    if placement_enabled {
        tokio::select! {
            () = &mut pool_loop => SandboxControllerExit::Pool,
            () = &mut lease_loop => SandboxControllerExit::Lease,
        }
    } else {
        lease_loop.await;
        SandboxControllerExit::Lease
    }
}

/// Run Sandbox lifecycle until shutdown.
///
/// Pool placement is started only when `placement_enabled`. The lease loop is
/// always started: switching External to Disabled is a drain operation, not a
/// way to abandon finalizers, quota reservations, or retained tombstones.
pub async fn run_sandbox_controller(
    client: Client,
    namespace: &str,
    reservation_namespace: &str,
    runtime_mode: crate::sandbox_runtime::AgentSandboxMode,
    shutdown: CancellationToken,
) {
    let placement_enabled = runtime_mode.enabled();
    let managed_runtime_identity =
        (runtime_mode == crate::sandbox_runtime::AgentSandboxMode::Managed).then(|| {
            crate::sandbox_runtime::ManagedRuntimeIdentity::from_env()
                .expect("managed runtime identity was validated during startup")
        });
    let ctx = Arc::new(SandboxContext {
        client: client.clone(),
        namespace: namespace.to_string(),
        reservation_namespace: reservation_namespace.to_string(),
        shutdown: shutdown.clone(),
        access_ledger_enabled: true,
        placement_enabled,
        runtime_mode,
        managed_runtime_identity,
    });

    let pools: Api<SandboxPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<SandboxLease> = Api::namespaced(client, namespace);

    if placement_enabled {
        info!("Starting Sandbox placement and lifecycle controllers (management)");
    } else {
        info!("Starting Sandbox lifecycle controller in cleanup-only mode");
    }

    let pool_ctx = ctx.clone();
    let pool_shutdown = shutdown.clone();
    let pool_loop = async move {
        if placement_enabled {
            Controller::new(pools, Config::default())
                .graceful_shutdown_on(async move { pool_shutdown.cancelled().await })
                .run(reconcile_pool, pool_error_policy, pool_ctx)
                .for_each(|result| async move {
                    if let Err(error) = result {
                        error!(error = %error, "SandboxPool controller error");
                    }
                })
                .await;
        } else {
            pool_shutdown.cancelled().await;
        }
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

    let exited = first_sandbox_controller_exit(placement_enabled, pool_loop, lease_loop).await;
    if shutdown.is_cancelled() {
        info!(loop_name = ?exited, "Sandbox lifecycle controller shut down");
    } else {
        error!(loop_name = ?exited, "Sandbox controller loop exited unexpectedly");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `supervisor_lost` is deliberately not process-absence proof. Its cleanup
    /// outcome must advance the exact target's destruction instead of joining
    /// ordinary retries; management then deletes the Claim, while child
    /// placement checkpoints verified-destroy receipt mode.
    #[test]
    fn uncertain_terminal_execution_advances_target_destruction() {
        assert_eq!(
            execution_cleanup_advance(
                crate::api::sandbox_executions::ExecutionCleanupOutcome::AwaitTargetDestruction,
            ),
            ExecutionCleanupAdvance::DestroyTarget
        );
        assert_eq!(
            execution_cleanup_advance(
                crate::api::sandbox_executions::ExecutionCleanupOutcome::Retry,
            ),
            ExecutionCleanupAdvance::Retry
        );
    }

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

    /// Either half of the enabled controller pair is safety-critical. A clean
    /// early return is therefore still fatal and must not be hidden behind the
    /// other half's long-lived future.
    #[tokio::test]
    async fn enabled_controller_pair_returns_when_either_loop_exits() {
        assert_eq!(
            first_sandbox_controller_exit(true, std::future::ready(()), std::future::pending(),)
                .await,
            SandboxControllerExit::Pool,
        );
        assert_eq!(
            first_sandbox_controller_exit(true, std::future::pending(), std::future::ready(()),)
                .await,
            SandboxControllerExit::Lease,
        );
    }

    /// Cleanup-only mode deliberately has no pool loop. Its synthetic disabled
    /// branch must never mask or manufacture lifecycle-controller completion.
    #[tokio::test]
    async fn cleanup_only_controller_waits_exclusively_for_lease_loop() {
        let still_running = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            first_sandbox_controller_exit(false, std::future::ready(()), std::future::pending()),
        )
        .await;
        assert!(
            still_running.is_err(),
            "the disabled pool branch must not wake supervision",
        );

        assert_eq!(
            first_sandbox_controller_exit(false, std::future::pending(), std::future::ready(()),)
                .await,
            SandboxControllerExit::Lease,
        );
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
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NS: &str = "test-ns";
    const POOL_UID: &str = "pool-uid-1";
    const POOL_GENERATION: i64 = 3;
    const LEASE: &str = "sbx-1";

    const POOL_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agents";
    const POOL_STATUS_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agents/status";
    const LEASES_PATH: &str = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases";
    const CLAIMS_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims";
    const CLAIM_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims/kobe-sbx-1";
    const TEMPLATE_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxtemplates/kobe-agents";
    const WARM_POOL_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxwarmpools/kobe-agents";
    const SANDBOXES_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes";
    const SANDBOX_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes/sbx";
    const PODS_PATH: &str = "/api/v1/namespaces/test-ns/pods";
    const POD_PATH: &str = "/api/v1/namespaces/test-ns/pods/sandbox-pod";
    const SERVICES_PATH: &str = "/api/v1/namespaces/test-ns/services";
    const SERVICE_PATH: &str = "/api/v1/namespaces/test-ns/services/sandbox-service";
    const PVCS_PATH: &str = "/api/v1/namespaces/test-ns/persistentvolumeclaims";
    const PVS_PATH: &str = "/api/v1/persistentvolumes";
    const NETWORK_POLICY_PATH: &str =
        "/apis/networking.k8s.io/v1/namespaces/test-ns/networkpolicies/kobe-agents-network-policy";
    const LEASE_STATUS_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1/status";
    const LEASE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1";
    const ALLOCATION_FENCE_PATH: &str =
        "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/kobe-sbx-fence-sbx-1";
    const CHILD_POOL_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/children";
    const CHILD_INSTANCE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/kobe-abc123";

    fn test_managed_identity() -> crate::sandbox_runtime::ManagedRuntimeIdentity {
        crate::sandbox_runtime::ManagedRuntimeIdentity {
            owner: "test-ns/kobe".into(),
            manifest_sha256: "a".repeat(64),
            bootstrap_name: "kobe-agent-sandbox-v1-0-0".into(),
        }
    }

    async fn mount_healthy_runtime(server: &MockServer) {
        for (name, group, plural, kind) in [
            (
                "sandboxtemplates.extensions.agents.x-k8s.io",
                "extensions.agents.x-k8s.io",
                "sandboxtemplates",
                "SandboxTemplate",
            ),
            (
                "sandboxwarmpools.extensions.agents.x-k8s.io",
                "extensions.agents.x-k8s.io",
                "sandboxwarmpools",
                "SandboxWarmPool",
            ),
            (
                "sandboxclaims.extensions.agents.x-k8s.io",
                "extensions.agents.x-k8s.io",
                "sandboxclaims",
                "SandboxClaim",
            ),
            (
                "sandboxes.agents.x-k8s.io",
                "agents.x-k8s.io",
                "sandboxes",
                "Sandbox",
            ),
        ] {
            let openapi = if kind == "SandboxWarmPool" {
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "object",
                            "properties": {
                                "observedGeneration": {
                                    "type": "integer",
                                    "format": "int64",
                                    "minimum": 0
                                }
                            }
                        }
                    }
                })
            } else {
                serde_json::json!({ "type": "object" })
            };
            Mock::given(method("GET"))
                .and(path(format!(
                    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "CustomResourceDefinition",
                    "metadata": {
                        "name": name,
                        "annotations": {
                            "kobe.kunobi.ninja/agent-sandbox-owner": "test-ns/kobe",
                            "kobe.kunobi.ninja/agent-sandbox-manifest-sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    },
                    "spec": {
                        "group": group,
                        "names": {
                            "kind": kind,
                            "listKind": format!("{kind}List"),
                            "plural": plural,
                            "singular": plural.trim_end_matches('s')
                        },
                        "scope": "Namespaced",
                        "versions": [{
                            "name": "v1beta1",
                            "served": true,
                            "storage": true,
                            "schema": { "openAPIV3Schema": openapi }
                        }]
                    },
                    "status": {
                        "conditions": [{
                            "type": "Established",
                            "status": "True",
                            "reason": "Installed",
                            "message": "installed",
                            "lastTransitionTime": "2026-08-20T00:00:00Z"
                        }],
                        "storedVersions": ["v1beta1"]
                    }
                })))
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/agent-sandbox-system/deployments/agent-sandbox-controller",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "agent-sandbox-controller",
                    "namespace": "agent-sandbox-system",
                    "annotations": {
                        "kobe.kunobi.ninja/agent-sandbox-owner": "test-ns/kobe",
                        "kobe.kunobi.ninja/agent-sandbox-manifest-sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                },
                "spec": {
                    "selector": { "matchLabels": { "app": "agent-sandbox" } },
                    "template": {
                        "metadata": { "labels": { "app": "agent-sandbox" } },
                        "spec": { "containers": [{
                            "name": "agent-sandbox-controller",
                            "image": crate::sandbox_runtime::MANAGED_CONTROLLER_IMAGE
                        }] }
                    }
                }
            })))
            .mount(server)
            .await;
    }

    async fn test_context() -> (Arc<SandboxContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let ctx = Arc::new(SandboxContext {
            client: crate::testutil::mock_k8s_client(&server),
            namespace: NS.to_string(),
            reservation_namespace: NS.to_string(),
            shutdown: CancellationToken::new(),
            access_ledger_enabled: false,
            placement_enabled: true,
            runtime_mode: crate::sandbox_runtime::AgentSandboxMode::Managed,
            managed_runtime_identity: Some(test_managed_identity()),
        });
        mount_healthy_runtime(&server).await;
        let required_names = crate::sandbox_runtime::REQUIRED_AGENT_SANDBOX_CRDS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join("\n");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/bootstrapconfigs/kobe-agent-sandbox-v1-0-0",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "BootstrapConfig",
                "metadata": {
                    "name": "kobe-agent-sandbox-v1-0-0",
                    "namespace": NS,
                    "annotations": {
                        "kobe.kunobi.ninja/agent-sandbox-owner": "test-ns/kobe",
                        "kobe.kunobi.ninja/agent-sandbox-manifest-sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                },
                "spec": { "files": { "agent-sandbox-v1.0.0.yaml": format!(
                    "{}\n{}",
                    crate::sandbox_runtime::MANAGED_CONTROLLER_IMAGE,
                    required_names
                ) } }
            })))
            .mount(&server)
            .await;

        let pool = management_pool(POOL_UID, POOL_GENERATION);
        let owner = pool.controller_owner_ref(&()).unwrap();
        let mut template =
            build_sandbox_template("kobe-agents", NS, &pool.spec, Some(&owner)).unwrap();
        template.metadata.uid = Some("template-uid".into());
        template.metadata.generation = Some(1);
        let mut warm_pool = build_sandbox_warm_pool(
            "kobe-agents",
            NS,
            "kobe-agents",
            pool.spec.warm_capacity,
            Some(&owner),
        )
        .unwrap();
        warm_pool.metadata.uid = Some("warm-pool-uid".into());
        warm_pool.metadata.generation = Some(1);
        warm_pool.data["status"] = serde_json::json!({
            "observedGeneration": 1,
            "replicas": 0,
            "readyReplicas": 0,
            "selector": format!(
                "agents.x-k8s.io/warm-pool-sandbox={}",
                crate::controllers::sandbox_pool_certification::upstream_name_hash("kobe-agents")
            )
        });
        for (path_value, object) in [(TEMPLATE_PATH, template), (WARM_POOL_PATH, warm_pool)] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(200).set_body_json(object))
                .with_priority(10)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .with_priority(100)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(ALLOCATION_FENCE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .with_priority(100)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(NETWORK_POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "kobe-agents-network-policy",
                    "namespace": NS,
                    "uid": "network-policy-uid",
                    "ownerReferences": [{
                        "apiVersion": AGENT_SANDBOX_API_VERSION,
                        "kind": SANDBOX_TEMPLATE_KIND,
                        "name": "kobe-agents",
                        "uid": "template-uid",
                        "controller": true
                    }]
                },
                "spec": crate::controllers::sandbox_pool_certification::expected_network_policy_spec("kobe-agents")
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SANDBOXES_PATH))
            .and(query_param(
                "labelSelector",
                format!(
                    "agents.x-k8s.io/warm-pool-sandbox={}",
                    crate::controllers::sandbox_pool_certification::upstream_name_hash(
                        "kobe-agents"
                    )
                ),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "agents.x-k8s.io/v1beta1",
                "kind": "SandboxList",
                "metadata": {},
                "items": []
            })))
            .mount(&server)
            .await;
        (ctx, server)
    }

    #[tokio::test]
    async fn exact_child_runtime_receipt_skips_repeating_the_canary() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let owner = OwnerReference {
            api_version: "v1".into(),
            kind: "Namespace".into(),
            name: CHILD_SANDBOX_NAMESPACE.into(),
            uid: "child-namespace-uid".into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}/configmaps/{CHILD_RUNTIME_RECEIPT_NAME}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": CHILD_RUNTIME_RECEIPT_NAME,
                    "namespace": CHILD_SANDBOX_NAMESPACE,
                    "uid": "receipt-uid",
                    "resourceVersion": "1",
                    "ownerReferences": [{
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "name": CHILD_SANDBOX_NAMESPACE,
                        "uid": "child-namespace-uid",
                        "controller": true,
                        "blockOwnerDeletion": true
                    }]
                },
                "data": {
                    "phase": "Certified",
                    "instanceUid": "child-instance-uid",
                    "owner": "test-ns/kobe",
                    "manifestSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })))
            .mount(&server)
            .await;

        assert!(
            ensure_child_runtime_certified(
                &client,
                &owner,
                &management_pool(POOL_UID, POOL_GENERATION),
                "agents",
                "child-instance-uid",
                chrono::Utc::now() + chrono::Duration::minutes(5),
                &test_managed_identity(),
            )
            .await
            .expect("exact certification receipt")
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn child_runtime_receipt_becomes_certified_only_after_exact_absence() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let owner = OwnerReference {
            api_version: "v1".into(),
            kind: "Namespace".into(),
            name: CHILD_SANDBOX_NAMESPACE.into(),
            uid: "child-namespace-uid".into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let receipt = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": CHILD_RUNTIME_RECEIPT_NAME,
                "namespace": CHILD_SANDBOX_NAMESPACE,
                "uid": "receipt-uid",
                "resourceVersion": "1",
                "ownerReferences": [{
                    "apiVersion": "v1", "kind": "Namespace",
                    "name": CHILD_SANDBOX_NAMESPACE, "uid": "child-namespace-uid",
                    "controller": true, "blockOwnerDeletion": true
                }]
            },
            "data": {
                "phase": "Deleting",
                "instanceUid": "child-instance-uid",
                "owner": "test-ns/kobe",
                "manifestSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "claimUid": "claim-uid",
                "sandboxName": "runtime-sandbox",
                "sandboxUid": "sandbox-uid",
                "podName": "runtime-pod",
                "podUid": "pod-uid"
            }
        });
        let receipt_path = format!(
            "/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}/configmaps/{CHILD_RUNTIME_RECEIPT_NAME}"
        );
        Mock::given(method("GET"))
            .and(path(&receipt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&receipt))
            .mount(&server)
            .await;
        for missing_path in [
            format!(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{CHILD_SANDBOX_NAMESPACE}/sandboxclaims/{CHILD_RUNTIME_CANARY_NAME}"
            ),
            format!(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/{CHILD_SANDBOX_NAMESPACE}/sandboxes/runtime-sandbox"
            ),
            format!("/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}/pods/runtime-pod"),
        ] {
            Mock::given(method("GET"))
                .and(path(missing_path))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "code": 404, "reason": "NotFound"
                })))
                .mount(&server)
                .await;
        }
        Mock::given(method("PUT"))
            .and(path(&receipt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(receipt))
            .mount(&server)
            .await;

        assert!(
            !ensure_child_runtime_certified(
                &client,
                &owner,
                &management_pool(POOL_UID, POOL_GENERATION),
                "agents",
                "child-instance-uid",
                chrono::Utc::now() + chrono::Duration::minutes(5),
                &test_managed_identity(),
            )
            .await
            .expect("absence checkpoint")
        );
        let requests = server.received_requests().await.unwrap();
        let update: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "PUT")
                .expect("receipt certification update")
                .body,
        )
        .unwrap();
        assert_eq!(update["data"]["phase"], "Certified");
    }

    /// The outer freshness and full-capacity gates must stand down exactly
    /// while the certification protocol owns the WarmPool (fence installed
    /// through fence deletion) — the protocol drains and restores capacity
    /// itself, so enforcing "warm and observed" there starves its own arms.
    /// Entry, canary, terminal and blocked phases keep the strict gates.
    #[test]
    fn only_fence_to_unfence_phases_relax_the_outer_gates() {
        use crate::crd::sandbox::SandboxPoolCertificationPhase as Phase;
        for (phase, in_flight) in [
            (Phase::Initialized, false),
            (Phase::ClaimCreated, false),
            (Phase::WorkloadCaptured, false),
            (Phase::CanaryPassed, false),
            (Phase::FenceInstalled, true),
            (Phase::DrainAcknowledged, true),
            (Phase::ClaimDeleting, true),
            (Phase::AbsenceProven, true),
            (Phase::Replenished, true),
            (Phase::FenceFinalizerRemoved, true),
            (Phase::FenceDeleting, true),
            (Phase::Certified, false),
            (Phase::CleanupBlocked, false),
        ] {
            assert_eq!(
                super::certification_phase_is_in_flight(&phase),
                in_flight,
                "{phase:?}"
            );
        }
        let mut pool = management_pool("pool-uid", 1);
        assert!(!super::certification_protocol_in_flight(&pool));
        pool.status = None;
        assert!(!super::certification_protocol_in_flight(&pool));
    }

    fn quantity(cpu: &str, memory: &str, ephemeral_storage: &str) -> SandboxResourceQuantity {
        SandboxResourceQuantity {
            cpu: cpu.into(),
            memory: memory.into(),
            ephemeral_storage: ephemeral_storage.into(),
        }
    }

    pub(crate) fn management_pool(uid: &str, generation: i64) -> SandboxPool {
        let mut pool = SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                namespace: Some(NS.into()),
                uid: Some(uid.into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: SandboxPoolSpec {
                warm_capacity: 0,
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
                    attach_command: None,
                },
                isolation: SandboxIsolation::TrustedRunc {},
                readiness: SandboxReadinessRequirements {
                    canary: SandboxExecutionCanary {
                        argv: vec!["/agent".into(), "health".into()],
                        timeout: "30s".into(),
                    },
                },
            },
            status: Some(SandboxPoolStatus {
                observed_generation: Some(generation),
                ready: 0,
                allocated: 0,
                quarantined: 0,
                placement: None,
                placement_authority: None,
                certification: None,
                conditions: vec![SandboxCondition {
                    condition_type: POOL_READY_CONDITION.into(),
                    status: SandboxConditionStatus::True,
                    reason: "Certified".into(),
                    message: "test fixture represents a fully certified pool".into(),
                    observed_generation: Some(generation),
                    last_transition_time: Some("2026-08-20T00:00:00Z".into()),
                }],
            }),
        };
        let upstream = |kind: &str, object_uid: &str| DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: AGENT_SANDBOX_API_VERSION.into(),
                kind: kind.into(),
            }),
            metadata: ObjectMeta {
                name: Some("kobe-agents".into()),
                namespace: Some(NS.into()),
                uid: Some(object_uid.into()),
                generation: Some(1),
                ..ObjectMeta::default()
            },
            data: serde_json::json!({}),
        };
        let template = upstream(SANDBOX_TEMPLATE_KIND, "template-uid");
        let mut warm_pool = upstream(SANDBOX_WARM_POOL_KIND, "warm-pool-uid");
        warm_pool.data = serde_json::json!({
            "status": {
                "observedGeneration": 1,
                "replicas": 2,
                "readyReplicas": 2
            }
        });
        let reference = |api_version: &str,
                         kind: &str,
                         name: &str,
                         object_uid: &str,
                         object_generation: Option<i64>| {
            crate::crd::SandboxObjectReference {
                api_version: api_version.into(),
                kind: kind.into(),
                namespace: Some(NS.into()),
                name: name.into(),
                uid: object_uid.into(),
                generation: object_generation,
            }
        };
        let fingerprint =
            crate::controllers::sandbox_pool_certification::certification_fingerprint(
                &pool, &template, &warm_pool,
            )
            .unwrap();
        pool.status.as_mut().unwrap().certification =
            Some(crate::crd::SandboxPoolCertificationStatus {
                fingerprint,
                observed_generation: generation,
                phase: crate::crd::SandboxPoolCertificationPhase::Certified,
                sandbox_template: reference(
                    AGENT_SANDBOX_API_VERSION,
                    SANDBOX_TEMPLATE_KIND,
                    "kobe-agents",
                    "template-uid",
                    Some(1),
                ),
                sandbox_warm_pool: reference(
                    AGENT_SANDBOX_API_VERSION,
                    SANDBOX_WARM_POOL_KIND,
                    "kobe-agents",
                    "warm-pool-uid",
                    Some(1),
                ),
                sandbox_claim: Some(reference(
                    AGENT_SANDBOX_API_VERSION,
                    SANDBOX_CLAIM_KIND,
                    "kobe-cert",
                    "cert-claim-uid",
                    Some(1),
                )),
                sandbox: Some(reference(
                    crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                    crate::controllers::sandbox_canary::SANDBOX_KIND,
                    "cert-sandbox",
                    "cert-sandbox-uid",
                    Some(1),
                )),
                pod: Some(reference("v1", "Pod", "cert-pod", "cert-pod-uid", None)),
                service: None,
                persistent_volume_claims: vec![],
                persistent_volumes: vec![],
                teardown_fence: Some(reference(
                    "v1",
                    "ConfigMap",
                    "deleted-cert-fence",
                    "cert-fence-uid",
                    None,
                )),
                baseline_idle_sandbox_uids: vec!["retired-cert-sandbox-uid".into()],
                drain_generation: Some(1),
                replenish_generation: Some(1),
                canary_passed_at: Some("2026-08-20T00:00:00Z".into()),
                certified_at: Some("2026-08-20T00:01:00Z".into()),
                message: None,
            });
        pool
    }

    pub(crate) fn admitted_lease() -> SandboxLease {
        let created_at = chrono::Utc::now();
        let requester = SandboxPrincipal {
            provider: "oidc".into(),
            requester_type: "user".into(),
            issuer: "https://issuer.invalid".into(),
            identity: "alice".into(),
        };
        let reservation_name = crate::api::sandbox::quota_reservation_name(
            &crate::api::sandbox::principal_hash_for(&requester),
            0,
        );
        let reservation_provenance = serde_json::json!([{
            "kind": "quota",
            "name": reservation_name,
            "uid": "reservation-uid-1"
        }])
        .to_string();
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
                    [
                        (
                            SANDBOX_ADMISSION_ANNOTATION.to_string(),
                            SANDBOX_ADMISSION_ADMITTED.to_string(),
                        ),
                        (
                            crate::api::sandbox::SANDBOX_RESERVATIONS_ANNOTATION.to_string(),
                            reservation_provenance,
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
                finalizers: Some(vec![crate::sandbox::SANDBOX_LEASE_FINALIZER.to_string()]),
                ..Default::default()
            },
            spec: SandboxLeaseSpec {
                pool_ref: SandboxPoolReference {
                    name: "agents".into(),
                    uid: POOL_UID.into(),
                    generation: POOL_GENERATION,
                },
                placement_authority: None,
                ttl: "1h".into(),
                alias: None,
                requester,
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
                claim_cleanup_fence: Some(crate::crd::SandboxClaimCleanupFence::FinalizerV1),
                target: Some(crate::crd::SandboxTargetProvenance {
                    namespace: NS.into(),
                    child_cluster_lease: None,
                    child_cluster_instance: None,
                    child_cluster_kubeconfig_secret: None,
                    child_cluster_kubeconfig_sha256: None,
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
                    service: Some(reference("v1", "Service", "sandbox-service", "service-uid")),
                }),
                ..Default::default()
            }),
        }
    }

    /// Exact durable shape returned by successful admission before the first
    /// placement-controller pass.
    fn freshly_admitted_lease() -> SandboxLease {
        let mut lease = admitted_lease();
        let provisioning_deadline = lease
            .status
            .as_ref()
            .and_then(|status| status.provisioning_deadline.clone());
        lease.status = Some(SandboxLeaseStatus {
            phase: crate::crd::SandboxLeasePhase::Pending,
            provisioning_deadline,
            ..Default::default()
        });
        lease
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
                "labels": {
                    "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                    "kobe.kunobi.ninja/sandbox-lease-uid": "lease-uid-1",
                },
                "finalizers": [crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER],
            },
            "spec": {
                "warmPoolRef": { "name": "kobe-agents" },
                "lifecycle": {
                    "shutdownTime": "2026-08-20T00:10:00Z",
                    "shutdownPolicy": "DeleteForeground"
                }
            },
            "status": status,
        })
    }

    /// Byte-for-byte ownership/finalizer shape emitted by the base management
    /// Claim producer before the cleanup-fence protocol.
    fn base_legacy_claim_json(status: serde_json::Value) -> serde_json::Value {
        let mut claim = claim_json(status);
        claim["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("finalizers");
        claim["metadata"]["ownerReferences"] = serde_json::json!([{
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxLease",
            "name": LEASE,
            "uid": "lease-uid-1",
            "controller": true,
        }]);
        claim["spec"]["lifecycle"] = serde_json::json!({
            "shutdownPolicy": "DeleteForeground"
        });
        claim
    }

    fn tombstone_claim_json(uid: &str, prior_claim_uid: Option<&str>) -> serde_json::Value {
        let mut claim = claim_json(serde_json::json!({}));
        claim["metadata"]["uid"] = uid.into();
        claim["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_CLAIM_TOMBSTONE_RETAIN_UNTIL_ANNOTATION:
                (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION: LEASE
        });
        claim["metadata"]["labels"][SANDBOX_CLAIM_TOMBSTONE_LABEL] = "true".into();
        if let Some(prior_claim_uid) = prior_claim_uid {
            claim["metadata"]["labels"][SANDBOX_CLAIM_TOMBSTONE_PRIOR_UID_LABEL] =
                prior_claim_uid.into();
        }
        claim["spec"] = serde_json::json!({
            "warmPoolRef": { "name": "kobe-agents" },
            "lifecycle": {
                "shutdownTime": (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
                "shutdownPolicy": "Retain"
            }
        });
        claim
    }

    async fn mount_resolved_sandbox(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(SANDBOX_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                "metadata": {
                    "name": "sbx", "namespace": NS, "uid": "sandbox-uid",
                    "ownerReferences": [{
                        "apiVersion": AGENT_SANDBOX_API_VERSION,
                        "kind": SANDBOX_CLAIM_KIND,
                        "name": "kobe-sbx-1",
                        "uid": "claim-uid",
                        "controller": true,
                    }],
                },
                "status": {
                    "selector": "kobe.test/sandbox=sbx",
                    "service": "sandbox-service",
                },
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVICE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": "sandbox-service", "namespace": NS, "uid": "service-uid",
                    "ownerReferences": [{
                        "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                        "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                        "name": "sbx",
                        "uid": "sandbox-uid",
                        "controller": true,
                    }],
                },
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
                    "metadata": {
                        "name": "sandbox-pod", "namespace": NS, "uid": "pod-uid",
                        "ownerReferences": [{
                            "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                            "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                            "name": "sbx",
                            "uid": "sandbox-uid",
                            "controller": true,
                        }],
                    },
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

    /// `admitted` without the exact persisted gate is a durable record, not
    /// workload authority. The controller must quarantine it before even
    /// resolving the pool, so no Claim or other footprint can be created.
    #[tokio::test]
    async fn missing_admitted_gate_quarantines_before_any_footprint_request() {
        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .expect(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));

        let requests = server.received_requests().await.unwrap_or_default();
        let quarantine = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("durable quarantine checkpoint");
        let status = status_value_of(quarantine).unwrap();
        assert_eq!(status["phase"], "Quarantined");
        assert!(
            status["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["reason"] == "access_gate_unverifiable"
                        && condition["status"] == "False"
                })
        );

        for forbidden in [
            POOL_PATH,
            CLAIMS_PATH,
            CLAIM_PATH,
            TEMPLATE_PATH,
            WARM_POOL_PATH,
            SANDBOX_PATH,
            PODS_PATH,
            SERVICE_PATH,
        ] {
            assert!(
                requests
                    .iter()
                    .all(|request| request.url.path() != forbidden),
                "gate failure must happen before touching {forbidden}"
            );
        }
    }

    /// A child namespace is adopted only when its cross-cluster lease UID
    /// fence matches; a same-named namespace is not authority.
    #[tokio::test]
    async fn child_namespace_is_created_with_exact_lease_identity() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-sandbox"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/namespaces"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "kobe-sandbox",
                    "uid": "namespace-uid",
                    "labels": {
                        "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                        "kobe.kunobi.ninja/sandbox-lease-uid": "lease-uid",
                    },
                    "annotations": {
                        "kobe.kunobi.ninja/sandbox-lease-name": "lease-name",
                    },
                },
            })))
            .mount(&server)
            .await;

        let namespace = ensure_child_namespace(&client, "lease-name", "lease-uid")
            .await
            .expect("the exact namespace must be created");
        let owner = namespace
            .controller_owner_ref(&())
            .expect("the namespace UID is an owner fence");
        assert_eq!(owner.kind, "Namespace");
        assert_eq!(owner.uid, "namespace-uid");
    }

    /// A same-named namespace from another composition is never patched or
    /// adopted into this child placement.
    #[tokio::test]
    async fn foreign_child_namespace_is_rejected_without_mutation() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-sandbox"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "kobe-sandbox",
                    "uid": "foreign-namespace-uid",
                    "labels": {
                        "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                        "kobe.kunobi.ninja/sandbox-lease-uid": "foreign-lease-uid",
                    },
                    "annotations": {
                        "kobe.kunobi.ninja/sandbox-lease-name": "lease-name",
                    },
                },
            })))
            .mount(&server)
            .await;

        assert!(matches!(
            ensure_child_namespace(&client, "lease-name", "lease-uid").await,
            Err(SandboxPlacementError::Invalid(_))
        ));
        assert_eq!(requests_to(&server, "POST", "/api/v1/namespaces").await, 0);
        assert_eq!(
            requests_to(&server, "PATCH", "/api/v1/namespaces/kobe-sandbox").await,
            0
        );
    }

    /// Force-SSA corrects drift only after an exact owner read and carries the
    /// read resourceVersion as a replacement-race precondition.
    #[tokio::test]
    async fn upstream_apply_is_owner_and_resource_version_fenced() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let owner = OwnerReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "SandboxPool".into(),
            name: "agents".into(),
            uid: POOL_UID.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let desired = build_sandbox_template(
            "kobe-agents",
            NS,
            &management_pool(POOL_UID, POOL_GENERATION).spec,
            Some(&owner),
        )
        .unwrap();
        Mock::given(method("GET"))
            .and(path(TEMPLATE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": SANDBOX_TEMPLATE_KIND,
                "metadata": {
                    "name": "kobe-agents", "namespace": NS,
                    "uid": "template-uid", "resourceVersion": "7",
                    "ownerReferences": [{
                        "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                        "kind": "SandboxPool", "name": "agents",
                        "uid": POOL_UID, "controller": true,
                    }],
                },
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(TEMPLATE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": SANDBOX_TEMPLATE_KIND,
                "metadata": {
                    "name": "kobe-agents", "namespace": NS,
                    "uid": "template-uid", "resourceVersion": "8",
                    "ownerReferences": [{
                        "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                        "kind": "SandboxPool", "name": "agents",
                        "uid": POOL_UID, "controller": true,
                    }],
                },
            })))
            .mount(&server)
            .await;

        apply_upstream(
            &client,
            NS,
            &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
            &desired,
            &owner,
        )
        .await
        .unwrap();
        let requests = server.received_requests().await.unwrap_or_default();
        let patch: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "PATCH")
                .expect("the owned object is updated")
                .body,
        )
        .unwrap();
        assert_eq!(patch["metadata"]["resourceVersion"], "7");
    }

    /// A foreign upstream object is rejected before force-SSA can seize its
    /// fields or owner reference.
    #[tokio::test]
    async fn foreign_upstream_object_is_never_force_applied() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let owner = OwnerReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "SandboxPool".into(),
            name: "agents".into(),
            uid: POOL_UID.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let desired = build_sandbox_template(
            "kobe-agents",
            NS,
            &management_pool(POOL_UID, POOL_GENERATION).spec,
            Some(&owner),
        )
        .unwrap();
        Mock::given(method("GET"))
            .and(path(TEMPLATE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": SANDBOX_TEMPLATE_KIND,
                "metadata": {
                    "name": "kobe-agents", "namespace": NS,
                    "uid": "foreign-template-uid", "resourceVersion": "7",
                    "ownerReferences": [{
                        "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                        "kind": "SandboxPool", "name": "agents",
                        "uid": "foreign-pool-uid", "controller": true,
                    }],
                },
            })))
            .mount(&server)
            .await;

        assert!(matches!(
            apply_upstream(
                &client,
                NS,
                &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
                &desired,
                &owner,
            )
            .await,
            Err(SandboxPlacementError::Invalid(_))
        ));
        assert_eq!(requests_to(&server, "PATCH", TEMPLATE_PATH).await, 0);
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

    /// Pool status is an exact observation, not an optimistic capacity hint.
    /// The controller must count only admitted exact-UID leases, observe the
    /// exact-owned WarmPool, and still withhold Ready until certification is
    /// implemented. The status write itself must be fenced to the Pool object
    /// version that produced those observations.
    #[tokio::test]
    async fn pool_status_counts_exact_uid_and_withholds_uncertified_readiness() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let ctx = Arc::new(SandboxContext {
            client: crate::testutil::mock_k8s_client(&server),
            namespace: NS.into(),
            reservation_namespace: NS.into(),
            shutdown: CancellationToken::new(),
            access_ledger_enabled: false,
            placement_enabled: true,
            runtime_mode: crate::sandbox_runtime::AgentSandboxMode::External,
            managed_runtime_identity: None,
        });

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.warm_capacity = 2;
        let pool_owner = pool.controller_owner_ref(&()).unwrap();
        let upstream = |kind: &str, uid: &str, resource_version: &str, spec, status| {
            serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": kind,
                "metadata": {
                    "name": "kobe-agents",
                    "namespace": NS,
                    "uid": uid,
                    "resourceVersion": resource_version,
                    "generation": 1,
                    "ownerReferences": [{
                        "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                        "kind": "SandboxPool",
                        "name": "agents",
                        "uid": POOL_UID,
                        "controller": true
                    }]
                },
                "spec": spec,
                "status": status
            })
        };
        let template = upstream(
            SANDBOX_TEMPLATE_KIND,
            "template-uid",
            "template-rv",
            build_sandbox_template("kobe-agents", NS, &pool.spec, Some(&pool_owner))
                .unwrap()
                .data
                .get("spec")
                .cloned()
                .unwrap(),
            serde_json::json!({}),
        );
        let warm_pool = upstream(
            SANDBOX_WARM_POOL_KIND,
            "warm-pool-uid",
            "warm-pool-rv",
            build_sandbox_warm_pool(
                "kobe-agents",
                NS,
                "kobe-agents",
                pool.spec.warm_capacity,
                Some(&pool_owner),
            )
            .unwrap()
            .data
            .get("spec")
            .cloned()
            .unwrap(),
            serde_json::json!({ "replicas": 2, "readyReplicas": 1, "observedGeneration": 1 }),
        );
        for (target, body) in [(TEMPLATE_PATH, template), (WARM_POOL_PATH, warm_pool)] {
            Mock::given(method("GET"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .mount(&server)
                .await;
            Mock::given(method("PATCH"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }

        let counted = |name: &str, phase: SandboxLeasePhase, uid: &str, admitted: bool| {
            let mut lease = admitted_lease();
            lease.metadata.name = Some(name.into());
            lease.metadata.uid = Some(format!("{name}-uid"));
            lease.spec.pool_ref.uid = uid.into();
            lease.status.as_mut().unwrap().phase = phase;
            if !admitted {
                lease.metadata.annotations.as_mut().unwrap().insert(
                    SANDBOX_ADMISSION_ANNOTATION.into(),
                    crate::api::sandbox::SANDBOX_ADMISSION_PENDING.into(),
                );
            }
            lease
        };
        let leases = vec![
            counted("ready", SandboxLeasePhase::Ready, POOL_UID, true),
            counted(
                "quarantined",
                SandboxLeasePhase::Quarantined,
                POOL_UID,
                true,
            ),
            counted("released", SandboxLeasePhase::Released, POOL_UID, true),
            counted(
                "replacement",
                SandboxLeasePhase::Ready,
                "replacement-pool-uid",
                true,
            ),
            counted(
                "pending-admission",
                SandboxLeasePhase::Ready,
                POOL_UID,
                false,
            ),
        ];
        Mock::given(method("GET"))
            .and(path(LEASES_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(leases)),
            )
            .mount(&server)
            .await;

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.warm_capacity = 2;
        pool.metadata.resource_version = Some("pool-rv".into());
        Mock::given(method("PATCH"))
            .and(path(POOL_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool.clone()))
            .mount(&server)
            .await;

        reconcile_pool(Arc::new(pool), ctx).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == POOL_STATUS_PATH
            })
            .expect("pool status must be written");
        let patch: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(patch[0]["path"], "/metadata/uid");
        assert_eq!(patch[0]["value"], POOL_UID);
        assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
        assert_eq!(patch[1]["value"], "pool-rv");
        let status = status_value_of(request).expect("status operation");
        assert_eq!(status["observedGeneration"], POOL_GENERATION);
        assert_eq!(status["ready"], 1);
        assert_eq!(status["allocated"], 2);
        assert_eq!(status["quarantined"], 1);
        assert_eq!(status["conditions"][0]["type"], POOL_READY_CONDITION);
        assert_eq!(status["conditions"][0]["status"], "False");
        assert_eq!(
            status["conditions"][0]["reason"],
            POOL_CERTIFICATION_PENDING_REASON
        );
        assert_eq!(
            status["conditions"][0]["observedGeneration"],
            POOL_GENERATION
        );
        assert!(
            status["conditions"][0]["message"]
                .as_str()
                .unwrap()
                .contains("replicas=2/readyReplicas=1")
        );
    }

    /// Child discovery publishes exact authority without claiming readiness.
    #[tokio::test]
    async fn child_pool_status_records_exact_cluster_pool_authority_fail_closed() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(LEASES_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<SandboxLease>::new()),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CHILD_POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child_cluster_pool_json()))
            .mount(&server)
            .await;

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.placement = serde_json::from_value(serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "children"
        }))
        .unwrap();
        pool.metadata.resource_version = Some("pool-rv".into());
        Mock::given(method("PATCH"))
            .and(path(POOL_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&pool))
            .mount(&server)
            .await;

        reconcile_pool(Arc::new(pool), ctx).await.unwrap();

        let requests = server.received_requests().await.unwrap_or_default();
        let status = requests
            .iter()
            .find_map(|request| {
                (request.method.as_str() == "PATCH" && request.url.path() == POOL_STATUS_PATH)
                    .then(|| status_value_of(request))
                    .flatten()
            })
            .expect("child pool status checkpoint");
        assert_eq!(status["conditions"][0]["status"], "False");
        assert_eq!(status["conditions"][0]["reason"], "CompositionEligible");
        assert_eq!(status["ready"], 0);
        assert_eq!(
            status["placementAuthority"],
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "namespace": NS,
                "name": "children",
                "uid": "cluster-pool-uid",
                "generation": 1
            })
        );
    }

    /// A Ready pool can lose certification while a reconcile is preparing a
    /// Claim. The second strong Pool GET is the last remote operation before
    /// POST and must catch that flip instead of relying on the earlier read.
    #[tokio::test]
    async fn pre_claim_gate_catches_readiness_revoked_after_initial_pool_read() {
        let (ctx, server) = test_context().await;
        let ready = serde_json::to_value(management_pool(POOL_UID, POOL_GENERATION)).unwrap();
        let mut revoked = ready.clone();
        revoked["status"]["conditions"][0]["status"] = serde_json::json!("False");
        revoked["status"]["conditions"][0]["reason"] =
            serde_json::json!(POOL_CERTIFICATION_PENDING_REASON);
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let response_reads = Arc::clone(&reads);
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(move |_: &wiremock::Request| {
                let body = if response_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                {
                    ready.clone()
                } else {
                    revoked.clone()
                };
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        let target = lease
            .status
            .as_mut()
            .and_then(|status| status.target.as_mut())
            .unwrap();
        target.sandbox_claim = None;
        target.sandbox = None;
        target.pod = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            requests_to(&server, "POST", CLAIMS_PATH).await,
            0,
            "revoked certification must stop the final Claim create"
        );
    }

    #[test]
    fn chart_grants_pool_status_without_pool_spec_mutation() {
        let chart = include_str!("../../charts/kobe/templates/rbac.yaml");
        assert!(chart.contains(
            "resources: [\"sandboxpools/status\"]\n    verbs: [\"get\", \"patch\", \"update\"]"
        ));
        assert!(
            chart.contains(
                "resources: [\"sandboxpools\"]\n    verbs: [\"get\", \"list\", \"watch\"]"
            )
        );
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

    /// Without a resolved placement, even a foreign same-named child handle
    /// selects the conservative child path. Its label is rejected there; it
    /// must never let a management Claim 404 release capacity.
    #[tokio::test]
    async fn unresolved_foreign_child_artifact_fails_closed() {
        let (ctx, server) = test_context().await;
        let mut foreign = child_cluster_lease("foreign-child-uid", "Pending", None);
        foreign["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL] =
            "foreign-outer-uid".into();
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(foreign))
            .mount(&server)
            .await;

        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().placement = None;
        lease.status.as_mut().unwrap().target = None;
        assert!(is_child_placed(&lease, &ctx).await);
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

    /// A controller upgrade can observe the base Claim after its CREATE but
    /// before any new cleanup checkpoint exists. The exact legacy owner and
    /// cleanup finalizer are migrated in one UID/resourceVersion-fenced patch;
    /// the pass ends before status claims the new invariant or uses the Claim.
    #[tokio::test]
    async fn legacy_management_claim_is_atomically_fenced_before_use() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().claim_cleanup_fence = None;
        let provisioning_deadline = lease
            .status
            .as_ref()
            .and_then(|status| status.provisioning_deadline.clone())
            .expect("admission persists the provisioning deadline");
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;

        let legacy = base_legacy_claim_json(serde_json::json!({
            "conditions": [{ "type": "Ready", "status": "False" }]
        }));
        let mut migrated = legacy.clone();
        migrated["metadata"]["resourceVersion"] = "claim-rv-2".into();
        migrated["metadata"]["ownerReferences"] = serde_json::json!([]);
        migrated["metadata"]["finalizers"] =
            serde_json::json!([crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER]);
        migrated["spec"]["lifecycle"] = serde_json::json!({
            "shutdownTime": provisioning_deadline,
            "shutdownPolicy": "DeleteForeground"
        });
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&legacy))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&migrated))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&migrated))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .mount(&server)
            .await;

        let first = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(first, Action::await_change());
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 1);
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 0);
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);

        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH" && request.url.path() == CLAIM_PATH)
            .expect("legacy Claim migration patch");
        let operations: Vec<serde_json::Value> = serde_json::from_slice(&request.body).unwrap();
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/uid"
                && operation["value"] == "claim-uid"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/spec/lifecycle"
                && operation["value"]["shutdownTime"] == provisioning_deadline
                && operation["value"]["shutdownPolicy"] == "DeleteForeground"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "77"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/metadata/ownerReferences"
                && operation["value"] == serde_json::json!([])
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/metadata/finalizers"
                && operation["value"].as_array().is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
                })
        }));

        let second = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(second, Action::await_change());
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 1);
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 1);
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("cleanup-fence status checkpoint");
        assert_eq!(status["claimCleanupFence"], "FinalizerV1");
    }

    /// Metadata migration of an already-Ready legacy Claim must not shorten
    /// its runtime lease back to the earlier provisioning deadline.
    #[test]
    fn ready_legacy_claim_migration_preserves_valid_runtime_expiry() {
        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.ready_at = Some("2026-08-20T01:00:00Z".into());
        status.expires_at = Some("2026-08-20T02:00:00Z".into());
        let mut claim = base_legacy_claim_json(serde_json::json!({}));
        claim["spec"]["lifecycle"] = serde_json::json!({
            "shutdownTime": "2026-08-20T03:00:00Z",
            "shutdownPolicy": "DeleteForeground"
        });
        let claim: DynamicObject = serde_json::from_value(claim).unwrap();

        assert_eq!(
            management_claim_lifecycle_patch(&claim, &lease).unwrap(),
            None
        );
    }

    /// A DELETE accepted against the old active Claim UID must remain blocked
    /// while that same object is converted into the retained tombstone.
    #[tokio::test]
    async fn queued_old_claim_delete_keeps_the_tombstone_name_occupied() {
        let (ctx, server) = test_context().await;
        let mut deleting = claim_json(serde_json::json!({}));
        deleting["metadata"]["deletionTimestamp"] = "2026-08-20T00:05:00Z".into();
        let deleting: DynamicObject = serde_json::from_value(deleting).unwrap();
        let converted = tombstone_claim_json("claim-uid", Some("claim-uid"));
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(converted))
            .expect(1)
            .mount(&server)
            .await;
        let claims: Api<DynamicObject> = Api::namespaced_with(
            ctx.client.clone(),
            NS,
            &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
        );

        assert!(
            patch_management_claim_tombstone(
                &claims,
                &deleting,
                &releasing_lease(crate::crd::SandboxLeasePhase::Releasing),
                Some("claim-uid"),
                chrono::Utc::now(),
            )
            .await
            .unwrap()
        );
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH" && request.url.path() == CLAIM_PATH)
            .expect("tombstone conversion patch");
        let operations: Vec<serde_json::Value> = serde_json::from_slice(&request.body).unwrap();
        let finalizers = operations
            .iter()
            .find(|operation| operation["path"] == "/metadata/finalizers")
            .expect("conversion retains finalizers");
        assert!(finalizers["value"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value == crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER)
        }));

        let fresh = build_management_claim_tombstone(
            &releasing_lease(crate::crd::SandboxLeasePhase::Releasing),
            NS,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(sandbox_claim_cleanup_finalizer_present(&fresh));
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

    /// Child allocation persists the exact handle before binding can block.
    /// The handle itself has no ownerRef, so the outer finalizer—not GC—owns
    /// the receipt lifecycle.
    #[tokio::test]
    async fn child_handle_identity_is_checkpointed_before_binding() {
        const CHILD_POOL_PATH: &str =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool";
        const CLUSTER_LEASES_PATH: &str =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases";
        let (ctx, server) = test_context().await;
        let cluster_pool: crate::crd::ClusterPool = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "child-pool",
                "namespace": NS,
                "uid": "child-pool-uid",
                "generation": 1,
            },
            "spec": {
                "ttl": "9h",
                "backend": { "type": "k3s" },
                "cluster": { "version": "v1.32.0" },
            },
            "status": {
                "phase": "Idle",
                "quarantined": 0,
                "unhealthy": 0,
            },
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(CHILD_POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cluster_pool))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.placement = serde_json::from_value(serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "child-pool"
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&pool))
            .mount(&server)
            .await;
        let mut lease = admitted_lease();
        lease.spec.placement_authority = Some(crate::crd::SandboxPlacementAuthority {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterPool".into(),
            namespace: NS.into(),
            name: "child-pool".into(),
            uid: "child-pool-uid".into(),
            generation: 1,
        });
        lease.status.as_mut().unwrap().placement = None;
        lease.status.as_mut().unwrap().target = None;
        Mock::given(method("GET"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .with_priority(1)
            .mount(&server)
            .await;
        let lifetime = crate::controllers::sandbox_child::required_child_lifetime(
            std::time::Duration::from_secs(600),
            std::time::Duration::from_secs(3600),
            crate::controllers::sandbox_child::CHILD_DRAIN_GRACE,
        );
        let mut created = crate::controllers::sandbox_child::build_internal_cluster_lease(
            &lease,
            "child-pool",
            lifetime,
        )
        .unwrap();
        created.metadata.uid = Some("child-lease-uid".into());
        created.metadata.generation = Some(1);
        created.metadata.resource_version = Some("child-rv-1".into());
        Mock::given(method("POST"))
            .and(path(CLUSTER_LEASES_PATH))
            .respond_with(ResponseTemplate::new(201).set_body_json(&created))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;

        let outcome = compose_child_target(&lease, &pool, "child-pool", &ctx)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ChildTarget::Pending(action) if action == Action::await_change())
        );

        let requests = server.received_requests().await.unwrap_or_default();
        let create: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| {
                    request.method.as_str() == "POST" && request.url.path() == CLUSTER_LEASES_PATH
                })
                .expect("internal lease create")
                .body,
        )
        .unwrap();
        assert!(create["metadata"].get("ownerReferences").is_none());
        assert_eq!(
            create["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL],
            "lease-uid-1"
        );
        let checkpoint = requests
            .iter()
            .filter_map(status_value_of)
            .next_back()
            .expect("pre-binding identity checkpoint");
        assert_eq!(checkpoint["placement"]["type"], "childCluster");
        assert_eq!(
            checkpoint["target"]["childClusterLease"]["uid"],
            "child-lease-uid"
        );
    }

    /// Reusing the configured ClusterPool name after admission must fail before
    /// the internal ClusterLease CREATE, even if the replacement is eligible.
    #[tokio::test]
    async fn child_pool_name_reuse_is_refused_by_the_final_pre_post_get() {
        const CLUSTER_LEASES_PATH: &str =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases";
        let (ctx, server) = test_context().await;
        let mut original = child_cluster_pool_json();
        original["metadata"]["name"] = "child-pool".into();
        original["metadata"]["uid"] = "child-pool-uid".into();
        let mut replacement = original.clone();
        replacement["metadata"]["uid"] = "replacement-pool-uid".into();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let response_reads = Arc::clone(&reads);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let body = if response_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                {
                    original.clone()
                } else {
                    replacement.clone()
                };
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.placement = serde_json::from_value(serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "child-pool"
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&pool))
            .mount(&server)
            .await;
        let mut lease = admitted_lease();
        lease.spec.placement_authority =
            Some(child_placement_authority("child-pool", "child-pool-uid", 1));
        lease.status.as_mut().unwrap().placement = None;
        lease.status.as_mut().unwrap().target = None;
        Mock::given(method("GET"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .with_priority(1)
            .mount(&server)
            .await;

        let error = match compose_child_target(&lease, &pool, "child-pool", &ctx).await {
            Err(error) => error,
            Ok(_) => panic!("same-named replacement must not compose"),
        };
        assert!(error.to_string().contains("changed identity"));
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(requests_to(&server, "POST", CLUSTER_LEASES_PATH).await, 0);
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
        let requests = server.received_requests().await.unwrap_or_default();
        let created: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| {
                    request.method.as_str() == "POST" && request.url.path() == CLAIMS_PATH
                })
                .expect("management claim create attempt")
                .body,
        )
        .unwrap();
        assert!(
            created["metadata"].get("ownerReferences").is_none(),
            "management claim cleanup must be explicit under the outer finalizer"
        );
        assert_eq!(
            created["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL],
            "lease-uid-1"
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
        target.service = None;

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
        assert_eq!(status["target"]["service"]["uid"], "service-uid");
    }

    /// Exposed ports create a Service, so Ready must checkpoint that exact UID.
    #[test]
    fn exposed_ports_require_service_provenance_before_ready() {
        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.target.as_mut().unwrap().service = None;

        assert!(workload_provenance_is_complete(status, false));
        assert!(!workload_provenance_is_complete(status, true));

        status.target.as_mut().unwrap().service = Some(crate::crd::SandboxObjectReference {
            api_version: "v1".into(),
            kind: "Service".into(),
            namespace: Some(NS.into()),
            name: "sandbox-service".into(),
            uid: "service-uid".into(),
            generation: None,
        });
        assert!(workload_provenance_is_complete(status, true));
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
    /// become unverifiable. A terminal object still carrying Kobe's finalizer
    /// is periodically revisited for proof/operator recovery, but it must never
    /// fall through into placement.
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
            assert_eq!(
                action,
                Action::requeue(std::time::Duration::from_secs(300)),
                "terminal phase {phase}"
            );
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
        Mock::given(method("GET"))
            .and(path(ALLOCATION_FENCE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .with_priority(1)
            .mount(&server)
            .await;
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
            ("lease-rv-5", "claim cleanup fence"),
            ("lease-rv-6", "claim provenance"),
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
        lease.metadata.resource_version = Some("lease-rv-7".into());
        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(
            action,
            Action::await_change(),
            "target provenance checkpoint"
        );
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-8").await;

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

    /// Only a clean terminal checkpoint permits Kobe's finalizer to leave,
    /// and another controller's finalizer is preserved byte-for-byte.
    #[tokio::test]
    async fn verified_terminal_removes_only_the_sandbox_finalizer() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        let mut status = lease.status.clone().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Released;
        status.conditions = with_condition_for_status(
            &status,
            lease.metadata.generation,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "gone",
        );
        status.conditions = with_condition_for_status(
            &status,
            lease.metadata.generation,
            CLEANUP_VERIFIED_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "TeardownVerified",
            "clean",
        );
        lease.status = Some(status);
        lease.metadata.finalizers = Some(vec![
            "another.example/finalizer".into(),
            crate::sandbox::SANDBOX_LEASE_FINALIZER.into(),
        ]);

        Mock::given(method("PATCH"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.clone()))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH" && request.url.path() == LEASE_PATH)
            .expect("finalizer patch");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!([
                { "op": "test", "path": "/metadata/uid", "value": "lease-uid-1" },
                { "op": "test", "path": "/metadata/resourceVersion", "value": "lease-rv-1" },
                { "op": "add", "path": "/metadata/finalizers", "value": ["another.example/finalizer"] }
            ])
        );
    }

    /// Quarantine is uncertainty, not cleanup proof. It must keep Kobe's
    /// finalizer even when Kubernetes deletion is already waiting on it.
    #[tokio::test]
    async fn quarantined_lease_retains_its_cleanup_finalizer() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        lease.status.as_mut().unwrap().phase = crate::crd::SandboxLeasePhase::Quarantined;
        lease.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            ));

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(300))
        );
        assert_eq!(requests_to(&server, "PATCH", LEASE_PATH).await, 0);
    }

    /// Quarantine is a durable evidence hold, not a permanent lifecycle tomb.
    /// Once the same exact footprint becomes provably clean, a retry must pass
    /// through Releasing again, return quota, reach the original cause's clean
    /// terminal phase, and only then remove Kobe's finalizer.
    #[tokio::test]
    async fn remediated_quarantine_releases_only_after_fresh_proof() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("PATCH"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(admitted_lease()))
            .expect(1)
            .mount(&server)
            .await;

        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Quarantined);

        assert_eq!(
            reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .unwrap(),
            Action::await_change(),
            "the retry first re-enters Releasing under the lease fence"
        );
        assert_eq!(recorded_phases(&server).await, vec!["Releasing"]);
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-releasing").await;

        assert_eq!(
            reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .unwrap(),
            Action::await_change(),
            "fresh footprint absence is a second durable checkpoint"
        );
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-proof").await;
        assert!(footprint_absence_proven(lease.status.as_ref().unwrap()));
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "proof and quota release cannot happen in the same pass"
        );

        assert_eq!(
            reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .unwrap(),
            Action::await_change()
        );
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-terminal").await;
        assert_eq!(
            lease.status.as_ref().unwrap().phase,
            crate::crd::SandboxLeasePhase::Released
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

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(requests_to(&server, "PATCH", LEASE_PATH).await, 1);
    }

    /// Legacy admitted objects are fenced with the cleanup finalizer before
    /// the controller reads a pool or creates any upstream object.
    #[tokio::test]
    async fn a_missing_cleanup_finalizer_is_backfilled_before_placement() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        lease.metadata.finalizers = Some(vec!["another.example/finalizer".into()]);
        Mock::given(method("PATCH"))
            .and(path(LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.clone()))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(requests_to(&server, "GET", POOL_PATH).await, 0);
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH" && request.url.path() == LEASE_PATH)
            .expect("finalizer patch");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body[2]["value"],
            serde_json::json!([
                "another.example/finalizer",
                crate::sandbox::SANDBOX_LEASE_FINALIZER
            ])
        );
    }

    /// deletionTimestamp is itself a server-owned release request. The
    /// Releasing+cause checkpoint must precede every teardown side effect.
    #[tokio::test]
    async fn direct_delete_checkpoints_requested_release_without_an_annotation() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Ready;
        status.ready_at = Some(chrono::Utc::now().to_rfc3339());
        status.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        lease.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            ));
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.clone()))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("Releasing checkpoint");
        let status = status_value_of(&request).unwrap();
        assert_eq!(status["phase"], "Releasing");
        assert_eq!(status["releaseCause"], "Requested");
    }

    /// Disabled mode is cleanup-only, not controller-off. It atomically
    /// checkpoints a distinct drain cause before reading a pool or touching a
    /// Claim, so an External -> Disabled rollout cannot strand an admitted
    /// finalizer or accidentally continue placement.
    #[tokio::test]
    async fn disabled_mode_drains_admitted_lease_before_any_placement() {
        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().placement_enabled = false;
        let lease = admitted_lease();
        Mock::given(method("PATCH"))
            .and(path(LEASE_STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.clone()))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(requests_to(&server, "GET", POOL_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "POST", CLAIMS_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", ALLOCATION_FENCE_PATH).await, 0);
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
            })
            .expect("cleanup-only Releasing checkpoint");
        let status = status_value_of(&request).unwrap();
        assert_eq!(status["phase"], "Releasing");
        assert_eq!(status["releaseCause"], "ModeDisabled");
    }

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
        if matches!(
            phase,
            crate::crd::SandboxLeasePhase::Releasing | crate::crd::SandboxLeasePhase::Quarantined
        ) {
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        }
        status.sandbox_claim_tombstone = status
            .target
            .as_ref()
            .and_then(|target| target.sandbox_claim.clone());
        status.allocation_fence = Some(crate::crd::SandboxObjectReference {
            api_version: "coordination.k8s.io/v1".into(),
            kind: "Lease".into(),
            namespace: Some(NS.into()),
            name: allocation_fence_name(LEASE),
            uid: "allocation-fence-uid".into(),
            generation: None,
        });
        lease
    }

    /// The distributed gate is a durable teardown checkpoint: admission has
    /// already created it open, and the pass that closes it must stop before
    /// credentials, Claims, or reservations are touched. The next pass is the
    /// first one allowed to observe it empty.
    #[tokio::test]
    async fn release_checkpoints_a_closed_access_gate_before_teardown() {
        use sha2::{Digest, Sha256};

        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let lease_uid = lease.uid().unwrap();
        let gate = format!(
            "kobe-access-g-{}",
            &format!("{:x}", Sha256::digest(lease_uid.as_bytes()))[..40]
        );
        lease.metadata.annotations.as_mut().unwrap().insert(
            crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION.into(),
            crate::sandbox_access_ledger::encode_gate_reference(
                &crate::sandbox_access_ledger::AccessGateReference {
                    name: gate.clone(),
                    uid: "access-gate-uid".into(),
                },
            )
            .unwrap(),
        );
        let gate_path = format!("{RESERVATIONS_PATH}/{gate}");
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {
                    "name": gate,
                    "namespace": NS,
                    "uid": "access-gate-uid",
                    "resourceVersion": "1",
                    "labels": {
                        "kobe.kunobi.ninja/sandbox-access-kind": "lease-gate",
                        "kobe.kunobi.ninja/sandbox-lease-name": LEASE,
                        "kobe.kunobi.ninja/sandbox-access-lease-uid": lease_uid,
                    },
                    "annotations": {
                        "kobe.kunobi.ninja/sandbox-access-state": "open",
                        "kobe.kunobi.ninja/sandbox-access-entries": "{}",
                        "kobe.kunobi.ninja/sandbox-executions": "{}",
                    },
                },
                "spec": {},
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {
                    "name": gate,
                    "namespace": NS,
                    "uid": "access-gate-uid",
                    "resourceVersion": "1",
                    "labels": {
                        "kobe.kunobi.ninja/sandbox-access-kind": "lease-gate",
                        "kobe.kunobi.ninja/sandbox-lease-name": LEASE,
                        "kobe.kunobi.ninja/sandbox-access-lease-uid": lease_uid,
                    },
                    "annotations": {
                        "kobe.kunobi.ninja/sandbox-access-state": "closed",
                        "kobe.kunobi.ninja/sandbox-access-entries": "{}",
                        "kobe.kunobi.ninja/sandbox-executions": "{}",
                    },
                },
                "spec": {},
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(2))
        );
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        let post = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("closed gate checkpoint");
        let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(
            body[2]["path"],
            "/metadata/annotations/kobe.kunobi.ninja~1sandbox-access-state"
        );
        assert_eq!(body[3]["value"], "closed");
    }

    /// A closed access gate still carries the exact execution inventory.
    /// Teardown retires one abandoned pre-CREATE slot and ends the pass before
    /// credentials or workload can be touched; the next pass must re-list the
    /// execution namespace before accepting absence.
    #[tokio::test]
    async fn execution_cleanup_checkpoints_before_credentials_and_claims() {
        use sha2::{Digest, Sha256};

        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        mount_teardown_scaffolding(&server).await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let lease_uid = lease.uid().unwrap();
        let gate = format!(
            "kobe-access-g-{}",
            &format!("{:x}", Sha256::digest(lease_uid.as_bytes()))[..40]
        );
        lease.metadata.annotations.as_mut().unwrap().insert(
            crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION.into(),
            crate::sandbox_access_ledger::encode_gate_reference(
                &crate::sandbox_access_ledger::AccessGateReference {
                    name: gate.clone(),
                    uid: "access-gate-uid".into(),
                },
            )
            .unwrap(),
        );
        let gate_path = format!("{RESERVATIONS_PATH}/{gate}");
        let execution_manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "pod-uid",
                "reservedAt": "2020-01-01T00:00:00Z",
                "creationState": "rejected",
                "active": false
            }
        })
        .to_string();
        let gate_object = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": gate,
                "namespace": NS,
                "uid": "access-gate-uid",
                "resourceVersion": "1",
                "labels": {
                    "kobe.kunobi.ninja/sandbox-access-kind": "lease-gate",
                    "kobe.kunobi.ninja/sandbox-lease-name": LEASE,
                    "kobe.kunobi.ninja/sandbox-access-lease-uid": lease_uid,
                },
                "annotations": {
                    "kobe.kunobi.ninja/sandbox-access-state": "closed",
                    "kobe.kunobi.ninja/sandbox-access-entries": "{}",
                    "kobe.kunobi.ninja/sandbox-executions": execution_manifest,
                },
            },
            "spec": {},
        });
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxExecutionList",
                "metadata":{"resourceVersion":"1"},
                "items":[]
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            execution_cleanup_checkpoint_action()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert!(requests.iter().all(|request| {
            let path = request.url.path();
            !path.contains("/serviceaccounts/")
                && !path.contains("/roles/")
                && !path.contains("/rolebindings/")
        }));
        let patch = requests
            .iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("execution retirement checkpoint");
        let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        let entries: serde_json::Value =
            serde_json::from_str(body[3]["value"].as_str().unwrap()).unwrap();
        assert_eq!(entries, serde_json::json!({}));
    }

    /// Run the destructive half only after the durable Releasing checkpoint
    /// has been observed at a new Kubernetes resourceVersion.
    async fn reconcile_release_after_checkpoint(
        mut lease: SandboxLease,
        ctx: Arc<SandboxContext>,
        server: &MockServer,
    ) -> Action {
        for pass in 0..8 {
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
            if action == Action::requeue(std::time::Duration::from_secs(5)) {
                // Child-handle ACK/delete/fence writes are not watched by the
                // Sandbox controller. Model the explicit short requeue and let
                // the next fixture observation expose the new tombstone state.
                continue;
            }
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
        panic!("release did not settle within eight durable checkpoints")
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

    /// Mount the status PATCH, empty exact footprint, and reservation tail.
    ///
    /// Footprint mocks are deliberately low priority so an invariant test can
    /// replace one observation without rebuilding the rest of the teardown.
    async fn mount_teardown_scaffolding(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(ALLOCATION_FENCE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {
                    "name": allocation_fence_name(LEASE),
                    "namespace": NS,
                    "uid": "allocation-fence-uid",
                    "resourceVersion": "fence-rv",
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                    "labels": {
                        "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                        crate::sandbox::SANDBOX_LEASE_UID_LABEL: "lease-uid-1",
                        SANDBOX_ALLOCATION_FENCE_LABEL: "true"
                    },
                    "annotations": {
                        SANDBOX_ALLOCATION_FENCE_LEASE_NAME_ANNOTATION: LEASE,
                        SANDBOX_ALLOCATION_FENCE_RETAIN_UNTIL_ANNOTATION: "2026-08-28T00:00:00Z"
                    }
                },
                "spec": { "holderIdentity": "closed:lease-uid-1" }
            })))
            .with_priority(10)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(CHILD_POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child_cluster_pool_json()))
            .with_priority(10)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(CHILD_INSTANCE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child_cluster_instance_json()))
            .with_priority(10)
            .mount(server)
            .await;
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
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(tombstone_claim_json("claim-uid", Some("claim-uid"))),
            )
            .with_priority(10)
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
                        "labels": {
                            crate::api::sandbox::SANDBOX_RESERVATION_TYPE_LABEL: "quota",
                            crate::api::sandbox::SANDBOX_RESERVATION_LEASE_UID_LABEL: "lease-uid-1",
                            crate::api::sandbox::REQUESTER_HASH_LABEL:
                                crate::api::sandbox::principal_hash_for(&admitted_lease().spec.requester),
                        },
                        "annotations": {
                            crate::api::sandbox::SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION: LEASE,
                        }
                    },
                    "spec": {},
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
        for path_value in [SANDBOX_PATH, POD_PATH, SERVICE_PATH] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
                })))
                .with_priority(10)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(SANDBOXES_PATH))
            .and(query_param(
                "labelSelector",
                format!("{UPSTREAM_CLAIM_UID_LABEL}=claim-uid"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": "SandboxList", "metadata": { "resourceVersion": "1" }, "items": []
            })))
            .with_priority(10)
            .mount(server)
            .await;
        for (path_value, kind) in [(PODS_PATH, "PodList"), (SERVICES_PATH, "ServiceList")] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": kind,
                    "metadata": { "resourceVersion": "1" }, "items": []
                })))
                .with_priority(10)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(PVCS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaimList",
                "metadata": { "resourceVersion": "1" }, "items": []
            })))
            .with_priority(10)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(PVS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "PersistentVolumeList",
                "metadata": { "resourceVersion": "1" }, "items": []
            })))
            .with_priority(10)
            .mount(server)
            .await;
    }

    /// An exact Claim tombstone is only one part of proof: a recorded Pod that
    /// is still present keeps both the footprint checkpoint and capacity held.
    #[tokio::test]
    async fn claim_tombstone_waits_for_recorded_pod_absence() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(POD_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {
                    "name": "sandbox-pod", "namespace": NS, "uid": "pod-uid",
                    "ownerReferences": [{
                        "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                        "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                        "name": "sbx", "uid": "sandbox-uid", "controller": true
                    }]
                }
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(
            Arc::new(releasing_lease(crate::crd::SandboxLeasePhase::Releasing)),
            ctx,
        )
        .await
        .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        assert_eq!(recorded_phases(&server).await, Vec::<String>::new());
        assert_eq!(requests_to(&server, "GET", POD_PATH).await, 1);
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

    /// A same-named downstream object with another UID is not evidence that
    /// the recorded object disappeared cleanly; teardown quarantines.
    #[tokio::test]
    async fn same_named_downstream_replacement_quarantines() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(SANDBOX_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                "metadata": { "name": "sbx", "namespace": NS, "uid": "replacement-uid" }
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(
            Arc::new(releasing_lease(crate::crd::SandboxLeasePhase::Releasing)),
            ctx,
        )
        .await
        .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
        assert_eq!(requests_to(&server, "GET", POD_PATH).await, 0);
    }

    /// Authorization failures are durable uncertainty, while an ordinary API
    /// outage retries without converting uncertainty into absence.
    #[tokio::test]
    async fn downstream_absence_errors_fail_closed() {
        for (code, reason, quarantined) in [
            (401, "Unauthorized", true),
            (403, "Forbidden", true),
            (500, "InternalError", false),
        ] {
            let (ctx, server) = test_context().await;
            mount_teardown_scaffolding(&server).await;
            Mock::given(method("GET"))
                .and(path(SERVICE_PATH))
                .respond_with(
                    ResponseTemplate::new(code).set_body_json(serde_json::json!({
                        "kind": "Status", "status": "Failure", "code": code, "reason": reason
                    })),
                )
                .with_priority(1)
                .mount(&server)
                .await;

            let action = reconcile_lease(
                Arc::new(releasing_lease(crate::crd::SandboxLeasePhase::Releasing)),
                ctx,
            )
            .await
            .unwrap();
            if quarantined {
                assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
                assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
            } else {
                assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
                assert_eq!(recorded_phases(&server).await, Vec::<String>::new());
            }
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
    }

    /// Exposed ports require an exact Service UID checkpoint. Pool identity is
    /// rechecked before using its template as that requirement proof.
    #[tokio::test]
    async fn exposed_ports_without_service_provenance_quarantine_before_tombstone_proof() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
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
            .service = None;
        lease.status.as_mut().unwrap().ready_at = Some(chrono::Utc::now().to_rfc3339());

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "GET", PVCS_PATH).await, 0);
    }

    /// Storage is disallowed, so an exact Sandbox-owned PVC and its bound PV
    /// are retained as quarantine evidence and never silently ignored.
    #[tokio::test]
    async fn exact_owned_pvc_and_associated_pv_quarantine_before_tombstone_conversion() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(PVCS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaimList",
                "metadata": { "resourceVersion": "1" },
                "items": [{
                    "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                    "metadata": {
                        "name": "data", "namespace": NS, "uid": "pvc-uid",
                        "ownerReferences": [{
                            "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                            "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                            "name": "sbx", "uid": "sandbox-uid", "controller": true
                        }]
                    }
                }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(PVS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "PersistentVolumeList",
                "metadata": { "resourceVersion": "1" },
                "items": [{
                    "apiVersion": "v1", "kind": "PersistentVolume",
                    "metadata": { "name": "pv-data", "uid": "pv-uid" },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "capacity": { "storage": "1Gi" },
                        "persistentVolumeReclaimPolicy": "Retain",
                        "claimRef": { "namespace": NS, "name": "data", "uid": "pvc-uid" }
                    }
                }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(
            Arc::new(releasing_lease(crate::crd::SandboxLeasePhase::Releasing)),
            ctx,
        )
        .await
        .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
        assert_eq!(requests_to(&server, "GET", PVS_PATH).await, 1);
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
    }

    /// Cancelling before the upstream controller assigns a Sandbox is a clean
    /// teardown only after Claim-UID scoped descendant lists are all empty.
    #[tokio::test]
    async fn cancel_while_provisioning_without_assigned_sandbox_finishes_cleanly() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox = None;
        target.pod = None;
        target.service = None;

        let action = reconcile_release_after_checkpoint(lease, ctx, &server).await;
        assert_eq!(action, Action::await_change());
        assert_eq!(
            recorded_phases(&server).await,
            vec!["Releasing".to_string(), "Released".to_string()]
        );
        assert_eq!(requests_to(&server, "GET", SANDBOXES_PATH).await, 1);
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

    /// A successful admission can be released before placement observes it.
    /// The Releasing write itself certifies that exact Pending shape, then an
    /// inert Claim tombstone and empty scans release quota without inventing a
    /// management target or quarantining capacity.
    #[tokio::test]
    async fn release_before_first_controller_pass_proves_admission_only_absence() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;

        let tombstone = tombstone_claim_json("admission-only-tombstone-uid", None);
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(ResponseTemplate::new(201).set_body_json(&tombstone))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&tombstone))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SANDBOXES_PATH))
            .and(query_param(
                "labelSelector",
                format!("{UPSTREAM_CLAIM_UID_LABEL}=admission-only-tombstone-uid"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": "SandboxList", "metadata": { "resourceVersion": "1" }, "items": []
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let mut lease = freshly_admitted_lease();
        assert!(admitted_pending_is_allocation_free(
            &lease,
            lease.status.as_ref().unwrap()
        ));
        lease.metadata.annotations.as_mut().unwrap().insert(
            SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION.to_string(),
            chrono::Utc::now().to_rfc3339(),
        );

        for pass in 0..12 {
            let before = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
                })
                .count();
            let _ = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .expect("admission-only cancellation must converge");
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
            if let Some(latest) = statuses.get(before).cloned() {
                lease.status =
                    Some(serde_json::from_value(latest).expect("typed admission-only checkpoint"));
                lease.metadata.resource_version = Some(format!("admission-only-rv-{pass}"));
            }
            if lease.status.as_ref().unwrap().phase == crate::crd::SandboxLeasePhase::Released {
                break;
            }
        }

        let status = lease.status.as_ref().unwrap();
        assert_eq!(status.phase, crate::crd::SandboxLeasePhase::Released);
        assert_eq!(
            status.claim_cleanup_fence,
            Some(crate::crd::SandboxClaimCleanupFence::AdmissionOnlyV1)
        );
        assert!(status.target.is_none(), "no workload target ever existed");
        assert!(
            !recorded_phases(&server)
                .await
                .iter()
                .any(|phase| phase == "Quarantined")
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
        let claim_posts: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| {
                request.method.as_str() == "POST" && request.url.path() == CLAIMS_PATH
            })
            .collect();
        assert_eq!(claim_posts.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&claim_posts[0].body).unwrap();
        assert_eq!(body["spec"]["lifecycle"]["shutdownPolicy"], "Retain");
    }

    /// Cancellation can win after the management POST protocol was
    /// checkpointed but before the Claim UID was. The create-from-birth
    /// finalizer makes a 404 authoritative: after the exact inert tombstone
    /// occupies the name, its UID is safe to use for empty descendant proof
    /// and quota must converge to Released rather than Quarantined.
    #[tokio::test]
    async fn cancel_before_management_claim_uid_checkpoint_releases_all_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;

        let tombstone = tombstone_claim_json("never-started-uid", None);
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(ResponseTemplate::new(201).set_body_json(&tombstone))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&tombstone))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SANDBOXES_PATH))
            .and(query_param(
                "labelSelector",
                format!("{UPSTREAM_CLAIM_UID_LABEL}=never-started-uid"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": "SandboxList", "metadata": { "resourceVersion": "1" }, "items": []
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let status = lease.status.as_mut().unwrap();
        status.sandbox_claim_tombstone = None;
        let target = status.target.as_mut().unwrap();
        target.sandbox_claim = None;
        target.sandbox = None;
        target.pod = None;
        target.service = None;

        for pass in 0..10 {
            let before = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
                })
                .count();
            let _ = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .expect("pre-checkpoint cancellation must converge");
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
            if let Some(latest) = statuses.get(before).cloned() {
                lease.status =
                    Some(serde_json::from_value(latest).expect("typed cancellation checkpoint"));
                lease.metadata.resource_version = Some(format!("cancel-rv-{pass}"));
            }
            if lease.status.as_ref().unwrap().phase == crate::crd::SandboxLeasePhase::Released {
                break;
            }
        }

        let status = lease.status.as_ref().unwrap();
        assert_eq!(status.phase, crate::crd::SandboxLeasePhase::Released);
        assert_eq!(
            status
                .target
                .as_ref()
                .and_then(|target| target.sandbox_claim.as_ref())
                .map(|claim| claim.uid.as_str()),
            Some("never-started-uid")
        );
        assert!(
            !recorded_phases(&server)
                .await
                .iter()
                .any(|phase| phase == "Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            1,
            "the partially admitted slot must be returned exactly once"
        );
    }

    /// A descendant created after Claim observation is caught by the exact
    /// Claim-UID index and quarantined when no durable Sandbox UID exists.
    #[tokio::test]
    async fn late_created_claim_labelled_descendant_retains_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(SANDBOXES_PATH))
            .and(query_param(
                "labelSelector",
                format!("{UPSTREAM_CLAIM_UID_LABEL}=claim-uid"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                "kind": "SandboxList", "metadata": { "resourceVersion": "2" },
                "items": [{
                    "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                    "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                    "metadata": {
                        "name": "late-sbx", "namespace": NS, "uid": "late-sandbox-uid",
                        "labels": { (UPSTREAM_CLAIM_UID_LABEL): "claim-uid" },
                        "ownerReferences": [{
                            "apiVersion": AGENT_SANDBOX_API_VERSION,
                            "kind": SANDBOX_CLAIM_KIND, "name": "kobe-sbx-1",
                            "uid": "claim-uid", "controller": true
                        }]
                    }
                }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox = None;
        target.pod = None;
        target.service = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(recorded_phases(&server).await, vec!["Quarantined"]);
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

    /// Agent Sandbox Services have only a Sandbox owner UID (not the Claim UID
    /// label). Exact-owner enumeration still catches a late Service.
    #[tokio::test]
    async fn late_service_without_claim_uid_label_retains_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(SERVICES_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "ServiceList",
                "metadata": { "resourceVersion": "2" },
                "items": [{
                    "apiVersion": "v1", "kind": "Service",
                    "metadata": {
                        "name": "late-service", "namespace": NS, "uid": "late-service-uid",
                        "labels": { "agents.x-k8s.io/sandbox-name-hash": "opaque" },
                        "ownerReferences": [{
                            "apiVersion": crate::controllers::sandbox_canary::SANDBOX_API_VERSION,
                            "kind": crate::controllers::sandbox_canary::SANDBOX_KIND,
                            "name": "sbx", "uid": "sandbox-uid", "controller": true
                        }]
                    }
                }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox = None;
        target.pod = None;
        target.service = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        assert_eq!(recorded_phases(&server).await, Vec::<String>::new());
        assert_eq!(requests_to(&server, "GET", SERVICES_PATH).await, 1);
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

    /// If the Claim already identifies a live Sandbox, teardown checkpoints
    /// all discoverable exact descendant UIDs before tombstone conversion.
    #[tokio::test]
    async fn live_claim_descendants_are_checkpointed_before_tombstone_conversion() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        mount_resolved_sandbox(&server).await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(claim_json(
                serde_json::json!({ "sandbox": { "name": "sbx" } }),
            )))
            .with_priority(1)
            .mount(&server)
            .await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.sandbox = None;
        target.pod = None;
        target.service = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("descendant checkpoint");
        assert_eq!(status["target"]["sandbox"]["uid"], "sandbox-uid");
        assert_eq!(status["target"]["pod"]["uid"], "pod-uid");
        assert_eq!(status["target"]["service"]["uid"], "service-uid");
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
    /// pass; it never converts an object known only by a derived name.
    #[tokio::test]
    async fn teardown_recovers_missing_claim_provenance_before_tombstone_conversion() {
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
        lease.status.as_mut().unwrap().sandbox_claim_tombstone = None;

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

    /// A derived name is not provenance. If the object at that name lacks this
    /// exact lease UID label, recovery quarantines without deleting it or
    /// returning quota.
    #[tokio::test]
    async fn teardown_never_recovers_a_foreign_claim() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut foreign = claim_json(serde_json::json!({}));
        foreign["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL] =
            "another-lease-uid".into();
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

    /// Release recovery accepts only the exact base ownerRef shape, then adds
    /// the cleanup finalizer and clears that owner atomically before recording
    /// the missing Claim UID. No delete or quota release can cross this
    /// restart boundary.
    #[tokio::test]
    async fn teardown_migrates_exact_legacy_management_claim_before_recovery() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let dependent = base_legacy_claim_json(serde_json::json!({}));
        let mut migrated = dependent.clone();
        migrated["metadata"]["resourceVersion"] = "claim-rv-2".into();
        migrated["metadata"]["ownerReferences"] = serde_json::json!([]);
        migrated["metadata"]["finalizers"] =
            serde_json::json!([crate::sandbox::SANDBOX_CLAIM_CLEANUP_FINALIZER]);
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&dependent))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&migrated))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&migrated))
            .expect(1)
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
        lease.status.as_mut().unwrap().sandbox_claim_tombstone = None;

        let action = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(requests_to(&server, "DELETE", CLAIM_PATH).await, 0);
        assert_eq!(requests_to(&server, "PATCH", CLAIM_PATH).await, 1);
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 0);
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0
        );
        assert!(recorded_phases(&server).await.is_empty());

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 1);
        let recovered = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("recovered legacy Claim identity");
        assert_eq!(recovered["target"]["sandboxClaim"]["uid"], "claim-uid");
    }

    /// If the recorded Claim name is already occupied by another UID, the
    /// pre-teardown descendant checkpoint quarantines before touching it.
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
        Mock::given(method("GET"))
            .and(path(SERVICE_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 403, "reason": "Forbidden"
            })))
            .with_priority(1)
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

    /// A live lease whose admission gate could not be verified is stamped
    /// `Unverifiable` in the same fenced write that quarantines it. Without a
    /// durable cause the Quarantined reconcile arm returned before any
    /// evidence retry, wedging finalizer and quota forever; with one, the
    /// intended evidence path becomes reachable.
    #[tokio::test]
    async fn unverifiable_gate_quarantine_stamps_a_durable_cause() {
        let (ctx, server) = test_context().await;
        mount_one_winning_status_patch(&server).await;
        // Ready with no release signal: exactly the shape that reaches the
        // pre-release gate check.
        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Ready);
        assert!(lease.status.as_ref().unwrap().release_cause.is_none());

        let quarantine = quarantine_unverifiable_gate(&lease, &ctx, "access_gate_unverifiable")
            .await
            .unwrap();
        assert_eq!(
            quarantine,
            Action::requeue(std::time::Duration::from_secs(300))
        );

        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["phase"], "Quarantined");
        assert_eq!(
            statuses[0]["releaseCause"], "Unverifiable",
            "the cause must land atomically with the phase"
        );
    }

    #[test]
    fn an_unverifiable_release_cause_is_reachable_and_terminal() {
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Quarantined);
        lease.status.as_mut().unwrap().release_cause =
            Some(crate::crd::SandboxReleaseCause::Unverifiable);
        assert!(
            matches!(release_reason(&lease), Some(ReleaseReason::Unverifiable)),
            "a stamped quarantine must re-enter teardown instead of being held cause-less"
        );

        let reason = ReleaseReason::Unverifiable;
        assert_eq!(reason.as_str(), "IntegrityUnverifiable");
        assert_eq!(
            reason.persisted_cause(),
            Some(crate::crd::SandboxReleaseCause::Unverifiable)
        );
        assert_eq!(
            reason.terminal_phase(),
            crate::crd::SandboxLeasePhase::Released
        );
    }

    /// The only legal exit from `Quarantined` runs back through `Releasing`
    /// with the persisted cause intact — the immutability guard must accept
    /// its own stamp, and the terminal accounting keeps attributing the
    /// teardown to the integrity fault rather than to a caller request.
    #[tokio::test]
    async fn unverifiable_quarantine_resumes_teardown_through_releasing() {
        let (ctx, server) = test_context().await;
        mount_one_winning_status_patch(&server).await;
        let mut lease = releasing_lease(crate::crd::SandboxLeasePhase::Quarantined);
        lease.status.as_mut().unwrap().release_cause =
            Some(crate::crd::SandboxReleaseCause::Unverifiable);

        let action = drive_release(&lease, &ctx, ReleaseReason::Unverifiable)
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());

        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["phase"], "Releasing");
        assert_eq!(statuses[0]["releaseCause"], "Unverifiable");
    }
    /// `FootprintAbsent` is the restart boundary. Once present, reconciliation
    /// skips workload teardown but still removes the receipt-bearing internal
    /// handle explicitly before the reservation/terminal tail.
    #[tokio::test]
    async fn restart_from_footprint_proof_skips_claim_and_child_teardown() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let receipt = verified_receipt("kobe-abc123", "child-instance-uid");
        let receipt_token = receipt_acknowledgement_token(&receipt);
        let evidence = child_evidence_reference(&receipt);
        mount_child_handle_cleanup(&server, 1, Some(receipt)).await;
        let mut lease = child_placed_lease("child-lease-uid");
        {
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Releasing;
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
            status.child_teardown_receipt_acknowledgement = Some(receipt_token);
            status.child_teardown_evidence = Some(evidence);
        }
        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "persisted before controller restart",
        );

        let retirement = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(
            retirement,
            Action::requeue(std::time::Duration::from_secs(5)),
            "ACK+DELETE ends the pass so the retained terminating handle is re-read"
        );
        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 2);
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 1);
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
        let delete = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "DELETE" && request.url.path() == CLUSTER_LEASE_PATH
            })
            .expect("verified child handle delete");
        let options: serde_json::Value = serde_json::from_slice(&delete.body).unwrap();
        assert_eq!(options["preconditions"]["uid"], "child-lease-uid");
        assert_eq!(options["propagationPolicy"], "Foreground");
    }

    /// A reservation API outage occurs after workload absence is durable. The
    /// proof must survive the failed tail so a retry neither rechecks nor
    /// re-destroys the external footprint.
    #[tokio::test]
    async fn reservation_failure_retains_footprint_proof_for_retry() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let receipt = verified_receipt("kobe-abc123", "child-instance-uid");
        let receipt_token = receipt_acknowledgement_token(&receipt);
        let evidence = child_evidence_reference(&receipt);
        mount_child_handle_cleanup(&server, 1, Some(receipt)).await;
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
            status.child_teardown_receipt_acknowledgement = Some(receipt_token);
            status.child_teardown_evidence = Some(evidence);
        }
        lease.status.as_mut().unwrap().conditions = with_condition(
            &lease,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "FootprintObservedAbsent",
            "persisted before reservation cleanup",
        );

        let retirement = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(
            retirement,
            Action::requeue(std::time::Duration::from_secs(5))
        );
        let first = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
            .await
            .unwrap();
        assert_eq!(first, Action::requeue(std::time::Duration::from_secs(15)));
        assert_eq!(requests_to(&server, "PATCH", LEASE_STATUS_PATH).await, 1);
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 2);
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 1);
        assert_eq!(requests_to(&server, "GET", CLAIM_PATH).await, 0);
        assert!(footprint_absence_proven(lease.status.as_ref().unwrap()));
        advance_lease_to_latest_status(&mut lease, &server, "lease-rv-after-reservation-failure")
            .await;
        assert!(
            lease
                .status
                .as_ref()
                .unwrap()
                .conditions
                .iter()
                .any(|condition| {
                    condition.condition_type == CLEANUP_VERIFIED_CONDITION
                        && condition.status == crate::crd::SandboxConditionStatus::False
                        && condition.reason == "ReservationReleaseRetry"
                })
        );

        let retry = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(retry, Action::await_change());
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 3);
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 1);
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
    /// only after the exact Claim tombstone is held and every descendant is
    /// observed absent.
    #[tokio::test]
    async fn capacity_returns_only_once_tombstone_and_descendants_are_proven() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;

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
        assert_eq!(
            requests_to(&server, "DELETE", CLAIM_PATH).await,
            0,
            "the tombstone must keep the deterministic Claim name occupied"
        );
        let requests = server.received_requests().await.unwrap_or_default();
        let first_claim_read = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "GET" && request.url.path() == CLAIM_PATH
            })
            .expect("exact tombstone read");
        let credential_checks: Vec<_> = requests
            .iter()
            .enumerate()
            .filter(|(_, request)| {
                request.method.as_str() == "GET"
                    && (request.url.path().contains("/rolebindings/")
                        || request.url.path().contains("/roles/")
                        || request.url.path().contains("/serviceaccounts/"))
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            credential_checks
                .iter()
                .filter(|credential_check| **credential_check < first_claim_read)
                .count(),
            12,
            "all four operations x three identity objects must be proven absent before tombstone proof"
        );
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

    /// RBAC uncertainty stops before tombstone proof and quota release. A 403
    /// is not evidence that an identity is absent, so the finalizer must retain
    /// the whole lease for operator inspection.
    #[tokio::test]
    async fn unverifiable_scoped_identity_quarantines_before_tombstone_proof() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let first_name = crate::api::sandbox_credentials::credential_name(
            "lease-uid-1",
            crate::api::sandbox_credentials::SandboxOperation::Logs,
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/rbac.authorization.k8s.io/v1/namespaces/{NS}/rolebindings/{first_name}"
            )))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 403, "reason": "Forbidden"
            })))
            .mount(&server)
            .await;

        let lease = releasing_lease(crate::crd::SandboxLeasePhase::Releasing);
        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(300))
        );
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
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
    }

    /// A deleting Claim cannot be the durable name tombstone. Its name lock is
    /// about to disappear, so cleanup quarantines and keeps holding capacity.
    #[tokio::test]
    async fn a_deleting_claim_quarantines_and_holds_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));

        assert_eq!(
            recorded_phases(&server).await,
            vec!["Releasing".to_string(), "Quarantined".to_string()],
            "a disappearing Claim name is not a durable resurrection fence"
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

        for terminal in [SandboxLeasePhase::Released, SandboxLeasePhase::Expired] {
            assert_eq!(
                release_reason(&releasing_lease(terminal)),
                None,
                "{terminal} is terminal and must not be torn down again"
            );
        }

        assert_eq!(
            release_reason(&releasing_lease(SandboxLeasePhase::Quarantined)),
            Some(ReleaseReason::Requested),
            "quarantine retries the immutable release cause without changing its outcome"
        );

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

        let deleting = |deleted_at: chrono::DateTime<chrono::Utc>| {
            let mut lease = admitted_lease();
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Ready;
            status.ready_at = Some((deadline - chrono::Duration::hours(1)).to_rfc3339());
            status.expires_at = Some(deadline.to_rfc3339());
            lease.metadata.deletion_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_millisecond(deleted_at.timestamp_millis())
                        .unwrap(),
                ));
            lease
        };
        assert_eq!(
            release_reason(&deleting(before)),
            Some(ReleaseReason::Requested),
            "a direct delete before expiry owns the terminal outcome"
        );
        assert_eq!(
            release_reason(&deleting(after)),
            Some(ReleaseReason::RuntimeTtl),
            "a delete after expiry cannot rewrite automatic expiry"
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

    fn child_placement_authority(
        name: &str,
        uid: &str,
        generation: i64,
    ) -> crate::crd::SandboxPlacementAuthority {
        crate::crd::SandboxPlacementAuthority {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterPool".into(),
            namespace: NS.into(),
            name: name.into(),
            uid: uid.into(),
            generation,
        }
    }

    fn child_placed_lease(cluster_lease_uid: &str) -> SandboxLease {
        let mut lease = admitted_lease();
        lease.spec.placement_authority =
            Some(child_placement_authority("children", "cluster-pool-uid", 1));
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
            namespace: CHILD_SANDBOX_NAMESPACE.into(),
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
            child_cluster_kubeconfig_secret: Some(crate::crd::SandboxObjectReference {
                api_version: "v1".into(),
                kind: "Secret".into(),
                namespace: Some(NS.into()),
                name: "kobe-abc123-kubeconfig".into(),
                uid: "child-kubeconfig-secret-uid".into(),
                generation: None,
            }),
            child_cluster_kubeconfig_sha256: Some("a".repeat(64)),
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
            service: None,
        });
        status.allocation_fence = Some(crate::crd::SandboxObjectReference {
            api_version: "coordination.k8s.io/v1".into(),
            kind: "Lease".into(),
            namespace: Some(NS.into()),
            name: allocation_fence_name(LEASE),
            uid: "allocation-fence-uid".into(),
            generation: None,
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

    fn child_evidence_reference(
        receipt: &serde_json::Value,
    ) -> crate::crd::TeardownEvidenceReference {
        let attempt = receipt["attemptId"]
            .as_str()
            .expect("receipt fixture has an attempt");
        crate::crd::TeardownEvidenceReference {
            name: crate::crd::verified_teardown_evidence_name("child-lease-uid", attempt),
            uid: "child-evidence-uid".into(),
            generation: 1,
            resource_version: "evidence-rv-1".into(),
        }
    }

    async fn mount_child_evidence(server: &MockServer, receipt: &serde_json::Value) {
        let reference = child_evidence_reference(receipt);
        let labels = crate::crd::verified_teardown_evidence_labels(
            "child-lease-uid",
            receipt["attemptId"]
                .as_str()
                .expect("receipt fixture has attempt"),
        );
        let evidence = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "VerifiedTeardownEvidence",
            "metadata": {
                "name": reference.name,
                "namespace": NS,
                "uid": reference.uid,
                "generation": reference.generation,
                "resourceVersion": reference.resource_version,
                "labels": labels,
            },
            "spec": {
                "lease": { "name": "kobe-sbx-sbx-1", "uid": "child-lease-uid" },
                "attemptId": receipt["attemptId"],
                "receipt": receipt,
            }
        });
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/{NS}/verifiedteardownevidence/{}",
                reference.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(evidence))
            .mount(server)
            .await;
    }

    fn child_cluster_lease(
        uid: &str,
        phase: &str,
        receipt: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut status = serde_json::json!({ "phase": phase });
        if phase == "Bound" || receipt.is_some() {
            status["clusterName"] = "kobe-abc123".into();
            status["binding"] = serde_json::to_value(child_binding()).unwrap();
        }
        if let Some(receipt) = receipt {
            status["teardownAttemptId"] = receipt["attemptId"].clone();
            status["teardownEvidence"] =
                serde_json::to_value(child_evidence_reference(&receipt)).unwrap();
            status["teardownReceipt"] = receipt;
        }
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": "kobe-sbx-sbx-1",
                "namespace": NS,
                "uid": uid,
                "generation": 1,
                "resourceVersion": "42",
                "labels": {
                    "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                    "kobe.kunobi.ninja/sandbox-lease-uid": "lease-uid-1",
                    crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL: "true",
                },
                "annotations": {
                    crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION: LEASE,
                    crate::controllers::sandbox_child::SANDBOX_COMPOSITION_NAME_ANNOTATION: LEASE,
                    crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION:
                        (chrono::Utc::now() + chrono::Duration::days(8)).to_rfc3339(),
                    crate::controllers::sandbox_child::CHILD_KUBECONFIG_PROVENANCE_ANNOTATION:
                        crate::controllers::sandbox_child::CHILD_KUBECONFIG_PROVENANCE_SECRET_UID_SHA256_V1,
                },
                "finalizers": [
                    crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
                ],
            },
            "spec": {
                "poolRef": "children",
                "ttl": "2h",
                "requester": { "type": "kobe:sandbox-composition", "identity": "lease-uid-1" },
                "cleanupMode": "VerifiedDestroy",
            },
            "status": status,
        })
    }

    #[test]
    fn receipt_authority_requires_immutable_outer_uid_and_exact_child_uid() {
        let consumer = child_placed_lease("child-lease-uid");
        let recorded = consumer
            .status
            .as_ref()
            .and_then(|status| status.target.as_ref())
            .and_then(|target| target.child_cluster_lease.as_ref())
            .unwrap();
        let exact: crate::crd::ClusterLease =
            serde_json::from_value(child_cluster_lease("child-lease-uid", "Released", None))
                .unwrap();
        assert!(composition_handle_matches_consumer(
            &exact, &consumer, recorded
        ));

        let mut mutable_metadata_forgery = exact.clone();
        mutable_metadata_forgery.spec.requester.identity = "foreign-outer-uid".into();
        assert!(
            !composition_handle_matches_consumer(&mutable_metadata_forgery, &consumer, recorded),
            "labels and annotations cannot replace immutable requester UID authority"
        );

        let mut replacement = recorded.clone();
        replacement.uid = "same-name-replacement".into();
        assert!(
            !composition_handle_matches_consumer(&exact, &consumer, &replacement),
            "a same-named replacement child cannot inherit an old consumer checkpoint"
        );
    }

    #[test]
    fn receipt_authority_never_acknowledges_never_bound_after_outer_instance_checkpoint() {
        let mut consumer = child_placed_lease("child-lease-uid");
        let recorded_instance = consumer
            .status
            .as_ref()
            .and_then(|status| status.target.as_ref())
            .and_then(|target| target.child_cluster_instance.as_ref())
            .cloned()
            .expect("fixture records the child instance");
        let mut child: crate::crd::ClusterLease =
            serde_json::from_value(child_cluster_lease("child-lease-uid", "Released", None))
                .unwrap();
        let status = child.status.as_mut().unwrap();
        status.teardown_attempt_id = Some("never-bound-attempt".into());
        status.unbound_release_verified_at = Some("2026-08-20T00:00:00Z".into());
        status.conditions.push(crate::crd::ClusterLeaseCondition {
            condition_type: "AllocationAbsent".into(),
            status: "True".into(),
            reason: "NeverBound".into(),
            message: "release attempt never-bound-attempt proved no reciprocal allocation existed"
                .into(),
            last_transition_time: Some("2026-08-20T00:00:00Z".into()),
        });

        assert!(validated_child_unbound_release_proof(&child, Some(&recorded_instance)).is_none());

        consumer
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .child_cluster_instance = None;
        let now_unrecorded = consumer
            .status
            .as_ref()
            .and_then(|status| status.target.as_ref())
            .and_then(|target| target.child_cluster_instance.as_ref());
        assert!(validated_child_unbound_release_proof(&child, now_unrecorded).is_some());
    }

    fn child_creation_manifest() -> crate::crd::TeardownCreationManifest {
        use crate::crd::{
            CreationControlRelation, CreationManifestResource, KubernetesResourceIdentity,
        };

        let instance = KubernetesResourceIdentity {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterInstance".into(),
            namespace: Some(NS.into()),
            name: "kobe-abc123".into(),
            uid: "child-instance-uid".into(),
        };
        let namespaced =
            |api_version: &str, kind: &str, name: &str, uid: &str| KubernetesResourceIdentity {
                api_version: api_version.into(),
                kind: kind.into(),
                namespace: Some(NS.into()),
                name: name.into(),
                uid: uid.into(),
            };
        let stateful_set = namespaced("apps/v1", "StatefulSet", "kobe-abc123-server", "sts-uid");
        let owned = |subject, resource| CreationManifestResource {
            subject,
            resource,
            controller: instance.clone(),
            control_relation: CreationControlRelation::ControllerOwner,
        };
        let manifest = crate::crd::TeardownCreationManifest {
            schema_version: crate::crd::TEARDOWN_CREATION_MANIFEST_SCHEMA_VERSION,
            instance: crate::crd::ResourceRef {
                name: "kobe-abc123".into(),
                uid: Some("child-instance-uid".into()),
            },
            namespace: NS.into(),
            backend_type: crate::crd::BackendType::K3s,
            config_digest: crate::crd::BackendProvenance::from_config(&crate::crd::BackendConfig {
                backend_type: crate::crd::BackendType::K3s,
                ..Default::default()
            })
            .unwrap()
            .config_digest,
            service_cidr: "10.43.0.0/16".into(),
            cluster_cidr: "10.42.0.0/16".into(),
            server_replicas: 1,
            agent_replicas: 0,
            resources: vec![
                owned(
                    crate::crd::TeardownSubject::ServerStatefulSet,
                    stateful_set.clone(),
                ),
                owned(
                    crate::crd::TeardownSubject::Service,
                    namespaced("v1", "Service", "kobe-abc123-server", "service-uid"),
                ),
                owned(
                    crate::crd::TeardownSubject::PublisherConfigMap,
                    namespaced(
                        "v1",
                        "ConfigMap",
                        "kobe-abc123-kubeconfig-publisher",
                        "publisher-uid",
                    ),
                ),
                owned(
                    crate::crd::TeardownSubject::TokenSecret,
                    namespaced("v1", "Secret", "kobe-abc123-token", "token-uid"),
                ),
                owned(
                    crate::crd::TeardownSubject::KubeconfigSecret,
                    namespaced("v1", "Secret", "kobe-abc123-kubeconfig", "kubeconfig-uid"),
                ),
                owned(
                    crate::crd::TeardownSubject::CidrClaim,
                    namespaced(
                        "kobe.kunobi.ninja/v1alpha1",
                        "CIDRClaim",
                        "kobe-abc123",
                        "cidr-uid",
                    ),
                ),
                CreationManifestResource {
                    subject: crate::crd::TeardownSubject::ServerPods,
                    resource: namespaced("v1", "Pod", "kobe-abc123-server-0", "pod-uid"),
                    controller: stateful_set,
                    control_relation: CreationControlRelation::ControllerOwner,
                },
            ],
            storage: Vec::new(),
            datastore: crate::crd::DatastoreProvenance::EmbeddedSqlite,
            sealed_at: "2026-01-01T00:00:00Z".into(),
        };
        assert_eq!(manifest.validate(), Ok(()));
        manifest
    }

    fn child_binding() -> crate::crd::LeaseBinding {
        let manifest = child_creation_manifest();
        crate::crd::LeaseBinding {
            binding_id: "31ec124f-b731-4e85-8d74-b306f2da7772".into(),
            lease: crate::crd::ResourceRef {
                name: "kobe-sbx-sbx-1".into(),
                uid: Some("child-lease-uid".into()),
            },
            instance: crate::crd::BoundInstanceRef {
                name: "kobe-abc123".into(),
                uid: "child-instance-uid".into(),
                observed_generation: 2,
            },
            pool: crate::crd::ResourceRef {
                name: "children".into(),
                uid: Some("cluster-pool-uid".into()),
            },
            backend: crate::crd::BackendProvenance {
                backend_type: crate::crd::BackendType::K3s,
                config_digest: manifest.config_digest.clone(),
                capi: None,
            },
            instance_spec_digest: "d".repeat(64),
            cleanup_mode: crate::crd::CleanupMode::VerifiedDestroy,
            creation_manifest_digest: Some(manifest.digest().unwrap()),
            creation_manifest: Some(manifest),
            connect_token: Some(crate::crd::KubernetesResourceIdentity {
                api_version: "v1".into(),
                kind: "Secret".into(),
                namespace: Some(NS.into()),
                name: "kobe-sbx-sbx-1-connect-token".into(),
                uid: "connect-token-uid".into(),
            }),
        }
    }

    fn child_cluster_pool_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "children",
                "namespace": NS,
                "uid": "cluster-pool-uid",
                "resourceVersion": "30",
                "generation": 1
            },
            "spec": {
                "size": 1,
                "ttl": "9h",
                "backend": { "type": "k3s" },
                "cluster": { "version": "v1.32.0" },
                "bootstraps": [{ "name": "kobe-agent-sandbox-v1-0-0" }]
            },
            "status": {
                "phase": "Healthy",
                "ready": 1,
                "quarantined": 0,
                "unhealthy": 0
            }
        })
    }

    fn child_cluster_instance_json() -> serde_json::Value {
        let binding = child_binding();
        let spec_hash = binding.instance_spec_digest.clone();
        let backend = binding.backend.clone();
        let creation_manifest = binding.creation_manifest.clone();
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "kobe-abc123",
                "namespace": NS,
                "uid": "child-instance-uid",
                "resourceVersion": "20",
                "generation": 2,
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "children",
                    "uid": "cluster-pool-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "children", "uid": "cluster-pool-uid" } },
            "status": {
                "phase": "Leased",
                "provisioned": true,
                "bootstrapped": true,
                "leaseRef": { "name": "kobe-sbx-sbx-1", "uid": "child-lease-uid" },
                "binding": binding,
                "specHash": spec_hash,
                "creationManifest": creation_manifest,
                "createdWith": {
                    "operatorVersion": "v0.40.0",
                    "backendType": "k3s",
                    "poolUid": "cluster-pool-uid",
                    "backend": backend
                }
            }
        })
    }

    fn child_test_kubeconfig(server: &MockServer) -> String {
        format!(
            r#"apiVersion: v1
kind: Config
clusters:
- name: child
  cluster:
    server: {}
users:
- name: admin
  user:
    token: test-token
contexts:
- name: child
  context:
    cluster: child
    user: admin
current-context: child
"#,
            server.uri()
        )
    }

    fn child_placed_lease_with_reachable_access(
        cluster_lease_uid: &str,
        server: &MockServer,
    ) -> SandboxLease {
        use sha2::{Digest as _, Sha256};

        let mut lease = child_placed_lease(cluster_lease_uid);
        lease
            .status
            .as_mut()
            .and_then(|status| status.target.as_mut())
            .expect("child target provenance")
            .child_cluster_kubeconfig_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(child_test_kubeconfig(server).as_bytes())
        ));
        lease
    }

    fn child_kubeconfig_secret_json(server: &MockServer, uid: &str) -> serde_json::Value {
        use base64::Engine as _;
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "kobe-abc123-kubeconfig",
                "namespace": NS,
                "uid": uid,
                "resourceVersion": "secret-rv-1",
                "ownerReferences": [],
            },
            "data": {
                "kubeconfig": base64::engine::general_purpose::STANDARD
                    .encode(child_test_kubeconfig(server)),
            }
        })
    }

    /// Secret identity alone is insufficient: an in-place payload rewrite
    /// would redirect every later cleanup request while retaining the UID.
    /// Idempotent metadata/SSA churn is harmless when the canonical bytes are
    /// unchanged, but alternate keys and content drift fail closed.
    #[tokio::test]
    async fn child_kubeconfig_checkpoint_fences_uid_and_exact_payload_not_resource_version() {
        let server = MockServer::start().await;
        let lease = child_placed_lease_with_reachable_access("child-lease-uid", &server);
        let target = lease.status.as_ref().unwrap().target.as_ref().unwrap();
        let instance = target.child_cluster_instance.as_ref().unwrap();
        let recorded = target.child_cluster_kubeconfig_secret.as_ref().unwrap();
        let digest = target.child_cluster_kubeconfig_sha256.as_deref().unwrap();

        let exact: Secret = serde_json::from_value(child_kubeconfig_secret_json(
            &server,
            "child-kubeconfig-secret-uid",
        ))
        .unwrap();
        let observed = child_kubeconfig_secret_observation(&exact, NS, instance).unwrap();
        require_exact_child_kubeconfig_secret(recorded, digest, &observed).unwrap();

        let mut newer_rv = exact.clone();
        newer_rv.metadata.resource_version = Some("secret-rv-2".into());
        let newer = child_kubeconfig_secret_observation(&newer_rv, NS, instance).unwrap();
        require_exact_child_kubeconfig_secret(recorded, digest, &newer).unwrap();

        let mut rewritten = exact.clone();
        rewritten.data.as_mut().unwrap().insert(
            "kubeconfig".into(),
            k8s_openapi::ByteString(b"different credential".to_vec()),
        );
        let rewritten = child_kubeconfig_secret_observation(&rewritten, NS, instance).unwrap();
        assert!(require_exact_child_kubeconfig_secret(recorded, digest, &rewritten).is_err());

        let mut ambiguous = exact.clone();
        ambiguous.data.as_mut().unwrap().insert(
            "value".into(),
            k8s_openapi::ByteString(b"alternate credential".to_vec()),
        );
        assert!(child_kubeconfig_secret_observation(&ambiguous, NS, instance).is_err());

        let mut replaced = exact;
        replaced.metadata.uid = Some("replacement-secret-uid".into());
        let replaced = child_kubeconfig_secret_observation(&replaced, NS, instance).unwrap();
        assert!(require_exact_child_kubeconfig_secret(recorded, digest, &replaced).is_err());
    }

    /// k3s reserves `{instance}-kubeconfig` under the ClusterInstance
    /// controller owner. That controller owner is composition-safe even when
    /// kubectl apply leaves extra non-controller metadata; a foreign
    /// controller is not.
    #[tokio::test]
    async fn child_kubeconfig_observation_accepts_exact_instance_controller_owner() {
        let server = MockServer::start().await;
        let lease = child_placed_lease("child-lease-uid");
        let instance = lease
            .status
            .as_ref()
            .and_then(|status| status.target.as_ref())
            .and_then(|target| target.child_cluster_instance.as_ref())
            .unwrap();

        let mut owned = child_kubeconfig_secret_json(&server, "child-kubeconfig-secret-uid");
        owned["metadata"]["ownerReferences"] = serde_json::json!([{
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "name": "kobe-abc123",
            "uid": "child-instance-uid",
            "controller": true,
            "blockOwnerDeletion": true
        }]);
        let owned: Secret = serde_json::from_value(owned).unwrap();
        child_kubeconfig_secret_observation(&owned, NS, instance).unwrap();

        let mut unnamed_namespace = owned.clone();
        unnamed_namespace.metadata.namespace = None;
        child_kubeconfig_secret_observation(&unnamed_namespace, NS, instance).unwrap();

        let mut dropped_controller = owned.clone();
        dropped_controller
            .metadata
            .owner_references
            .as_mut()
            .unwrap()[0]
            .controller = None;
        child_kubeconfig_secret_observation(&dropped_controller, NS, instance).unwrap();

        let mut foreign = owned.clone();
        foreign.metadata.owner_references.as_mut().unwrap()[0].uid = "other-instance".into();
        let foreign_error = match child_kubeconfig_secret_observation(&foreign, NS, instance) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("foreign ClusterInstance owner must fail closed"),
        };
        assert!(
            foreign_error.contains("unsafe provenance"),
            "{foreign_error}"
        );

        let mut extra = owned.clone();
        extra.metadata.owner_references.as_mut().unwrap().push(
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "v1".into(),
                kind: "Pod".into(),
                name: "publisher".into(),
                uid: "pod-uid".into(),
                controller: Some(false),
                ..Default::default()
            },
        );
        child_kubeconfig_secret_observation(&extra, NS, instance).unwrap();

        let mut foreign_controller = extra;
        foreign_controller
            .metadata
            .owner_references
            .as_mut()
            .unwrap()[1]
            .controller = Some(true);
        assert!(child_kubeconfig_secret_observation(&foreign_controller, NS, instance).is_err());
    }

    /// The first Secret observation may hash bytes for the checkpoint, but it
    /// must return immediately after the fenced status write. No child API
    /// request is authorised until a later reconcile re-reads the same UID and
    /// payload digest from durable status.
    #[tokio::test]
    async fn child_composition_checkpoints_secret_uid_and_digest_before_first_child_request() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_kubeconfig_secret_json(
                    &server,
                    "child-kubeconfig-secret-uid",
                )),
            )
            .mount(&server)
            .await;

        let mut pool = management_pool(POOL_UID, POOL_GENERATION);
        pool.spec.placement = serde_json::from_value(serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "children"
        }))
        .unwrap();
        let mut lease = child_placed_lease("child-lease-uid");
        let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
        target.child_cluster_kubeconfig_secret = None;
        target.child_cluster_kubeconfig_sha256 = None;
        let cluster_pool: crate::crd::ClusterPool =
            serde_json::from_value(child_cluster_pool_json()).unwrap();
        let lifetime = crate::controllers::sandbox_child::child_lifetime_fits(
            &cluster_pool,
            &pool,
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        let mut internal = crate::controllers::sandbox_child::build_internal_cluster_lease(
            &lease, "children", lifetime,
        )
        .unwrap();
        internal.metadata.uid = Some("child-lease-uid".into());
        internal.metadata.generation = Some(1);
        internal.metadata.resource_version = Some("child-rv-1".into());
        let bound: crate::crd::ClusterLease =
            serde_json::from_value(child_cluster_lease("child-lease-uid", "Bound", None)).unwrap();
        internal.status = bound.status;
        internal.status.as_mut().unwrap().expires_at =
            Some((chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339());
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(internal))
            .mount(&server)
            .await;

        let outcome = compose_child_target(&lease, &pool, "children", &ctx)
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ChildTarget::Pending(action) if action == Action::await_change()
        ));

        let requests = server.received_requests().await.unwrap_or_default();
        let checkpoint = requests.iter().filter_map(status_value_of).next_back();
        assert!(
            checkpoint.is_some(),
            "Secret provenance checkpoint missing; requests: {:?}",
            requests
                .iter()
                .map(|request| format!("{} {}", request.method, request.url.path()))
                .collect::<Vec<_>>()
        );
        let checkpoint = checkpoint.unwrap();
        assert_eq!(
            checkpoint["target"]["childClusterKubeconfigSecret"]["uid"],
            "child-kubeconfig-secret-uid"
        );
        assert_eq!(
            checkpoint["target"]["childClusterKubeconfigSha256"],
            child_placed_lease_with_reachable_access("child-lease-uid", &server)
                .status
                .unwrap()
                .target
                .unwrap()
                .child_cluster_kubeconfig_sha256
                .unwrap()
        );
        assert_eq!(
            requests_to(
                &server,
                "GET",
                &format!("/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}")
            )
            .await,
            0,
            "the checkpointing pass must not authenticate to the child"
        );
        assert!(requests.iter().all(|request| {
            !request
                .url
                .path()
                .starts_with("/apis/agent-sandbox.sigs.k8s.io/")
        }));
    }

    async fn mount_reachable_child_access(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_kubeconfig_secret_json(
                    server,
                    "child-kubeconfig-secret-uid",
                )),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": CHILD_SANDBOX_NAMESPACE,
                    "uid": "child-namespace-uid",
                    "resourceVersion": "namespace-rv-1",
                    "labels": {
                        "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                        crate::sandbox::SANDBOX_LEASE_UID_LABEL: "lease-uid-1",
                    },
                    "annotations": {
                        CHILD_LEASE_NAME_ANNOTATION: LEASE,
                    }
                }
            })))
            .mount(server)
            .await;
    }

    fn attach_test_access_gate(lease: &mut SandboxLease) -> (String, String) {
        use sha2::{Digest as _, Sha256};

        let lease_uid = lease.uid().unwrap();
        let gate = format!(
            "kobe-access-g-{}",
            &format!("{:x}", Sha256::digest(lease_uid.as_bytes()))[..40]
        );
        lease.metadata.annotations.as_mut().unwrap().insert(
            crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION.into(),
            crate::sandbox_access_ledger::encode_gate_reference(
                &crate::sandbox_access_ledger::AccessGateReference {
                    name: gate.clone(),
                    uid: "access-gate-uid".into(),
                },
            )
            .unwrap(),
        );
        let gate_path = format!("{RESERVATIONS_PATH}/{gate}");
        (gate, gate_path)
    }

    async fn mount_closed_execution_gate(
        server: &MockServer,
        lease: &SandboxLease,
        gate: &str,
        gate_path: &str,
        execution_manifest: &str,
    ) {
        let gate_object = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": gate,
                "namespace": NS,
                "uid": "access-gate-uid",
                "resourceVersion": "gate-rv-1",
                "labels": {
                    "kobe.kunobi.ninja/sandbox-access-kind": "lease-gate",
                    "kobe.kunobi.ninja/sandbox-lease-name": lease.name_any(),
                    "kobe.kunobi.ninja/sandbox-access-lease-uid": lease.uid().unwrap(),
                },
                "annotations": {
                    "kobe.kunobi.ninja/sandbox-access-state": "closed",
                    "kobe.kunobi.ninja/sandbox-access-entries": "{}",
                    "kobe.kunobi.ninja/sandbox-executions": execution_manifest,
                },
            },
            "spec": {},
        });
        Mock::given(method("GET"))
            .and(path(gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxExecutionList",
                "metadata":{"resourceVersion":"1"},
                "items":[]
            })))
            .mount(server)
            .await;
    }

    /// Credential ambiguity is not child unreachability. Only a transport
    /// failure from an exact, digest-checked Secret may select destroy-receipt
    /// fallback; management reads, authentication and child 5xx remain
    /// quarantine/retry classes.
    #[tokio::test]
    async fn child_access_classification_never_turns_credential_errors_into_destroy_fallback() {
        for (code, quarantine) in [(404, true), (403, true), (500, false)] {
            let (ctx, server) = test_context().await;
            Mock::given(method("GET"))
                .and(path(
                    "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
                ))
                .respond_with(
                    ResponseTemplate::new(code).set_body_json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "code": code,
                    })),
                )
                .mount(&server)
                .await;
            let lease = child_placed_lease("child-lease-uid");
            let instance = lease
                .status
                .as_ref()
                .unwrap()
                .target
                .as_ref()
                .unwrap()
                .child_cluster_instance
                .as_ref()
                .unwrap();
            let result = recorded_child_access(&lease, &ctx, instance).await;
            if quarantine {
                assert!(
                    matches!(result, RecordedChildAccess::Quarantine(_)),
                    "HTTP {code}"
                );
            } else {
                assert!(
                    matches!(result, RecordedChildAccess::Retry(_)),
                    "HTTP {code}"
                );
            }
        }

        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_kubeconfig_secret_json(
                    &server,
                    "child-kubeconfig-secret-uid",
                )),
            )
            .mount(&server)
            .await;
        let lease = child_placed_lease("child-lease-uid");
        let instance = lease
            .status
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .child_cluster_instance
            .as_ref()
            .unwrap();
        assert!(matches!(
            recorded_child_access(&lease, &ctx, instance).await,
            RecordedChildAccess::Quarantine(_)
        ));
        assert_eq!(
            requests_to(
                &server,
                "GET",
                &format!("/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}")
            )
            .await,
            0,
            "same UID with changed bytes must fail before authenticating"
        );

        for (code, quarantine) in [(403, true), (500, false)] {
            let (ctx, server) = test_context().await;
            Mock::given(method("GET"))
                .and(path(
                    "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    child_kubeconfig_secret_json(&server, "child-kubeconfig-secret-uid"),
                ))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!(
                    "/api/v1/namespaces/{CHILD_SANDBOX_NAMESPACE}"
                )))
                .respond_with(
                    ResponseTemplate::new(code).set_body_json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "code": code,
                    })),
                )
                .mount(&server)
                .await;
            let lease = child_placed_lease_with_reachable_access("child-lease-uid", &server);
            let instance = lease
                .status
                .as_ref()
                .unwrap()
                .target
                .as_ref()
                .unwrap()
                .child_cluster_instance
                .as_ref()
                .unwrap();
            let result = recorded_child_access(&lease, &ctx, instance).await;
            if quarantine {
                assert!(
                    matches!(result, RecordedChildAccess::Quarantine(_)),
                    "HTTP {code}"
                );
            } else {
                assert!(
                    matches!(result, RecordedChildAccess::Retry(_)),
                    "HTTP {code}"
                );
            }
        }

        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        let (ctx, server) = test_context().await;
        let unreachable_kubeconfig =
            child_test_kubeconfig(&server).replace(&server.uri(), "http://127.0.0.1:1");
        let mut secret = child_kubeconfig_secret_json(&server, "child-kubeconfig-secret-uid");
        secret["data"]["kubeconfig"] = base64::engine::general_purpose::STANDARD
            .encode(&unreachable_kubeconfig)
            .into();
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret))
            .mount(&server)
            .await;
        let mut lease = child_placed_lease("child-lease-uid");
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .child_cluster_kubeconfig_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(unreachable_kubeconfig.as_bytes())
        ));
        let instance = lease
            .status
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .child_cluster_instance
            .as_ref()
            .unwrap();
        assert!(matches!(
            recorded_child_access(&lease, &ctx, instance).await,
            RecordedChildAccess::TransportUnreachable
        ));
    }

    /// Model an internal lease through proof ACK and foreground deletion.
    ///
    /// The retention finalizer keeps the terminating object readable; 404 is
    /// not valid completion because it would reopen the deterministic name.
    async fn mount_child_handle_cleanup(
        server: &MockServer,
        visible_reads: u64,
        receipt: Option<serde_json::Value>,
    ) {
        let phase = if receipt.is_some() {
            "Recycling"
        } else {
            "Released"
        };
        let mut visible = child_cluster_lease("child-lease-uid", phase, receipt.clone());
        let (ack_key, proof_value) = if let Some(receipt) = receipt.as_ref() {
            mount_child_evidence(server, receipt).await;
            let receipt: crate::crd::TeardownReceipt =
                serde_json::from_value(receipt.clone()).expect("receipt fixture parses");
            (
                crate::crd::TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION,
                receipt
                    .acknowledgement_token()
                    .expect("complete receipt acknowledgement token"),
            )
        } else {
            let attempt = "never-bound-attempt-1";
            let proof = "2026-08-20T00:00:00Z".to_string();
            visible["status"]["teardownAttemptId"] = attempt.into();
            visible["status"]["unboundReleaseVerifiedAt"] = proof.clone().into();
            visible["status"]["conditions"] = serde_json::json!([{
                "type": "AllocationAbsent",
                "status": "True",
                "reason": "NeverBound",
                "message": format!("release attempt {attempt} proved no reciprocal allocation existed"),
                "lastTransitionTime": proof,
            }]);
            (
                crate::crd::UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION,
                format!("{attempt}:{proof}"),
            )
        };
        serde_json::from_value::<crate::crd::ClusterLease>(visible.clone())
            .expect("child cleanup fixture must deserialize");
        let mut acknowledged = visible.clone();
        acknowledged["metadata"]["resourceVersion"] = "43".into();
        acknowledged["metadata"]["annotations"][ack_key] = proof_value.clone().into();
        let mut terminating = acknowledged.clone();
        terminating["metadata"]["resourceVersion"] = "44".into();
        terminating["metadata"]["deletionTimestamp"] = "2026-08-20T00:10:00Z".into();
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(visible))
            .up_to_n_times(visible_reads)
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(terminating.clone()))
            .with_priority(10)
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(acknowledged))
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(terminating))
            .mount(server)
            .await;
    }

    /// A receipt about the exact instance recorded at composition time.
    fn verified_receipt(instance_name: &str, instance_uid: &str) -> serde_json::Value {
        let binding = child_binding();
        let manifest = binding.creation_manifest.as_ref().unwrap();
        let connect_token = binding.connect_token.as_ref().unwrap();
        let mut subjects = manifest.required_subjects();
        subjects.push(crate::crd::TeardownSubject::ConnectTokenSecret);
        let checks = subjects
            .into_iter()
            .map(|subject| crate::crd::TeardownCheck {
                subject,
                result: crate::crd::CheckResult::Verified,
                reason: None,
                verified: if subject == crate::crd::TeardownSubject::ConnectTokenSecret {
                    vec![connect_token.canonical_id()]
                } else {
                    manifest.identities_for_subject(subject)
                },
            })
            .collect();
        serde_json::to_value(crate::crd::TeardownReceipt {
            schema_version: crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION,
            attempt_id: "attempt-1".into(),
            lease: binding.lease,
            instance: crate::crd::ResourceRef {
                name: instance_name.into(),
                uid: Some(instance_uid.into()),
            },
            pool: binding.pool,
            backend_type: "k3s".into(),
            config_digest: binding.backend.config_digest,
            instance_spec_digest: binding.instance_spec_digest,
            creation_manifest_digest: binding.creation_manifest_digest.unwrap(),
            cleanup_mode: crate::crd::CleanupMode::VerifiedDestroy,
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:05:00Z".into()),
            checks,
            retry_count: 0,
            outcome: crate::crd::TeardownOutcome::Verified,
        })
        .unwrap()
    }

    fn receipt_acknowledgement_token(receipt: &serde_json::Value) -> String {
        serde_json::from_value::<crate::crd::TeardownReceipt>(receipt.clone())
            .expect("receipt fixture parses")
            .acknowledgement_token()
            .expect("complete receipt acknowledgement token")
    }

    const CLUSTER_LEASE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/kobe-sbx-sbx-1";

    /// Pool certification must not make every lease reconcile carry its large
    /// async state machines inline. Release paths run on ordinary Tokio test
    /// and controller worker stacks even though they never execute those
    /// branches.
    #[tokio::test]
    async fn pool_certification_submachines_are_heap_bounded() {
        let (ctx, _server) = test_context().await;
        let future = reconcile_lease(Arc::new(admitted_lease()), ctx);
        let bytes = std::mem::size_of_val(&future);
        assert!(
            bytes < 64 * 1024,
            "reconcile_lease future grew to {bytes} bytes; box large certification submachines"
        );
    }

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
        mount_reachable_child_access(&server).await;
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

        reconcile_release_after_checkpoint(
            child_placed_lease_with_reachable_access("child-lease-uid", &server),
            ctx,
            &server,
        )
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
        assert!(
            phases.iter().all(|phase| phase == "Releasing"),
            "teardown must remain nonterminal until the child receipt exists: {phases:?}"
        );
        let requests = server.received_requests().await.unwrap_or_default();
        let statuses: Vec<serde_json::Value> =
            requests.iter().filter_map(status_value_of).collect();
        assert!(statuses.iter().any(|status| {
            status["childTeardownMode"] == serde_json::json!("ReachableCleanupV1")
        }));
        let mode_checkpoint = requests
            .iter()
            .position(|request| {
                status_value_of(request).is_some_and(|status| {
                    status["childTeardownMode"] == serde_json::json!("ReachableCleanupV1")
                })
            })
            .expect("reachable cleanup mode checkpoint");
        let internal_release = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "PATCH"
                    && request.url.path() == format!("{CLUSTER_LEASE_PATH}/status")
            })
            .expect("internal release request");
        assert!(
            mode_checkpoint < internal_release,
            "the cleanup interpretation must be durable before cluster destruction starts"
        );
    }

    /// A restart consumes the write-once cleanup interpretation instead of
    /// reclassifying credentials. Both modes may request release only after
    /// their status checkpoint is visible, and neither re-reads the Secret on
    /// that destructive pass.
    #[tokio::test]
    async fn restart_uses_durable_child_teardown_mode_before_cluster_release() {
        for mode in [
            crate::crd::SandboxChildTeardownMode::ReachableCleanupV1,
            crate::crd::SandboxChildTeardownMode::VerifiedDestroyFallbackV1,
        ] {
            let (ctx, server) = test_context().await;
            mount_teardown_scaffolding(&server).await;
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

            let mut lease = child_placed_lease("child-lease-uid");
            let status = lease.status.as_mut().unwrap();
            status.phase = crate::crd::SandboxLeasePhase::Releasing;
            status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
            status.child_teardown_mode = Some(mode);

            assert_eq!(
                reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
                Action::requeue(std::time::Duration::from_secs(30))
            );
            assert_eq!(
                requests_to(
                    &server,
                    "GET",
                    "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig"
                )
                .await,
                0,
                "a durable mode is not reinterpreted after restart"
            );
            assert_eq!(
                requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
                1
            );
        }
    }

    /// Reachable-child teardown retires the execution manifest one durable
    /// mutation per pass. It cannot clean scoped credentials, checkpoint a
    /// mode, or release the cluster in the same pass as that ledger mutation.
    #[tokio::test]
    async fn reachable_child_execution_checkpoint_precedes_credentials_and_cluster_release() {
        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        mount_teardown_scaffolding(&server).await;
        mount_reachable_child_access(&server).await;
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

        let mut lease = child_placed_lease_with_reachable_access("child-lease-uid", &server);
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.target.as_mut().unwrap().pod = Some(crate::crd::SandboxObjectReference {
            api_version: "v1".into(),
            kind: "Pod".into(),
            namespace: Some(CHILD_SANDBOX_NAMESPACE.into()),
            name: "sandbox-pod".into(),
            uid: "sandbox-pod-uid".into(),
            generation: None,
        });
        let (gate, gate_path) = attach_test_access_gate(&mut lease);
        let manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "sandbox-pod-uid",
                "reservedAt": "2026-08-20T00:00:00Z",
                "creationState": "rejected",
                "active": false
            }
        })
        .to_string();
        mount_closed_execution_gate(&server, &lease, &gate, &gate_path, &manifest).await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            execution_cleanup_checkpoint_action()
        );
        assert_eq!(requests_to(&server, "PATCH", &gate_path).await, 1);
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(requests.iter().all(|request| {
            let path = request.url.path();
            !path.contains("/serviceaccounts/")
                && !path.contains("/roles/")
                && !path.contains("/rolebindings/")
        }));
        assert!(
            requests
                .iter()
                .filter_map(status_value_of)
                .all(|status| { status.get("childTeardownMode").is_none() })
        );
    }

    /// Transport-only fallback does the inverse ordering: it durably selects
    /// receipt mode without touching a running execution record. Only the
    /// later exact destroy receipt can authorise runner-free retirement.
    #[tokio::test]
    async fn unreachable_child_keeps_execution_manifest_until_destroy_receipt() {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};

        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        mount_teardown_scaffolding(&server).await;
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

        let unreachable_kubeconfig =
            child_test_kubeconfig(&server).replace(&server.uri(), "http://127.0.0.1:1");
        let mut secret = child_kubeconfig_secret_json(&server, "child-kubeconfig-secret-uid");
        secret["data"]["kubeconfig"] = base64::engine::general_purpose::STANDARD
            .encode(&unreachable_kubeconfig)
            .into();
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret))
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status
            .target
            .as_mut()
            .unwrap()
            .child_cluster_kubeconfig_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(unreachable_kubeconfig.as_bytes())
        ));
        let (gate, gate_path) = attach_test_access_gate(&mut lease);
        let manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "pod-uid",
                "reservedAt": "2026-08-20T00:00:00Z",
                "executionUid": "execution-uid",
                "creationState": "bound",
                "active": true
            }
        })
        .to_string();
        mount_closed_execution_gate(&server, &lease, &gate, &gate_path, &manifest).await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(
            requests_to(
                &server,
                "GET",
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions"
            )
            .await,
            0
        );
        assert_eq!(requests_to(&server, "PATCH", &gate_path).await, 0);
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
        let status = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .next_back()
            .expect("fallback mode checkpoint");
        assert_eq!(status["childTeardownMode"], "VerifiedDestroyFallbackV1");
    }

    /// Destruction started by a pre-protocol process carries no durable proof
    /// of whether child cleanup ran. Missing credentials must not be
    /// reinterpreted as transport unreachability on restart.
    #[tokio::test]
    async fn in_flight_child_destroy_without_a_mode_quarantines_on_restart() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut child = child_cluster_lease("child-lease-uid", "Recycling", None);
        child["status"]["clusterName"] = "kobe-abc123".into();
        child["status"]["binding"] = serde_json::to_value(child_binding()).unwrap();
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child))
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(300))
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "GET",
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig"
            )
            .await,
            0
        );
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
    }

    /// A legacy bound handle may be ownerRef-migrated, but it cannot be given a
    /// from-birth credential marker after the fact. Without that marker Kobe
    /// cannot prove which Secret bytes authenticated earlier child requests.
    #[tokio::test]
    async fn active_legacy_child_without_from_birth_credential_protocol_quarantines() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut child = child_cluster_lease("child-lease-uid", "Bound", None);
        child["metadata"]["annotations"]
            .as_object_mut()
            .unwrap()
            .remove(crate::controllers::sandbox_child::CHILD_KUBECONFIG_PROVENANCE_ANNOTATION);
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child))
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(300))
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "GET",
                "/api/v1/namespaces/test-ns/secrets/kobe-abc123-kubeconfig"
            )
            .await,
            0
        );
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0
        );
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

    /// Recovery of an uncheckpointed child allocation requires the exact UID
    /// label. A recreated same-named SandboxLease fails closed.
    #[tokio::test]
    async fn unrecorded_child_with_foreign_identity_quarantines() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut child = child_cluster_lease("child-lease-uid", "Bound", None);
        child["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL] =
            serde_json::json!("replacement-lease-uid");
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        assert_eq!(requests_to(&server, "GET", CLUSTER_LEASE_PATH).await, 1);
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0,
            "a foreign child must not be released"
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "uncertain ownership must retain quota"
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
    }

    async fn assert_exact_v1167179_child_owner_is_migrated(phase: &str) {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut child = child_cluster_lease("child-lease-uid", phase, None);
        // Byte-exact identity metadata from 1167179: managed-by plus the sole
        // controller owner, without the later UID/tombstone/finalizer fence.
        child["metadata"]["labels"] = serde_json::json!({
            "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY
        });
        child["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("annotations");
        child["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("finalizers");
        child["metadata"]["ownerReferences"] = serde_json::json!([{
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxLease",
            "name": LEASE,
            "uid": "lease-uid-1",
            "controller": true,
        }]);
        let mut ownerless = child.clone();
        ownerless["metadata"]["ownerReferences"] = serde_json::json!([]);
        ownerless["metadata"]["resourceVersion"] = "43".into();
        ownerless["metadata"]["labels"][crate::sandbox::SANDBOX_LEASE_UID_LABEL] =
            "lease-uid-1".into();
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(ownerless))
            .expect(1)
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.target.as_mut().unwrap().child_cluster_lease = None;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(5))
        );
        let request = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| {
                request.method.as_str() == "PATCH" && request.url.path() == CLUSTER_LEASE_PATH
            })
            .expect("ownerRef migration patch");
        let patch: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(patch.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/metadata/ownerReferences"
                && operation["value"] == serde_json::json!([])
        }));
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 0);
    }

    /// The exact ownerRef-only Pending shape emitted by 1167179 is migrated
    /// before release; absence of the not-yet-invented UID label is not foreign.
    #[tokio::test]
    async fn pending_v1167179_child_owner_is_migrated_before_use() {
        assert_exact_v1167179_child_owner_is_migrated("Pending").await;
    }

    /// Bound legacy handles use the same exact owner migration before any
    /// reciprocal binding recovery or destructive action.
    #[tokio::test]
    async fn bound_v1167179_child_owner_is_migrated_before_use() {
        assert_exact_v1167179_child_owner_is_migrated("Bound").await;
    }

    /// A Bound handle that won before the outer UID checkpoint is recovered
    /// only after the live lease, instance, and pool prove one reciprocal tuple.
    #[tokio::test]
    async fn unrecorded_bound_child_recovers_the_complete_reciprocal_tuple() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
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

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.placement = None;
        status.target = None;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0,
            "active teardown cannot start before the reciprocal tuple is durable"
        );
        let checkpoint = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("complete child recovery checkpoint");
        assert_eq!(
            checkpoint["target"]["childClusterLease"]["uid"],
            "child-lease-uid"
        );
        assert_eq!(
            checkpoint["target"]["childClusterInstance"]["uid"],
            "child-instance-uid"
        );
        assert_eq!(
            checkpoint["placement"]["clusterPool"]["uid"],
            "cluster-pool-uid"
        );
    }

    /// An uncheckpointed Pending handle is real provenance but not an
    /// allocation. Kobe records its exact UID, requests Released, consumes the
    /// controller's durable NeverBound proof, and returns capacity without
    /// inventing a pool instance.
    #[tokio::test]
    async fn unrecorded_pending_child_converges_through_never_bound_proof() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let pending = child_cluster_lease("child-lease-uid", "Pending", None);
        let attempt = "never-bound-attempt-1";
        let proof = "2026-08-20T00:00:00Z";
        let mut never_bound = child_cluster_lease("child-lease-uid", "Released", None);
        never_bound["status"]["teardownAttemptId"] = attempt.into();
        never_bound["status"]["unboundReleaseVerifiedAt"] = proof.into();
        never_bound["status"]["conditions"] = serde_json::json!([{
            "type": "AllocationAbsent",
            "status": "True",
            "reason": "NeverBound",
            "message": format!("release attempt {attempt} proved no reciprocal allocation existed"),
            "lastTransitionTime": proof,
        }]);
        let mut acknowledged = never_bound.clone();
        acknowledged["metadata"]["resourceVersion"] = "43".into();
        acknowledged["metadata"]["annotations"]
            [crate::crd::UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION] =
            format!("{attempt}:{proof}").into();
        let mut terminating = acknowledged.clone();
        terminating["metadata"]["resourceVersion"] = "44".into();
        terminating["metadata"]["deletionTimestamp"] = "2026-08-20T00:10:00Z".into();

        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(pending))
            .up_to_n_times(3)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(never_bound.clone()))
            // One read checkpoints the attempt-bound proof, one checkpoints
            // FootprintAbsent, and one is revalidated before ACK+delete.
            .up_to_n_times(3)
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(terminating.clone()))
            .with_priority(3)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{CLUSTER_LEASE_PATH}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(never_bound))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(acknowledged))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(terminating))
            .expect(1)
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.placement = None;
        status.target = None;

        for pass in 0..12 {
            let before = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "PATCH" && request.url.path() == LEASE_STATUS_PATH
                })
                .count();
            let _ = reconcile_lease(Arc::new(lease.clone()), ctx.clone())
                .await
                .expect("Pending child release must converge");
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
            if let Some(latest) = statuses.get(before).cloned() {
                lease.status = Some(serde_json::from_value(latest).unwrap());
                lease.metadata.resource_version = Some(format!("pending-proof-rv-{pass}"));
            }
            if lease
                .status
                .as_ref()
                .is_some_and(|status| status.phase == crate::crd::SandboxLeasePhase::Released)
            {
                break;
            }
        }

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(requests_to(&server, "GET", CHILD_POOL_PATH).await, 0);
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

    /// A binding that wins between the handle checkpoint and release is
    /// persisted before teardown, giving the later receipt an exact instance
    /// UID to prove rather than forcing a permanent quarantine after restart.
    #[tokio::test]
    async fn teardown_recovers_child_instance_before_requesting_release() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut child = child_cluster_lease("child-lease-uid", "Bound", None);
        child["status"]["binding"] = serde_json::to_value(child_binding()).unwrap();
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(child))
            .mount(&server)
            .await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.target.as_mut().unwrap().namespace = CHILD_SANDBOX_NAMESPACE.into();
        status.target.as_mut().unwrap().child_cluster_instance = None;

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(
            requests_to(&server, "PATCH", &format!("{CLUSTER_LEASE_PATH}/status")).await,
            0,
            "release waits for the outer identity checkpoint"
        );
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 0);
        let checkpoint = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .rev()
            .find_map(status_value_of)
            .expect("child instance checkpoint");
        assert_eq!(
            checkpoint["target"]["childClusterInstance"]["uid"],
            "child-instance-uid"
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

    /// Explicit child placement plus a missing handle is provenance loss.
    ///
    /// A 404 cannot distinguish "never created" from a handle GCed before its
    /// UID checkpoint. Only a retained handle carrying NeverBound can prove the
    /// former, so the ambiguous shape must keep capacity withheld.
    #[tokio::test]
    async fn child_placement_with_missing_handle_quarantines_and_keeps_capacity() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;

        let mut lease = child_placed_lease("child-lease-uid");
        // Placement is recorded, but handle provenance is missing and the
        // deterministic name reads 404 through the default mock.
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
            Some("Quarantined")
        );
        assert_eq!(
            requests_to(
                &server,
                "DELETE",
                &format!("{RESERVATIONS_PATH}/{}", reservation_name())
            )
            .await,
            0,
            "ambiguous child absence must not return the slot"
        );
    }

    /// A lease released while its child cluster was still being composed must
    /// not have its quota returned on a management-cluster 404.
    ///
    /// The normal create path now checkpoints placement plus exact internal
    /// UID before waiting for a binding. This fixture retains the older
    /// crash-window state to prove recovery from the UID label is also safe:
    /// it checkpoints the handle before requesting release and never treats a
    /// management-cluster Claim 404 as child teardown evidence.
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
        mount_child_handle_cleanup(
            &server,
            2,
            Some(verified_receipt("kobe-abc123", "child-instance-uid")),
        )
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
        assert_eq!(
            requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await,
            1,
            "the receipt handle is removed only after its proof is durable"
        );
    }

    /// Receipt-backed fallback still retires the durable execution inventory
    /// before `FootprintAbsent`, ACK, child-handle deletion, or quota release.
    /// The receipt permits runner-free cancellation; it does not permit the
    /// ledger record to be skipped.
    #[tokio::test]
    async fn child_destroy_receipt_checkpoints_execution_cleanup_before_footprint_absence() {
        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        mount_teardown_scaffolding(&server).await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.child_teardown_mode =
            Some(crate::crd::SandboxChildTeardownMode::VerifiedDestroyFallbackV1);
        let (gate, gate_path) = attach_test_access_gate(&mut lease);
        let manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "pod-uid",
                "reservedAt": "2026-08-20T00:00:00Z",
                "creationState": "rejected",
                "active": false
            }
        })
        .to_string();
        mount_closed_execution_gate(&server, &lease, &gate, &gate_path, &manifest).await;
        let receipt = verified_receipt("kobe-abc123", "child-instance-uid");
        mount_child_evidence(&server, &receipt).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Recycling",
                    Some(receipt),
                )),
            )
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            execution_cleanup_checkpoint_action()
        );
        assert_eq!(requests_to(&server, "PATCH", &gate_path).await, 1);
        let statuses: Vec<_> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(status_value_of)
            .collect();
        assert!(statuses.iter().all(|status| {
            status["conditions"].as_array().is_none_or(|conditions| {
                conditions
                    .iter()
                    .all(|condition| condition["type"] != FOOTPRINT_ABSENT_CONDITION)
            })
        }));
        assert_eq!(requests_to(&server, "PATCH", CLUSTER_LEASE_PATH).await, 0);
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 0);
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

    /// NeverBound is a proof of no allocation, not authority to rewrite a
    /// contradictory execution ledger. One non-empty manifest quarantines and
    /// leaves both the proof handle and quota intact.
    #[tokio::test]
    async fn never_bound_child_with_execution_manifest_quarantines_before_ack_or_release() {
        let (mut ctx, server) = test_context().await;
        Arc::get_mut(&mut ctx).unwrap().access_ledger_enabled = true;
        mount_teardown_scaffolding(&server).await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        let target = status.target.as_mut().unwrap();
        target.child_cluster_instance = None;
        target.child_cluster_kubeconfig_secret = None;
        target.child_cluster_kubeconfig_sha256 = None;
        let (gate, gate_path) = attach_test_access_gate(&mut lease);
        let manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "pod-uid",
                "reservedAt": "2026-08-20T00:00:00Z",
                "creationState": "creating",
                "active": true
            }
        })
        .to_string();
        mount_closed_execution_gate(&server, &lease, &gate, &gate_path, &manifest).await;

        let attempt = "never-bound-attempt-1";
        let proof = "2026-08-20T00:00:00Z";
        lease.status.as_mut().unwrap().child_unbound_release_proof =
            Some(crate::crd::ChildUnboundReleaseProof {
                attempt_id: attempt.into(),
                verified_at: proof.into(),
            });
        let mut never_bound = child_cluster_lease("child-lease-uid", "Released", None);
        never_bound["status"]["teardownAttemptId"] = attempt.into();
        never_bound["status"]["unboundReleaseVerifiedAt"] = proof.into();
        never_bound["status"]["conditions"] = serde_json::json!([{
            "type": "AllocationAbsent",
            "status": "True",
            "reason": "NeverBound",
            "message": format!("release attempt {attempt} proved no reciprocal allocation existed"),
            "lastTransitionTime": proof,
        }]);
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(never_bound))
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(300))
        );
        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Quarantined")
        );
        assert_eq!(requests_to(&server, "PATCH", &gate_path).await, 0);
        assert_eq!(requests_to(&server, "PATCH", CLUSTER_LEASE_PATH).await, 0);
        assert_eq!(requests_to(&server, "DELETE", CLUSTER_LEASE_PATH).await, 0);
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

    /// A sealed receipt authenticates the pool by its recorded UID; deleting
    /// the live ClusterPool after teardown cannot make that durable proof
    /// unconsumable either before or after FootprintAbsent is checkpointed.
    #[tokio::test]
    async fn exact_receipt_completes_when_the_recorded_pool_is_already_404() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        Mock::given(method("GET"))
            .and(path(CHILD_POOL_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_child_handle_cleanup(
            &server,
            2,
            Some(verified_receipt("kobe-abc123", "child-instance-uid")),
        )
        .await;

        reconcile_release_after_checkpoint(child_placed_lease("child-lease-uid"), ctx, &server)
            .await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(
            requests_to(&server, "GET", CHILD_POOL_PATH).await,
            0,
            "proof consumption must not depend on a live pool GET"
        );
    }

    /// NeverBound is likewise self-contained. A same-named replacement pool
    /// cannot block ACK/retirement after the outer proof checkpoint.
    #[tokio::test]
    async fn exact_never_bound_finishes_after_pool_replacement() {
        let (ctx, server) = test_context().await;
        mount_teardown_scaffolding(&server).await;
        let mut replacement = child_cluster_pool_json();
        replacement["metadata"]["uid"] = "replacement-pool-uid".into();
        Mock::given(method("GET"))
            .and(path(CHILD_POOL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_child_handle_cleanup(&server, 1, None).await;

        let mut lease = child_placed_lease("child-lease-uid");
        let status = lease.status.as_mut().unwrap();
        status.phase = crate::crd::SandboxLeasePhase::Releasing;
        status.release_cause = Some(crate::crd::SandboxReleaseCause::Requested);
        status.target.as_mut().unwrap().child_cluster_instance = None;
        status.child_unbound_release_proof = Some(crate::crd::ChildUnboundReleaseProof {
            attempt_id: "never-bound-attempt-1".into(),
            verified_at: "2026-08-20T00:00:00Z".into(),
        });
        status.conditions = with_condition_for_status(
            status,
            lease.metadata.generation,
            FOOTPRINT_ABSENT_CONDITION,
            crate::crd::SandboxConditionStatus::True,
            "ChildProofVerified",
            "exact NeverBound proof was checkpointed",
        );

        reconcile_release_after_checkpoint(lease, ctx, &server).await;

        assert_eq!(
            recorded_phases(&server).await.last().map(String::as_str),
            Some("Released")
        );
        assert_eq!(requests_to(&server, "GET", CHILD_POOL_PATH).await, 0);
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
        let receipt = verified_receipt("kobe-later", "a-later-instance-uid");
        mount_child_evidence(&server, &receipt).await;
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_lease(
                    "child-lease-uid",
                    "Recycling",
                    Some(receipt),
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
        let recorded_lease = crate::crd::SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterLease".into(),
            namespace: Some(NS.into()),
            name: "kobe-sbx-sbx-1".into(),
            uid: "child-lease-uid".into(),
            generation: Some(1),
        };
        let recorded_pool = crate::crd::SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterPool".into(),
            namespace: Some(NS.into()),
            name: "children".into(),
            uid: "cluster-pool-uid".into(),
            generation: Some(1),
        };
        let parse = |value: serde_json::Value| -> crate::crd::TeardownReceipt {
            serde_json::from_value(value).expect("receipt fixture parses")
        };
        let proves = |receipt: &crate::crd::TeardownReceipt,
                      instance: Option<&crate::crd::SandboxObjectReference>| {
            let lease: crate::crd::ClusterLease = serde_json::from_value(child_cluster_lease(
                "child-lease-uid",
                "Recycling",
                Some(serde_json::to_value(receipt).unwrap()),
            ))
            .unwrap();
            validated_child_receipt_token(
                &lease,
                receipt,
                &recorded_lease,
                instance,
                &recorded_pool,
            )
            .is_some()
        };

        let good = parse(verified_receipt("kobe-abc123", "child-instance-uid"));
        assert!(proves(&good, Some(&recorded)));

        // No recorded instance: nothing to compare against.
        assert!(!proves(&good, None));

        // An empty recorded UID must not be satisfiable.
        let mut blank = recorded.clone();
        blank.uid = String::new();
        let mut blank_receipt = good.clone();
        blank_receipt.instance.uid = Some(String::new());
        assert!(!proves(&blank_receipt, Some(&blank)));

        let mut quarantined = good.clone();
        quarantined.outcome = crate::crd::TeardownOutcome::Quarantined;
        assert!(!proves(&quarantined, Some(&recorded)));

        let mut unfinished = good.clone();
        unfinished.completed_at = None;
        assert!(!proves(&unfinished, Some(&recorded)));

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
        assert!(!proves(&inconsistent, Some(&recorded)));

        let mut future_schema = good.clone();
        future_schema.schema_version = crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION + 1;
        assert!(!proves(&future_schema, Some(&recorded)));

        // Right UID, wrong name — a shape mismatch that should never occur, and
        // must not be resolved in favour of releasing capacity.
        let mut renamed = good.clone();
        renamed.instance.name = "kobe-something-else".into();
        assert!(!proves(&renamed, Some(&recorded)));
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
