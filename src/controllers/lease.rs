use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kobe_state_machine::{
    BindingState as ModelBindingState, FinalizationDecision, InstancePhase as ModelInstancePhase,
    LeasePhase as ModelLeasePhase, exact_binding_finalization,
};
use kube::api::{
    Api, DeleteParams, ListParams, PartialObjectMeta, Patch, PatchParams, Preconditions,
};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::auth::JwtAuthenticator;
use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{
    BackendProvenance, BoundInstanceRef, CleanupMode, ClusterInstance, ClusterInstancePhase,
    ClusterLease, ClusterLeaseCondition, ClusterLeaseStatus, ClusterPool, ClusterPoolPhase,
    ClusterPoolStatus, ConnectTokenCreation, ConnectTokenCreationPhase, LeaseBinding, LeasePhase,
    ResourceRef, SandboxPlacementAuthority, TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION,
    TEARDOWN_RECEIPT_RETENTION_FINALIZER, TeardownAcknowledgedProofKind,
    UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION,
};
use crate::diagnostics;
use crate::lease_binding::BindingResolutionError;
use crate::pool::{
    PoolState, RenderContext, parse_duration, profile_spec_hash, resolve_bootstrap_specs,
    spec_hash_is_current,
};

#[derive(Debug)]
struct SandboxCompositionIdentity {
    outer_name: String,
    outer_uid: String,
}

#[derive(Debug)]
enum SandboxCompositionGate {
    NotComposition,
    Authorized(SandboxPlacementAuthority),
    LegacyBoundRecovery,
    NeedsMigration(SandboxCompositionIdentity),
    Closed(SandboxCompositionIdentity),
    Invalid,
    Retry,
}

/// The outer Sandbox authority is exact only while the named live ClusterPool
/// still has the UID and generation admitted by Kobe.
fn live_cluster_pool_matches_sandbox_authority(
    pool: &ClusterPool,
    authority: &SandboxPlacementAuthority,
    namespace: &str,
) -> bool {
    authority.api_version == "kobe.kunobi.ninja/v1alpha1"
        && authority.kind == "ClusterPool"
        && authority.namespace == namespace
        && pool.is_recorded_pool(namespace, &authority.name, &authority.uid)
        && pool.metadata.generation == Some(authority.generation)
}

/// A binding records a pool UID but no generation. Its name and UID must match
/// the immutable outer authority; the gate's fresh live-pool read supplies the
/// generation and deletion-state half of the proof.
fn binding_pool_matches_sandbox_authority(
    binding: &LeaseBinding,
    authority: &SandboxPlacementAuthority,
) -> bool {
    binding.pool.name == authority.name
        && binding.pool.uid.as_deref() == Some(authority.uid.as_str())
}

fn sandbox_composition_retention_metadata(
    lease: &ClusterLease,
    identity: &SandboxCompositionIdentity,
    stale_rejected: bool,
) -> (
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
    Vec<String>,
) {
    crate::controllers::sandbox_child::child_handle_retention_metadata(
        lease,
        &identity.outer_name,
        &identity.outer_uid,
        stale_rejected,
        chrono::Utc::now(),
    )
}

fn sandbox_composition_retention_fence_matches(
    lease: &ClusterLease,
    identity: &SandboxCompositionIdentity,
) -> bool {
    let (labels, annotations, finalizers) =
        sandbox_composition_retention_metadata(lease, identity, false);
    lease
        .metadata
        .owner_references
        .as_ref()
        .is_none_or(Vec::is_empty)
        && lease.metadata.labels.as_ref() == Some(&labels)
        && lease.metadata.annotations.as_ref() == Some(&annotations)
        && lease.metadata.finalizers.as_ref() == Some(&finalizers)
}

/// Authorize an internal Sandbox composition at the last controller boundary
/// before it can enter the ordinary ClusterLease allocation queue.
///
/// A POST may commit after the creating HTTP future was cancelled. The durable
/// coordination fence therefore has to be enforced by the consumer as well as
/// by the producer: a late Pending handle is terminalized before it can write a
/// binding intent or reserve a ClusterInstance.
async fn sandbox_composition_allocation_gate(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> SandboxCompositionGate {
    if lease.spec.requester.requester_type != "kobe:sandbox-composition" {
        return SandboxCompositionGate::NotComposition;
    }
    let derived_outer = lease
        .name_any()
        .strip_prefix("kobe-sbx-")
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    let Some(outer_name) = derived_outer else {
        return SandboxCompositionGate::Invalid;
    };
    if lease
        .annotations()
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION)
        .is_some_and(|annotated| annotated != &outer_name)
    {
        return SandboxCompositionGate::Invalid;
    }
    if lease
        .labels()
        .get("app.kubernetes.io/managed-by")
        .is_none_or(|value| value != crate::sandbox::KOBE_MANAGED_BY)
        || lease.spec.cleanup_mode != Some(crate::crd::CleanupMode::VerifiedDestroy)
    {
        return SandboxCompositionGate::Invalid;
    }

    // Base producers had no outer-UID label: the sole exact controller owner
    // was their identity. Newer producers use the UID label and no ownerRef.
    // During a rolling upgrade both may be present, but they must agree.
    let labelled_uid = lease
        .labels()
        .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
        .filter(|uid| !uid.is_empty())
        .cloned();
    let legacy_uid = match lease
        .metadata
        .owner_references
        .as_ref()
        .filter(|owners| !owners.is_empty())
    {
        None => None,
        Some(owners)
            if owners.len() == 1
                && owners[0].api_version == "kobe.kunobi.ninja/v1alpha1"
                && owners[0].kind == "SandboxLease"
                && owners[0].name == outer_name
                && !owners[0].uid.is_empty()
                && owners[0].controller == Some(true) =>
        {
            Some(owners[0].uid.clone())
        }
        Some(_) => return SandboxCompositionGate::Invalid,
    };
    if matches!((&labelled_uid, &legacy_uid), (Some(labelled), Some(legacy)) if labelled != legacy)
    {
        return SandboxCompositionGate::Invalid;
    }
    let Some(outer_uid) = labelled_uid.or(legacy_uid) else {
        return SandboxCompositionGate::Invalid;
    };
    if lease.spec.requester.identity.as_str() != outer_uid.as_str()
        && lease.spec.requester.identity != "kobe-operator"
    {
        return SandboxCompositionGate::Invalid;
    }

    let identity = SandboxCompositionIdentity {
        outer_name: outer_name.clone(),
        outer_uid: outer_uid.clone(),
    };
    let stale_rejected = lease
        .annotations()
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION);
    if stale_rejected.is_some_and(|uid| uid != &outer_uid) {
        return SandboxCompositionGate::Invalid;
    }
    if lease.metadata.deletion_timestamp.is_some()
        || stale_rejected.is_some_and(|uid| uid == &outer_uid)
    {
        return SandboxCompositionGate::Closed(identity);
    }
    let outers: Api<crate::crd::SandboxLease> = Api::namespaced(client.clone(), namespace);
    let outer = match outers.get(&outer_name).await {
        Ok(outer) => outer,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return SandboxCompositionGate::Closed(identity);
        }
        Err(_) => return SandboxCompositionGate::Retry,
    };
    if lease
        .status
        .as_ref()
        .is_some_and(|status| status.phase == LeasePhase::Bound)
        && outer.uid().as_deref() == Some(outer_uid.as_str())
        && outer.spec.placement_authority.is_none()
    {
        return SandboxCompositionGate::LegacyBoundRecovery;
    }
    let outer_is_open = outer.uid().as_deref() == Some(outer_uid.as_str())
        && crate::controllers::sandbox::sandbox_lease_authorizes_allocation(&outer);
    if !outer_is_open {
        return SandboxCompositionGate::Closed(identity);
    }

    let Some(authority) = outer.spec.placement_authority.as_ref() else {
        // A Pending handle from a pre-authority producer cannot safely select
        // same-named capacity. Already-Bound legacy recovery never enters this
        // allocation gate.
        return SandboxCompositionGate::Closed(identity);
    };
    if authority.api_version != "kobe.kunobi.ninja/v1alpha1"
        || authority.kind != "ClusterPool"
        || authority.namespace != namespace
        || authority.name != lease.spec.pool_ref
        || authority.uid.is_empty()
        || authority.generation < 1
    {
        return SandboxCompositionGate::Invalid;
    }
    let pools: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let live_pool = match pools.get(&authority.name).await {
        Ok(pool) => pool,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return SandboxCompositionGate::Closed(identity);
        }
        Err(_) => return SandboxCompositionGate::Retry,
    };
    if !live_cluster_pool_matches_sandbox_authority(&live_pool, authority, namespace) {
        return SandboxCompositionGate::Closed(identity);
    }

    let fences: Api<k8s_openapi::api::coordination::v1::Lease> =
        Api::namespaced(client.clone(), namespace);
    match fences
        .get(&crate::controllers::sandbox::allocation_fence_name(
            &outer_name,
        ))
        .await
    {
        Err(kube::Error::Api(error)) if error.code == 404 => {
            if sandbox_composition_retention_fence_matches(lease, &identity) {
                SandboxCompositionGate::Authorized(authority.clone())
            } else {
                SandboxCompositionGate::NeedsMigration(identity)
            }
        }
        Ok(_) => SandboxCompositionGate::Closed(identity),
        Err(_) => SandboxCompositionGate::Retry,
    }
}

/// Re-run the complete outer/live-pool proof for one proposed or resumed
/// reservation. `false` is a durable fail-closed result; an unavailable API
/// read is surfaced so the caller retries without writing authority-bearing
/// token or binding state.
async fn sandbox_composition_binding_is_authorized(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    binding: &LeaseBinding,
) -> Result<bool, LeaseError> {
    match sandbox_composition_allocation_gate(client, namespace, lease).await {
        SandboxCompositionGate::NotComposition => Ok(true),
        SandboxCompositionGate::Authorized(authority) => {
            Ok(binding_pool_matches_sandbox_authority(binding, &authority))
        }
        SandboxCompositionGate::Retry => Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Sandbox composition authority unavailable while reserving capacity"
        ))),
        SandboxCompositionGate::NeedsMigration(_)
        | SandboxCompositionGate::Closed(_)
        | SandboxCompositionGate::LegacyBoundRecovery
        | SandboxCompositionGate::Invalid => Ok(false),
    }
}

/// Atomically migrate an exact base composition before it can enter the queue.
///
/// The base object depended on the outer `SandboxLease` ownerRef and lacked its
/// durable UID label. A single UID/resourceVersion-fenced metadata patch clears
/// the GC edge and installs the label, tombstone marker, retention deadline,
/// and finalizer. The caller always ends the pass after this function.
async fn migrate_sandbox_composition_retention_fence(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    identity: &SandboxCompositionIdentity,
) -> Result<Action, LeaseError> {
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let (labels, annotations, finalizers) =
        sandbox_composition_retention_metadata(lease, identity, false);
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/metadata/ownerReferences", "value": [] },
        { "op": "add", "path": "/metadata/labels", "value": labels },
        { "op": "add", "path": "/metadata/annotations", "value": annotations },
        { "op": "add", "path": "/metadata/finalizers", "value": finalizers }
    ]));
    match leases
        .patch(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(Action::await_change()),
        Err(error) if optimistic_conflict(&error) => {
            Ok(Action::requeue(std::time::Duration::from_secs(1)))
        }
        Err(error) => Err(error.into()),
    }
}

async fn close_stale_sandbox_composition(
    client: &Client,
    namespace: &str,
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    identity: &SandboxCompositionIdentity,
) -> Result<Action, LeaseError> {
    let Some(uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let Some(resource_version) = lease.resource_version() else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let (labels, annotations, finalizers) =
        sandbox_composition_retention_metadata(lease, identity, true);
    let fenced = lease
        .metadata
        .owner_references
        .as_ref()
        .is_none_or(Vec::is_empty)
        && lease.metadata.labels.as_ref() == Some(&labels)
        && lease.metadata.annotations.as_ref() == Some(&annotations)
        && lease.metadata.finalizers.as_ref() == Some(&finalizers);
    let current = if !fenced {
        let patch = json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "add", "path": "/metadata/ownerReferences", "value": [] },
            { "op": "add", "path": "/metadata/labels", "value": labels },
            { "op": "add", "path": "/metadata/annotations", "value": annotations },
            { "op": "add", "path": "/metadata/finalizers", "value": finalizers }
        ]));
        match leases
            .patch(
                &lease.name_any(),
                &PatchParams::default(),
                &Patch::<()>::Json(patch),
            )
            .await
        {
            Ok(current) => current,
            Err(error) if optimistic_conflict(&error) => {
                return Ok(Action::requeue(std::time::Duration::from_secs(1)));
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        lease.clone()
    };

    let Some(uid) = current.uid().filter(|uid| !uid.is_empty()) else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let Some(resource_version) = current.resource_version() else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let mut next = current.status.clone().unwrap_or_default();
    next.phase = LeasePhase::Released;
    next.message = Some("stale Sandbox composition rejected by allocation fence".into());
    let patch = if current.status.is_some() {
        json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "test", "path": "/status/phase", "value": "Pending" },
            { "op": "add", "path": "/status", "value": next }
        ]))
    } else {
        json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "add", "path": "/status", "value": next }
        ]))
    };
    match leases
        .patch_status(
            &current.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(released) => {
            if let Some(binding) = released
                .status
                .as_ref()
                .and_then(|status| status.binding.as_ref())
                && !mark_instance_recycling(client, namespace, binding).await?
            {
                return Ok(Action::requeue(std::time::Duration::from_secs(1)));
            }
            Ok(Action::requeue(std::time::Duration::from_secs(1)))
        }
        Err(error) if optimistic_conflict(&error) => {
            Ok(Action::requeue(std::time::Duration::from_secs(1)))
        }
        Err(error) => Err(error.into()),
    }
}

async fn quarantine_invalid_sandbox_composition(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
) -> Result<Action, LeaseError> {
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    };
    let mut next = lease.status.clone().unwrap_or_default();
    next.phase = LeasePhase::Quarantined;
    next.message = Some("internal Sandbox composition identity is invalid".into());
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/status", "value": next }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(Action::await_change()),
        Err(error) if optimistic_conflict(&error) => Ok(Action::await_change()),
        Err(error) => Err(error.into()),
    }
}

const CONNECT_TOKEN_CREATE_FENCE_ANNOTATION: &str =
    "kobe.kunobi.ninja/connect-token-binding-before-create-v1";
const ALLOCATION_ABSENT_CONDITION: &str = "AllocationAbsent";

/// Shared state for the lease controller.
pub struct LeaseContext<B: ClusterBackend> {
    pub client: Client,
    /// Ambient default backend. **Never an authorization or dispatch input.**
    /// Teardown and access dispatch resolve through the binding's immutable
    /// `BackendProvenance` (see #79), so production code no longer reads this;
    /// only the controller tests still inspect it for call counts.
    #[allow(dead_code)]
    pub backend: B,
    /// Legacy shared pool cache kept during the ClusterInstance migration.
    #[allow(dead_code)]
    pub pools: Arc<RwLock<std::collections::HashMap<String, PoolState>>>,
    /// Priority queue of pending leases per profile.
    pub queues: RwLock<HashMap<String, Vec<PendingLease>>>,
    /// In-process guard against overlapping reconciles for the same lease.
    pub active_reconciles: Mutex<HashSet<String>>,
    /// Operator namespace.
    pub namespace: String,
    /// Authenticator for policy lookups by requester_type.
    pub authenticator: Arc<JwtAuthenticator>,
    /// Legacy backend factory kept during the ClusterInstance migration.
    #[allow(dead_code)]
    pub factory: Option<BackendFactory>,
    /// ClusterInstances as the controller's instance watch last saw them.
    /// Sizes the bind window (see [`bind_window`]). `None` outside the running
    /// controller, which leaves the window at the queue head.
    pub instances: Option<Store<ClusterInstance>>,
    /// Wakes the leases a queue removal moved into the bind window. `None`
    /// outside the running controller.
    pub queue_wakes: Option<tokio::sync::mpsc::UnboundedSender<ObjectRef<ClusterLease>>>,
    /// Consecutive failed reconciles per lease, for [`error_policy`] backoff.
    pub failures: Mutex<HashMap<String, u32>>,
}

struct ActiveLeaseReconcileGuard<'a> {
    active_reconciles: &'a Mutex<HashSet<String>>,
    lease_name: String,
}

impl Drop for ActiveLeaseReconcileGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut active_reconciles) = self.active_reconciles.lock() {
            active_reconciles.remove(&self.lease_name);
        }
    }
}

/// A pending lease in the priority queue.
#[derive(Debug, Clone)]
pub struct PendingLease {
    pub lease_name: String,
    pub priority: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Error type for the lease controller.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] anyhow::Error),
}

/// Start the lease reconciler controller.
///
/// Besides its own ClusterLease watch, the controller reconciles on:
/// - ClusterInstance events: a lease named by an instance (binding or
///   leaseRef, now or on the previous event), and the front of a pool's queue
///   when one of its instances becomes free capacity. See
///   [`instance_lease_triggers`].
/// - connect-token Secret events, for NeverBound proof. See
///   [`connect_token_lease_triggers`].
/// - queue removals, which wake the leases that entered the bind window. See
///   [`LeaseContext::dequeue`].
///
/// ClusterLease deletions are also evicted from the in-memory queue as they
/// happen, so a deleted Pending lease does not hold a queue slot until the
/// reaper's next sweep.
pub async fn run_lease_controller<B: ClusterBackend + Clone + 'static>(
    client: Client,
    namespace: &str,
    backend: B,
    pools: Arc<RwLock<std::collections::HashMap<String, PoolState>>>,
    authenticator: Arc<JwtAuthenticator>,
    factory: Option<BackendFactory>,
    shutdown: CancellationToken,
) {
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<PartialObjectMeta<Secret>> = Api::namespaced(client.clone(), namespace);
    let (instance_store, instance_writer) = kube::runtime::reflector::store();
    let (queue_wakes, queue_wake_requests) = tokio::sync::mpsc::unbounded_channel();

    let ctx = Arc::new(LeaseContext {
        client: client.clone(),
        backend,
        pools,
        queues: RwLock::new(HashMap::new()),
        active_reconciles: Mutex::new(HashSet::new()),
        namespace: namespace.to_string(),
        authenticator,
        factory,
        instances: Some(instance_store),
        queue_wakes: Some(queue_wakes),
        failures: Mutex::new(HashMap::new()),
    });

    rebuild_queues(&ctx).await;

    let reaper_ctx = ctx.clone();
    let reaper_ns = namespace.to_string();
    let reaper_shutdown = shutdown.clone();
    tokio::spawn(async move {
        run_reaper(reaper_ctx, &reaper_ns, reaper_shutdown).await;
    });

    info!("Starting lease controller");

    let controller = Controller::new(leases.clone(), Config::default());
    let lease_store = controller.store();
    // Every extra watch is built with `default_backoff()`: `watches_with`
    // retries without one, and a failing watch would spin.
    let controller = controller
        .reconcile_on(instance_lease_triggers(
            instances,
            Some(PendingWakes {
                instances: instance_writer,
                leases: lease_store,
            }),
        ))
        .reconcile_on(connect_token_lease_triggers(secrets))
        .reconcile_on(lease_deletion_evictions(leases, ctx.clone()))
        .reconcile_on(futures::stream::unfold(
            queue_wake_requests,
            |mut requests| async move { requests.recv().await.map(|lease| (lease, requests)) },
        ))
        .run(reconcile_lease_tracked, error_policy, ctx)
        .for_each(|result| async move { observe_lease_result(result) });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Lease controller shutting down");
        },
    }
}

type LeaseRunResult = Result<
    (ObjectRef<ClusterLease>, Action),
    kube::runtime::controller::Error<LeaseError, kube::runtime::watcher::Error>,
>;

/// Whether a controller-stream error only says a trigger woke an object that
/// is already gone.
///
/// Every teardown produces these: an instance's last patches wake the lease it
/// named after that lease was deleted, and deleting an instance wakes it
/// through its garbage-collected Jobs and CIDRClaims. kube-runtime reports
/// each as `ObjectNotFound`; none is a failed reconcile.
pub(crate) fn woke_deleted_object<R, Q>(error: &kube::runtime::controller::Error<R, Q>) -> bool {
    matches!(error, kube::runtime::controller::Error::ObjectNotFound(_))
}

/// Count and log one lease controller result. A wake for a deleted lease is
/// neither success nor failure (see [`woke_deleted_object`]).
fn observe_lease_result(result: LeaseRunResult) {
    match result {
        Ok((obj, _action)) => {
            crate::metrics::RECONCILIATIONS_TOTAL
                .with_label_values(&["lease", "ok"])
                .inc();
            debug!(lease = %obj.name, "Lease reconciled");
        }
        Err(error) if woke_deleted_object(&error) => {
            debug!(%error, "Lease trigger woke a deleted lease");
        }
        Err(e) => {
            crate::metrics::RECONCILIATIONS_TOTAL
                .with_label_values(&["lease", "error"])
                .inc();
            error!("Lease reconciliation error: {e:?}");
        }
    }
}

/// Backstop for a Pending lease. Instance events and queue removals wake it;
/// this only covers an event the watches missed.
const PENDING_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(30);
/// Backstop while a Recycling lease waits for its instance to be deleted. The
/// instance watch delivers the delete.
const RECYCLING_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(60);
/// Retry after a failed ClusterInstance read while Recycling.
const RECYCLING_READ_RETRY: std::time::Duration = std::time::Duration::from_secs(15);
/// Backstop while NeverBound proof waits for the connect token and every
/// instance reference to go. The Secret and instance watches deliver both.
const NEVER_BOUND_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(30);
/// Retry after an optimistic-concurrency conflict. The object changed under
/// us; re-reading it right away is usually the whole fix.
const CONFLICT_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
/// Consecutive failures that still retry after [`CONFLICT_RETRY`] when they
/// are conflicts. Past this, a lagging store is the likelier cause, and
/// conflicts join the exponential backoff.
const FAST_CONFLICT_RETRIES: u32 = 3;
/// First retry after a failed reconcile. Doubles per consecutive failure.
const ERROR_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(2);
/// Longest retry after repeated failed reconciles.
const ERROR_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(300);

impl<B: ClusterBackend> LeaseContext<B> {
    /// How many Pending leases of `pool` may attempt a reservation at once.
    fn bind_window(&self, pool: &str) -> usize {
        bind_window(
            self.instances
                .as_ref()
                .map_or(0, |store| free_instances_in_pool(&store.state(), pool)),
        )
    }

    /// Remove a lease from its pool's queue and wake the leases the removal
    /// moved into the bind window. Without the wake, the next lease only
    /// noticed on its backstop timer.
    async fn dequeue(&self, pool: &str, lease_name: &str) {
        let Some(removed_at) = remove_from_queue(&self.queues, pool, lease_name).await else {
            return;
        };
        if removed_at < self.bind_window(pool) {
            self.wake_window(pool).await;
        }
    }

    /// Wake the leases currently inside `pool`'s bind window.
    async fn wake_window(&self, pool: &str) {
        let Some(wakes) = self.queue_wakes.as_ref() else {
            return;
        };
        let window = self.bind_window(pool);
        let names = {
            let queues = self.queues.read().await;
            queues
                .get(pool)
                .map(|queue| queue_window(queue, window))
                .unwrap_or_default()
        };
        for name in names {
            // The receiver only closes when the controller stops.
            let _ = wakes.send(ObjectRef::new(&name).within(&self.namespace));
        }
    }
}

/// Number of Pending leases allowed to attempt reservation: one per free
/// instance, and always at least the queue head.
///
/// A strict head-of-line queue let one unsatisfiable head (say, one that
/// cannot accept any Ready instance's provenance) hold every other lease of
/// the pool until its queue timeout, even with several instances Ready.
/// Leases inside the window reserve concurrently. That is safe: the instance
/// reservation is a resourceVersion-fenced status patch, so two leases racing
/// for the same instance produce one `Reserved` and one `Occupied`, and the
/// loser clears its own intent and waits. Leases outside the window still
/// wait, so when capacity is scarcer than demand, priority order decides who
/// binds. With a single free instance the window is the head alone, and an
/// unsatisfiable head still blocks its pool until the queue timeout. See
/// [`candidates_for_slot`] for which instance each slot may take.
fn bind_window(free_instances: usize) -> usize {
    free_instances.max(1)
}

/// Whether `instance` is free capacity a Pending lease may reserve: Ready,
/// carrying neither side of a reservation, and not being deleted.
fn instance_is_free_capacity(instance: &ClusterInstance) -> bool {
    // An instance under deletion is not free capacity, however idle its
    // status looks. Between `deletionTimestamp` being set and the finalizer
    // completing, phase can still read Ready with no leaseRef; binding there
    // would hand a tenant a cluster that is going away, and
    // `resolve_lease_binding` would then refuse the connection
    // (`InstanceDeleting`) on a lease that already reached Bound and consumed
    // pool capacity.
    //
    // A genuinely-free instance carries neither side of a reciprocal
    // reservation. A stale full-status writer may revert phase or drop the
    // display-only leaseRef while the authoritative binding survives;
    // selecting that instance would manufacture a competing lease intent and
    // risk clearing it before the adopted pair reaches verified teardown.
    instance.metadata.deletion_timestamp.is_none()
        && instance.status.as_ref().is_some_and(|status| {
            status.phase == ClusterInstancePhase::Ready
                && status.lease_ref.is_none()
                && status.binding.is_none()
        })
}

const POOL_LABEL: &str = "kobe.kunobi.ninja/pool";

fn instance_pool(instance: &ClusterInstance) -> Option<&str> {
    instance.labels().get(POOL_LABEL).map(String::as_str)
}

fn free_instances_in_pool(instances: &[Arc<ClusterInstance>], pool: &str) -> usize {
    instances
        .iter()
        .filter(|instance| instance_pool(instance) == Some(pool))
        .filter(|instance| instance_is_free_capacity(instance))
        .count()
}

/// Names of the first `window` queued leases, in queue order.
fn queue_window(queue: &[PendingLease], window: usize) -> Vec<String> {
    queue
        .iter()
        .take(window)
        .map(|pending| pending.lease_name.clone())
        .collect()
}

/// Leases an instance names through its reservation (`binding` or `leaseRef`).
fn leases_named_by_instance(instance: &ClusterInstance) -> std::collections::BTreeSet<String> {
    let Some(status) = instance.status.as_ref() else {
        return Default::default();
    };
    status
        .binding
        .iter()
        .map(|binding| binding.lease.name.clone())
        .chain(
            status
                .lease_ref
                .iter()
                .map(|reference| reference.name.clone()),
        )
        .collect()
}

/// Remembers which leases each instance named on its previous event.
///
/// An update that drops a reservation no longer names the lease, yet that
/// lease may be the one waiting for it: NeverBound proof waits for every
/// instance reference to go. Reporting the union of old and new names wakes
/// it.
#[derive(Default)]
struct InstanceLeaseIndex {
    named: HashMap<String, std::collections::BTreeSet<String>>,
}

impl InstanceLeaseIndex {
    fn applied(&mut self, instance: &ClusterInstance) -> std::collections::BTreeSet<String> {
        let current = leases_named_by_instance(instance);
        let mut touched = self
            .named
            .insert(instance.name_any(), current.clone())
            .unwrap_or_default();
        touched.extend(current);
        touched
    }

    fn deleted(&mut self, instance: &ClusterInstance) -> std::collections::BTreeSet<String> {
        let mut touched = self.named.remove(&instance.name_any()).unwrap_or_default();
        touched.extend(leases_named_by_instance(instance));
        touched
    }
}

/// Pending leases to wake because `instance` is free capacity: the first
/// `window` Pending leases of its pool, in queue order (priority, then age).
fn pending_leases_to_wake(
    instance: &ClusterInstance,
    leases: &[Arc<ClusterLease>],
    window: usize,
) -> Vec<String> {
    let Some(pool) = instance_pool(instance) else {
        return Vec::new();
    };
    if !instance_is_free_capacity(instance) {
        return Vec::new();
    }
    let mut pending: Vec<&ClusterLease> = leases
        .iter()
        .map(AsRef::as_ref)
        .filter(|lease| lease.spec.pool_ref == pool)
        .filter(|lease| lease.metadata.deletion_timestamp.is_none())
        .filter(|lease| {
            lease
                .status
                .as_ref()
                .is_none_or(|status| status.phase == LeasePhase::Pending)
        })
        .collect();
    pending.sort_by(|a, b| {
        b.spec
            .priority
            .cmp(&a.spec.priority)
            .then(created_at_for(a).cmp(&created_at_for(b)))
    });
    pending
        .into_iter()
        .take(window)
        .map(|lease| lease.name_any())
        .collect()
}

/// Where an instance watch finds the queues it may wake.
struct PendingWakes {
    /// Reflects the instance watch; its store sizes the bind window.
    instances: kube::runtime::reflector::store::Writer<ClusterInstance>,
    /// The lease controller's store, to find a pool's Pending leases.
    leases: Store<ClusterLease>,
}

/// Reconcile requests for the leases an instance event concerns.
///
/// With `pending` set, the watch is reflected into a store that sizes the
/// bind window, and an instance that became free capacity also wakes the
/// front of its pool's queue. The release authority passes `None`: it never
/// binds, so it keeps no instance store.
fn instance_lease_triggers(
    instances: Api<ClusterInstance>,
    pending: Option<PendingWakes>,
) -> impl futures::Stream<Item = ObjectRef<ClusterLease>> + Send + 'static {
    use kube::runtime::{WatchStreamExt, watcher};

    let events = watcher(instances, Config::default()).default_backoff();
    let (events, pending) = match pending {
        Some(PendingWakes { instances, leases }) => {
            let instance_store = instances.as_reader();
            (
                events.reflect(instances).boxed(),
                Some((instance_store, leases)),
            )
        }
        None => (events.boxed(), None),
    };
    let mut index = InstanceLeaseIndex::default();
    events
        .filter_map(|event| async move {
            event
                .inspect_err(
                    |error| warn!(error = %error, "ClusterInstance watch for leases failed"),
                )
                .ok()
        })
        .flat_map(move |event| {
            let (instance, names) = match &event {
                watcher::Event::Apply(instance) | watcher::Event::InitApply(instance) => {
                    let mut names = index.applied(instance);
                    if let (Some((instance_store, leases)), Some(pool)) =
                        (pending.as_ref(), instance_pool(instance))
                    {
                        let window =
                            bind_window(free_instances_in_pool(&instance_store.state(), pool));
                        names.extend(pending_leases_to_wake(instance, &leases.state(), window));
                    }
                    (Some(instance), names)
                }
                watcher::Event::Delete(instance) => (Some(instance), index.deleted(instance)),
                watcher::Event::Init | watcher::Event::InitDone => (None, Default::default()),
            };
            let namespace = instance.and_then(|instance| instance.namespace());
            futures::stream::iter(
                names
                    .into_iter()
                    .map(|name| lease_ref(&name, namespace.as_deref()))
                    .collect::<Vec<_>>(),
            )
        })
}

fn lease_ref(name: &str, namespace: Option<&str>) -> ObjectRef<ClusterLease> {
    let reference = ObjectRef::new(name);
    match namespace {
        Some(namespace) => reference.within(namespace),
        None => reference,
    }
}

const CONNECT_SECRET_SUFFIX: &str = "-connect-token";

/// The lease a connect-token Secret belongs to, from its deterministic name
/// (see [`crate::api::connect::connect_secret_name`]).
fn lease_for_connect_secret(secret_name: &str) -> Option<&str> {
    secret_name
        .strip_suffix(CONNECT_SECRET_SUFFIX)
        .filter(|lease| !lease.is_empty())
}

/// Reconcile requests for leases whose connect-token Secret changed or went
/// away. NeverBound proof waits for that Secret to be absent.
///
/// Watches metadata only: the namespace also holds kubeconfig Secrets, and
/// their contents are none of this controller's business.
fn connect_token_lease_triggers(
    secrets: Api<PartialObjectMeta<Secret>>,
) -> impl futures::Stream<Item = ObjectRef<ClusterLease>> + Send + 'static {
    use kube::runtime::{WatchStreamExt, watcher};

    watcher(secrets, Config::default())
        .default_backoff()
        .touched_objects()
        .filter_map(|secret| async move {
            let secret = secret
                .inspect_err(|error| warn!(error = %error, "connect-token Secret watch failed"))
                .ok()?;
            let lease = lease_for_connect_secret(secret.metadata.name.as_deref()?)?;
            Some(lease_ref(lease, secret.metadata.namespace.as_deref()))
        })
}

/// Evict deleted leases from the in-memory queue as the deletes happen.
///
/// The controller's own watch drops Deleted events, and a lease without a
/// finalizer is gone before any reconcile can see it. Its queue entry stayed
/// until the reaper's next sweep and, sorted oldest-first, usually held the
/// head. The reaper sweep remains for deletes this watch misses across a
/// relist. Yields nothing itself: [`LeaseContext::dequeue`] sends the wakes.
fn lease_deletion_evictions<B: ClusterBackend + 'static>(
    leases: Api<ClusterLease>,
    ctx: Arc<LeaseContext<B>>,
) -> impl futures::Stream<Item = ObjectRef<ClusterLease>> + Send + 'static {
    use kube::runtime::{WatchStreamExt, watcher};

    watcher(leases, Config::default())
        .default_backoff()
        .filter_map(move |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    Ok(watcher::Event::Delete(lease)) => forget_deleted_lease(&ctx, &lease).await,
                    Ok(_) => {}
                    Err(error) => warn!(error = %error, "ClusterLease deletion watch failed"),
                }
                None
            }
        })
}

/// Drop what the controller keeps in memory for a deleted lease: its queue
/// entry, and its failure count, which a later lease reusing the name must
/// not inherit.
async fn forget_deleted_lease<B: ClusterBackend>(ctx: &LeaseContext<B>, lease: &ClusterLease) {
    let name = lease.name_any();
    if let Ok(mut failures) = ctx.failures.lock() {
        failures.remove(&name);
    }
    ctx.dequeue(&lease.spec.pool_ref, &name).await;
}

/// Reconcile, then forget the lease's failure count on success so the next
/// failure starts the backoff over.
async fn reconcile_lease_tracked<B: ClusterBackend + Clone + 'static>(
    lease: Arc<ClusterLease>,
    ctx: Arc<LeaseContext<B>>,
) -> Result<Action, LeaseError> {
    let name = lease.name_any();
    let result = reconcile_lease(lease, ctx.clone()).await;
    if result.is_ok()
        && let Ok(mut failures) = ctx.failures.lock()
    {
        failures.remove(&name);
    }
    result
}

#[derive(Clone)]
struct ReleaseAuthorityContext {
    client: Client,
    namespace: String,
    /// Retry spacing for this loop. It shares the queue-timeout contract of
    /// the lease controller it attests for, so it takes the deadline-bound cap.
    /// Held behind an `Arc` because this context is cloned: a cloned
    /// backoff would get its own map, and the reconciler and `error_policy`
    /// would silently stop sharing one.
    failures: std::sync::Arc<crate::controllers::backoff::FailureBackoff>,
}

/// Run the read/attest half of terminal lease handling under the dedicated
/// teardown-authority identity.
///
/// This controller never creates or deletes a connect token, backend object,
/// or `ClusterInstance`. It persists the attempt nonce that opens the general
/// lifecycle controller's deletion gate, and it certifies `NeverBound` only
/// after re-observing the complete lease namespace with that same attempt.
pub async fn run_release_authority_controller(
    client: Client,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<PartialObjectMeta<Secret>> = Api::namespaced(client.clone(), namespace);
    let context = Arc::new(ReleaseAuthorityContext {
        failures: std::sync::Arc::new(crate::controllers::backoff::FailureBackoff::new(
            crate::controllers::backoff::DEFAULT_BASE,
            crate::controllers::backoff::DEADLINE_BOUND_MAX,
        )),
        client,
        namespace: namespace.to_string(),
    });
    info!("Starting isolated release-attempt authority");
    // NeverBound proof waits on instance references and the connect-token
    // Secret, so both wake the lease they concern.
    let controller = Controller::new(leases, Config::default())
        .reconcile_on(instance_lease_triggers(instances, None))
        .reconcile_on(connect_token_lease_triggers(secrets))
        .run(
            reconcile_release_authority_tracked,
            release_authority_error_policy,
            context,
        )
        .for_each(|result| async move {
            match result {
                Err(error) if woke_deleted_object(&error) => {
                    debug!(%error, "release authority woke a deleted lease");
                }
                Err(error) => debug!(?error, "release authority reconciliation error"),
                Ok(_) => {}
            }
        });
    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => info!("Release-attempt authority shutting down"),
    }
}

/// [`reconcile_release_authority`] behind the failure-backoff gate.
///
/// This loop wakes on instance changes and the connect-token Secret besides
/// its own object, so a wake inside a backoff is usually one of those rather
/// than the retry the delay was for.
///
/// The main lease controller deliberately does not get this yet: it wakes on
/// four streams, one of them a deletion-eviction channel, and deferring there
/// without first establishing what a Pending lease needs could delay a
/// binding — which is the one thing a user measures.
async fn reconcile_release_authority_tracked(
    lease: Arc<ClusterLease>,
    ctx: Arc<ReleaseAuthorityContext>,
) -> Result<Action, LeaseError> {
    let name = lease.name_any();
    if let Some(remaining) = ctx.failures.defer(&name, &lease.metadata) {
        debug!(
            lease = %name,
            retry_in = ?remaining,
            "Release authority woke inside its failure backoff; deferring",
        );
        return Ok(Action::requeue(remaining));
    }

    let result = reconcile_release_authority(lease, ctx.clone()).await;
    if result.is_ok() {
        ctx.failures.forget(&name);
    }
    result
}

async fn reconcile_release_authority(
    lease: Arc<ClusterLease>,
    ctx: Arc<ReleaseAuthorityContext>,
) -> Result<Action, LeaseError> {
    let status = lease.status.clone().unwrap_or_default();

    // Until the lease itself changes there is nothing to attest, and the
    // lease watch delivers that change.
    if lease.spec.cleanup_mode != Some(CleanupMode::VerifiedDestroy)
        || !matches!(status.phase, LeasePhase::Released | LeasePhase::Expired)
        || lease.metadata.deletion_timestamp.is_some()
    {
        return Ok(Action::await_change());
    }
    if lease
        .annotations()
        .get(CONNECT_TOKEN_CREATE_FENCE_ANNOTATION)
        .map(String::as_str)
        != Some("true")
        || !lease
            .finalizers()
            .iter()
            .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
    {
        return Ok(Action::await_change());
    }

    let leases: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let attempt = match status.teardown_attempt_id.as_deref() {
        Some(attempt) if !attempt.trim().is_empty() => attempt,
        Some(_) => {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "terminal lease carries an empty teardown attempt"
            )));
        }
        None if status.teardown_receipt.is_some()
            || status.unbound_release_verified_at.is_some() =>
        {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "terminal lease carries proof without a durable attempt"
            )));
        }
        None => {
            persist_authority_teardown_attempt(&leases, &lease, &status).await?;
            return Ok(Action::requeue(std::time::Duration::from_secs(1)));
        }
    };

    if unbound_release_proof_is_complete_for_lease(&lease, &status)
        || status.teardown_receipt.is_some()
    {
        return Ok(Action::await_change());
    }
    if status.unbound_release_verified_at.is_some() {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "NeverBound proof does not match the exact retained lease intent"
        )));
    }
    let Some(verified_at) =
        authority_never_bound_observation(&ctx.client, &ctx.namespace, &lease).await?
    else {
        // The Secret and instance watches wake this lease when the token or an
        // instance reference goes; the timer only backs them up.
        return Ok(Action::requeue(NEVER_BOUND_BACKSTOP));
    };
    record_authority_unbound_release_proof(&leases, &lease, &status, attempt, &verified_at).await?;
    Ok(Action::requeue(std::time::Duration::from_secs(1)))
}

async fn persist_authority_teardown_attempt(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
) -> Result<(), LeaseError> {
    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let attempt = uuid::Uuid::new_v4().to_string();
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "add", "path": "/status/teardownAttemptId", "value": attempt }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Whether a retained verified binding is durably known to have stopped before
/// any create-capable token request could be dispatched.
///
/// The binding intent remains an immutable audit handle. `Closed` with no
/// identity can only be reached directly from `Prepared`; every path that
/// reached `Creating` must first recover an exact token UID and route through
/// receipt-backed teardown instead.
fn retained_unstarted_binding_is_closed(status: &ClusterLeaseStatus) -> bool {
    let Some(binding) = status.binding.as_ref() else {
        return false;
    };
    let Some(creation) = status.connect_token_creation.as_ref() else {
        return false;
    };
    binding.cleanup_mode == CleanupMode::VerifiedDestroy
        && binding.connect_token.is_none()
        && creation.phase == ConnectTokenCreationPhase::Closed
        && creation.identity.is_none()
        && creation
            .verified_absent_at
            .as_deref()
            .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
        && status.cluster_name.is_none()
}

/// Require the retained pre-create intent to name this exact lease and pool.
pub(crate) fn retained_unstarted_binding_matches_lease(
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
) -> bool {
    let Some(binding) = status.binding.as_ref() else {
        return false;
    };
    retained_unstarted_binding_is_closed(status)
        && lease.spec.cleanup_mode == Some(CleanupMode::VerifiedDestroy)
        && binding.lease.name == lease.name_any()
        && binding.lease.uid.as_deref() == lease.uid().as_deref()
        && binding.pool.name == lease.spec.pool_ref
        && binding
            .pool
            .uid
            .as_deref()
            .is_some_and(|uid| !uid.is_empty())
        && !binding.instance.name.is_empty()
        && !binding.instance.uid.is_empty()
        && binding.instance.observed_generation > 0
}

/// Return an authority timestamp only when the exact terminal attempt cannot
/// have a reciprocal instance allocation and its create-capable token name is
/// closed. A retained intent is accepted only in the unique `Prepared ->
/// Closed` shape, then a full instance list proves that neither its exact
/// candidate nor any other instance acquired this lease UID.
async fn authority_never_bound_observation(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<Option<String>, LeaseError> {
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    if status.cluster_name.is_some()
        || (status.binding.is_some() && !retained_unstarted_binding_matches_lease(lease, &status))
    {
        return Ok(None);
    }
    let verified_at = match status.connect_token_creation.as_ref() {
        Some(creation)
            if creation.phase == ConnectTokenCreationPhase::Closed
                && creation.verified_absent_at.is_some() =>
        {
            let verified_at = creation
                .verified_absent_at
                .as_ref()
                .filter(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
                .cloned();
            let Some(verified_at) = verified_at else {
                return Ok(None);
            };
            if let Some(identity) = creation.identity.as_ref() {
                let check = crate::api::connect::observe_lease_connect_token_absent(
                    client,
                    namespace,
                    &lease.name_any(),
                    identity,
                )
                .await;
                if check.result != crate::crd::CheckResult::Verified {
                    return Ok(None);
                }
            } else if !deterministic_connect_token_name_is_absent(
                client,
                namespace,
                &lease.name_any(),
            )
            .await?
            {
                return Ok(None);
            }
            verified_at
        }
        // No creator state plus no binding is the legacy-safe durable pre-allocation
        // checkpoint: this protocol never permits a Secret POST before both
        // values exist in one status write.
        None if status.binding.is_none() => {
            if !deterministic_connect_token_name_is_absent(client, namespace, &lease.name_any())
                .await?
            {
                return Ok(None);
            }
            chrono::Utc::now().to_rfc3339()
        }
        _ => return Ok(None),
    };

    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let all = instances.list(&ListParams::default()).await?;
    let lease_uid = lease_uid_for(lease)?;
    if all.iter().any(|instance| {
        instance.status.as_ref().is_some_and(|instance_status| {
            instance_status.binding.as_ref().is_some_and(|binding| {
                binding.lease.name == lease.name_any()
                    && binding.lease.uid.as_deref() == Some(lease_uid)
            }) || instance_status.lease_ref.as_ref().is_some_and(|reference| {
                reference.name == lease.name_any() && reference.uid.as_deref() == Some(lease_uid)
            })
        })
    }) {
        return Ok(None);
    }

    Ok(Some(verified_at))
}

async fn deterministic_connect_token_name_is_absent(
    client: &Client,
    namespace: &str,
    lease_name: &str,
) -> Result<bool, LeaseError> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), namespace);
    match secrets
        .get(&crate::api::connect::connect_secret_name(lease_name))
        .await
    {
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn record_authority_unbound_release_proof(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
    attempt: &str,
    verified_at: &str,
) -> Result<(), LeaseError> {
    if status.teardown_attempt_id.as_deref() != Some(attempt)
        || status.cluster_name.is_some()
        || (status.binding.is_some() && !retained_unstarted_binding_matches_lease(lease, status))
        || status.teardown_receipt.is_some()
    {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "NeverBound proof lost its exact release attempt"
        )));
    }
    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let mut conditions: Vec<_> = status
        .conditions
        .iter()
        .filter(|condition| condition.condition_type != ALLOCATION_ABSENT_CONDITION)
        .cloned()
        .collect();
    conditions.push(ClusterLeaseCondition {
        condition_type: ALLOCATION_ABSENT_CONDITION.into(),
        status: "True".into(),
        reason: "NeverBound".into(),
        message: format!("release attempt {attempt} proved no reciprocal allocation existed"),
        last_transition_time: Some(verified_at.to_string()),
    });
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "test", "path": "/status/teardownAttemptId", "value": attempt },
        { "op": "add", "path": "/status/unboundReleaseVerifiedAt", "value": verified_at },
        { "op": "add", "path": "/status/conditions", "value": conditions }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn release_authority_error_policy(
    lease: Arc<ClusterLease>,
    error: &LeaseError,
    ctx: Arc<ReleaseAuthorityContext>,
) -> Action {
    let name = lease.name_any();
    let delay = ctx.failures.record(&name, &lease.metadata);
    warn!(lease = %name, retry_in = ?delay, %error, "release authority reconcile failed");
    Action::requeue(delay)
}

/// Rebuild priority queues from existing Pending ClusterLease CRDs.
async fn rebuild_queues<B: ClusterBackend>(ctx: &LeaseContext<B>) {
    let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);

    let leases = match leases_api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to list leases for queue rebuild: {e}");
            return;
        }
    };

    let mut queues = ctx.queues.write().await;

    for lease in &leases {
        let status = lease.status.clone().unwrap_or_default();
        if status.phase != LeasePhase::Pending {
            continue;
        }

        let name = lease.name_any();
        let created_at = lease
            .metadata
            .creation_timestamp
            .as_ref()
            .and_then(|ts| {
                chrono::DateTime::parse_from_rfc3339(&ts.0.to_string())
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            })
            .unwrap_or_else(chrono::Utc::now);

        let queue = queues
            .entry(lease.spec.pool_ref.clone())
            .or_insert_with(Vec::new);

        if !queue.iter().any(|p| p.lease_name == name) {
            queue.push(PendingLease {
                lease_name: name,
                priority: lease.spec.priority,
                created_at,
            });
        }
    }

    for queue in queues.values_mut() {
        queue.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.created_at.cmp(&b.created_at))
        });
    }

    let total: usize = queues.values().map(|q| q.len()).sum();
    if total > 0 {
        info!(
            pending_leases = total,
            profiles = queues.len(),
            "Rebuilt priority queues from existing CRDs"
        );
    }
}

/// Main reconciliation logic for a ClusterLease.
#[tracing::instrument(skip_all, fields(lease = %lease.name_any()))]
async fn reconcile_lease<B: ClusterBackend + Clone + 'static>(
    lease: Arc<ClusterLease>,
    ctx: Arc<LeaseContext<B>>,
) -> Result<Action, LeaseError> {
    let name = lease.name_any();
    let _active_reconcile = match try_start_reconcile(&ctx, &name) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            info!(lease = %name, "Lease already reconciling, deferring duplicate event");
            return Ok(Action::requeue(std::time::Duration::from_secs(1)));
        }
        Err(err) => return Err(err),
    };
    let ns = lease.namespace().unwrap_or_else(|| ctx.namespace.clone());
    let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), &ns);

    let lease = if lease.resource_version().is_some() {
        match leases_api.get(&name).await {
            Ok(current) => Arc::new(current),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(lease = %name, "Lease disappeared before reconcile could load current state");
                // Evict on the way out. This covers only the narrow race
                // where the delete lands after this reconcile was
                // dispatched (store hit) but before its apiserver GET.
                // Deletes in general produce no reconcile here: kube-runtime
                // drives the controller from `applied_objects()`, which
                // drops Deleted events. `lease_deletion_evictions` handles
                // them as they happen, and the reaper's sweep
                // (`prune_queues_against_live`) catches any that watch
                // missed.
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return Ok(Action::await_change());
            }
            Err(err) => return Err(LeaseError::Kube(err)),
        }
    } else {
        lease
    };

    let status = lease.status.clone().unwrap_or_default();

    // A delayed Sandbox composition POST must be fenced before this
    // controller performs *any* metadata upgrade on the handle. Otherwise a
    // stale object can consume the receipt-finalizer upgrade pass and defer
    // its allocation fence to a later reconcile.
    if status.phase == LeasePhase::Pending {
        match sandbox_composition_allocation_gate(&ctx.client, &ns, &lease).await {
            SandboxCompositionGate::NotComposition | SandboxCompositionGate::Authorized(_) => {}
            SandboxCompositionGate::NeedsMigration(identity) => {
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return migrate_sandbox_composition_retention_fence(&leases_api, &lease, &identity)
                    .await;
            }
            SandboxCompositionGate::Closed(identity) => {
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return close_stale_sandbox_composition(
                    &ctx.client,
                    &ns,
                    &leases_api,
                    &lease,
                    &identity,
                )
                .await;
            }
            SandboxCompositionGate::Invalid => {
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return quarantine_invalid_sandbox_composition(&leases_api, &lease).await;
            }
            SandboxCompositionGate::Retry => {
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
            SandboxCompositionGate::LegacyBoundRecovery => {
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return quarantine_invalid_sandbox_composition(&leases_api, &lease).await;
            }
        }
    }

    // Verified handles carry the release protocol from their first observed
    // Pending state, not from the later allocation attempt. Internal Sandbox
    // compositions install both at CREATE time; this is the idempotent upgrade
    // path for older exact handles.
    if lease.metadata.deletion_timestamp.is_none()
        && status.phase == LeasePhase::Pending
        && lease.spec.cleanup_mode == Some(CleanupMode::VerifiedDestroy)
        && (!lease
            .finalizers()
            .iter()
            .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
            || lease
                .annotations()
                .get(CONNECT_TOKEN_CREATE_FENCE_ANNOTATION)
                .map(String::as_str)
                != Some("true"))
    {
        ensure_receipt_retention_finalizer(&ctx.client, &ns, &lease).await?;
        return Ok(Action::requeue(std::time::Duration::from_secs(1)));
    }

    // A direct Kubernetes DELETE can race the bind path. The receipt-retention
    // finalizer is installed before reservation, so it also owns this edge:
    // never bind a terminating lease and never remove the finalizer until a
    // pre-intent connect token is observed absent.
    if lease.metadata.deletion_timestamp.is_some()
        && lease
            .finalizers()
            .iter()
            .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
    {
        if matches!(status.phase, LeasePhase::Pending | LeasePhase::Bound)
            && ((status.binding.is_some() || status.cluster_name.is_some())
                || requires_attempt_bound_token_deletion(&lease))
        {
            let uid = lease_uid_for(&lease)?;
            let rv = lease
                .resource_version()
                .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
            let patch = json_patch(serde_json::json!([
                { "op": "test", "path": "/metadata/uid", "value": uid },
                { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
                { "op": "test", "path": "/status/phase", "value": status.phase },
                { "op": "add", "path": "/status/phase", "value": "Released" }
            ]));
            leases_api
                .patch_status(&name, &PatchParams::default(), &Patch::<()>::Json(patch))
                .await?;
            return Ok(Action::requeue(std::time::Duration::from_secs(1)));
        }
        if status.binding.is_none()
            && status.cluster_name.is_none()
            && lease.spec.cleanup_mode == Some(CleanupMode::VerifiedDestroy)
            && !requires_attempt_bound_token_deletion(&lease)
        {
            // A deleting legacy handle without the create-before-bind fence
            // cannot exclude an already-dispatched token or reservation POST.
            // Retain it; manufacturing NeverBound here would turn a 404 into
            // authority while a delayed create may still commit.
            warn!(lease = %name, "retaining legacy verified handle without creation fence");
            return Ok(Action::requeue(std::time::Duration::from_secs(300)));
        }
    }

    // Pre-UID-fence controllers could crash after writing only clusterName.
    // Never "repair" that name into authority. Backfill is permitted only
    // after proving a unique reciprocal pair and immutable pool provenance.
    if status.phase == LeasePhase::Pending
        && status.cluster_name.is_some()
        && status.binding.is_none()
    {
        match backfill_legacy_binding(&ctx.client, &ns, &lease).await? {
            Some(binding) => {
                // Keep the retrying finalizer future off the already-large
                // reconcile state machine's stack frame.
                let bound = Box::pin(finalize_binding(
                    &ctx,
                    &ns,
                    &binding,
                    created_at_for(&lease),
                ))
                .await?;
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                return Ok(Action::requeue(std::time::Duration::from_secs(if bound {
                    60
                } else {
                    1
                })));
            }
            None => {
                mark_binding_unverified(&leases_api, &lease, "legacy_binding_unverified").await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            }
        }
    }

    let phase = &status.phase;

    match phase {
        LeasePhase::Pending => {
            info!(lease = %name, profile = %lease.spec.pool_ref, "Reconciling pending lease");

            let created_at = lease
                .metadata
                .creation_timestamp
                .as_ref()
                .and_then(|ts| {
                    chrono::DateTime::parse_from_rfc3339(&ts.0.to_string())
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                })
                .unwrap_or_else(chrono::Utc::now);

            let window = ctx.bind_window(&lease.spec.pool_ref);
            let (in_window, position) = {
                let mut queues = ctx.queues.write().await;
                let queue = queues
                    .entry(lease.spec.pool_ref.clone())
                    .or_insert_with(Vec::new);

                if !queue.iter().any(|p| p.lease_name == name) {
                    queue.push(PendingLease {
                        lease_name: name.clone(),
                        priority: lease.spec.priority,
                        created_at,
                    });
                    queue.sort_by(|a, b| {
                        b.priority
                            .cmp(&a.priority)
                            .then(a.created_at.cmp(&b.created_at))
                    });
                }

                let pos = queue
                    .iter()
                    .position(|p| p.lease_name == name)
                    .map(|p| p as u32 + 1)
                    .unwrap_or(0);
                (pos >= 1 && pos as usize <= window, pos)
            };

            let Some(lease_uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Pending lease has no UID"
                )));
            };
            let Some(lease_rv) = lease.resource_version() else {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Pending lease has no resourceVersion"
                )));
            };
            let mut queued_status = status.clone();
            queued_status.phase = LeasePhase::Pending;
            queued_status.queue_position = position;
            let patch = json_patch(serde_json::json!([
                { "op": "test", "path": "/metadata/uid", "value": lease_uid },
                { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
                { "op": "add", "path": "/status", "value": queued_status }
            ]));
            let queued_lease = match leases_api
                .patch_status(&name, &PatchParams::default(), &Patch::<()>::Json(patch))
                .await
            {
                Ok(queued) => queued,
                Err(error) if optimistic_conflict(&error) => {
                    return Ok(Action::requeue(CONFLICT_RETRY));
                }
                Err(error) => return Err(error.into()),
            };

            // Event-driven wakes cover capacity and queue changes; the queue
            // timeout is a clock deadline, so the backstop never sleeps past it.
            let mut pending_requeue = PENDING_BACKSTOP;

            // Every pool shape gets a queue timeout, not just autoscaled ones
            // (#233). A fixed-size pool's `size` is as hard a ceiling as an
            // autoscaled pool's `max_clusters`, so a caller that vanished
            // (cancelled CI job, closed laptop) can wedge a fixed pool's
            // queue exactly like it would an autoscaled one; `scaling`
            // being unset must not turn that off. Prefer
            // `scaling.queue_timeout` when autoscaling is on (it already
            // has its own default and is the value the pool's autoscaling
            // is tuned against); otherwise fall back to the top-level
            // `spec.queue_timeout`, which defaults identically.
            if let Some(profile) = get_profile(&ctx.client, &lease.spec.pool_ref, &ns).await
                && let Some(timeout) = parse_duration(
                    profile
                        .spec
                        .scaling
                        .as_ref()
                        .map(|scaling| scaling.queue_timeout.as_str())
                        .unwrap_or(profile.spec.queue_timeout.as_str()),
                )
            {
                let age = chrono::Utc::now() - created_at;
                if age > timeout {
                    warn!(lease = %name, "Lease exceeded queue timeout, expiring");
                    crate::metrics::LEASE_QUEUE_WAIT_SECONDS
                        .with_label_values(&[lease.spec.pool_ref.as_str(), "expired"])
                        .observe(age.num_milliseconds() as f64 / 1000.0);
                    ctx.dequeue(&lease.spec.pool_ref, &name).await;
                    expire_lease_fenced(&leases_api, &queued_lease).await?;
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
                if let Ok(remaining) = (timeout - age).to_std() {
                    pending_requeue = pending_requeue.min(remaining.max(CONFLICT_RETRY));
                }
            }

            if !in_window {
                debug!(lease = %name, position, window, "Outside the bind window, waiting for higher-priority leases");
                return Ok(Action::requeue(pending_requeue));
            }

            // Each window slot has its own instance, so concurrent
            // reservations do not collide (see `candidates_for_slot`).
            let reserved_binding = reserve_ready_instance(
                &ctx.client,
                &ns,
                &queued_lease,
                ctx.factory.as_ref(),
                position.saturating_sub(1) as usize,
            )
            .await?;

            if let Some(binding) = reserved_binding {
                // The instance reservation is durable. If this final status
                // write fails or the process stops, the next reconcile sees
                // the same lease-side intent and finishes the same pair. It
                // must not roll back on an uncertain response.
                // Keep the retrying finalizer future off the already-large
                // reconcile state machine's stack frame.
                let bound = Box::pin(finalize_binding(&ctx, &ns, &binding, created_at)).await?;
                ctx.dequeue(&lease.spec.pool_ref, &name).await;
                Ok(Action::requeue(std::time::Duration::from_secs(if bound {
                    60
                } else {
                    1
                })))
            } else {
                // No Ready cluster to bind. Populate status.message with the
                // pool's health so a client can tell "warming up" from "this
                // pool will never satisfy me" — a fixed-size pool has no queue
                // timeout, so an exhausted pool otherwise leaves the lease hung
                // in Pending with no explanation (#189). Read the pool status
                // (best-effort; a missing pool yields a generic message).
                let pool_status = get_profile(&ctx.client, &lease.spec.pool_ref, &ns)
                    .await
                    .and_then(|p| p.status);
                let (message, reason) = unsatisfiable_status(&lease.spec.pool_ref, &pool_status);

                // Count the edge, not every reconcile of the same Pending
                // lease. Request-time preflight rejections are counted in the
                // API; here we count only entry into an unsatisfiable condition
                // or a change of reason. Warming is a normal cold-start.
                if reason != crate::metrics::LeaseUnsatisfiableReason::Warming
                    && entered_unsatisfiable_condition(&status.conditions, reason)
                {
                    crate::metrics::LEASE_UNSATISFIABLE_TOTAL
                        .with_label_values(&[lease.spec.pool_ref.as_str(), reason.as_str()])
                        .inc();
                }

                info!(
                    lease = %name,
                    profile = %lease.spec.pool_ref,
                    priority = lease.spec.priority,
                    reason = reason.as_str(),
                    "No ready cluster, lease queued at position {position}: {message}"
                );

                // Derive conditions for the still-Pending, not-yet-satisfiable
                // lease: Bound=False (phase Pending) and Satisfiable=False
                // carrying the unsatisfiable reason. Preserve lastTransitionTime
                // against the on-disk conditions so a steady-state warm-up
                // doesn't churn the timestamp on every requeue.
                let pending_status = ClusterLeaseStatus {
                    phase: LeasePhase::Pending,
                    message: Some(message.clone()),
                    ..status.clone()
                };
                let conditions = derive_lease_conditions(
                    &pending_status,
                    &status.conditions,
                    Some(reason),
                    &chrono::Utc::now().to_rfc3339(),
                );

                // Best-effort: a failed message write must not block requeue —
                // the lease is still validly Pending and will retry.
                let queued_uid = queued_lease.metadata.uid.as_deref().unwrap_or_default();
                let queued_rv = queued_lease.resource_version().unwrap_or_default();
                let patch = json_patch(serde_json::json!([
                    { "op": "test", "path": "/metadata/uid", "value": queued_uid },
                    { "op": "test", "path": "/metadata/resourceVersion", "value": queued_rv },
                    { "op": "test", "path": "/status/phase", "value": "Pending" },
                    { "op": "add", "path": "/status/message", "value": message },
                    { "op": "add", "path": "/status/conditions", "value": conditions }
                ]));
                if let Err(e) = leases_api
                    .patch_status(&name, &PatchParams::default(), &Patch::<()>::Json(patch))
                    .await
                {
                    warn!(lease = %name, "Failed to write unsatisfiable status message (continuing): {e}");
                }

                Ok(Action::requeue(pending_requeue))
            }
        }

        LeasePhase::Bound => {
            if let Some(expires_at_str) = &status.expires_at {
                match chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                    Ok(expires_at) => {
                        if chrono::Utc::now() > expires_at.with_timezone(&chrono::Utc) {
                            crate::metrics::CLAIMS_TOTAL
                                .with_label_values(&[lease.spec.pool_ref.as_str(), "expired"])
                                .inc();
                            if let Some(held) = crate::metrics::elapsed_secs_since_rfc3339(
                                status.bound_at.as_deref(),
                            ) {
                                crate::metrics::LEASE_HOLD_SECONDS
                                    .with_label_values(&[lease.spec.pool_ref.as_str(), "expired"])
                                    .observe(held);
                            }
                            info!(lease = %name, "Lease TTL expired");
                            expire_lease_fenced(&leases_api, &lease).await?;
                            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                        }
                    }
                    Err(e) => {
                        error!(
                            lease = %name,
                            expires_at = %expires_at_str,
                            "Failed to parse expires_at, force-expiring lease: {e}"
                        );
                        expire_lease_fenced(&leases_api, &lease).await?;
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    }
                }
            }

            // Requeue at this lease's expiry deadline (clamped to [1s, 30s])
            // rather than a fixed 30s, so TTL expiry is detected promptly instead
            // of up to ~30-60s late. (The 60s reaper remains a backstop.)
            let until_expiry = status
                .expires_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|e| e.with_timezone(&chrono::Utc) - chrono::Utc::now())
                .and_then(|d| d.to_std().ok())
                .map(|d| {
                    d.clamp(
                        std::time::Duration::from_secs(1),
                        std::time::Duration::from_secs(30),
                    )
                })
                .unwrap_or(std::time::Duration::from_secs(30));
            Ok(Action::requeue(until_expiry))
        }

        LeasePhase::Released | LeasePhase::Expired => {
            info!(lease = %name, phase = %phase, "Processing lease termination");

            ctx.dequeue(&lease.spec.pool_ref, &name).await;

            let mut terminal_lease = (*lease).clone();
            let mut terminal_status = status.clone();
            let verified_cleanup = requires_attempt_bound_token_deletion(&terminal_lease);

            if verified_cleanup {
                if terminal_lease
                    .annotations()
                    .get(CONNECT_TOKEN_CREATE_FENCE_ANNOTATION)
                    .map(String::as_str)
                    != Some("true")
                {
                    mark_binding_unverified(
                        &leases_api,
                        &terminal_lease,
                        "connect_token_create_protocol_unverified",
                    )
                    .await?;
                    return Ok(Action::requeue(std::time::Duration::from_secs(30)));
                }

                // This nonce must be durable before token deletion, absence
                // lookup, or NeverBound classification. A retry reuses it.
                if ensure_unbound_release_attempt(&leases_api, &terminal_lease, &terminal_status)
                    .await?
                    .is_none()
                {
                    return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                }

                if let Some(binding) = terminal_status.binding.clone() {
                    let Some((closed_lease, closed_binding)) =
                        close_terminal_connect_token_creation(
                            &ctx.client,
                            &ns,
                            &terminal_lease,
                            &terminal_status,
                            &binding,
                        )
                        .await?
                    else {
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    };
                    terminal_lease = closed_lease;
                    terminal_status = terminal_lease.status.clone().unwrap_or_default();

                    if !retained_unstarted_binding_matches_lease(&terminal_lease, &terminal_status)
                    {
                        // Once creation advanced past Prepared, a persisted
                        // intent may already have a delayed reservation. Adopt
                        // the exact candidate into receipt-backed teardown;
                        // only the pre-create Closed shape is eligible for an
                        // authority-observed NeverBound proof.
                        if reserve_binding_instance_after_lease_fence(
                            &ctx.client,
                            &ns,
                            &closed_binding,
                        )
                        .await?
                            != ReservationOutcome::Reserved
                        {
                            mark_binding_unverified(
                                &leases_api,
                                &terminal_lease,
                                "binding_intent_could_not_be_adopted_for_teardown",
                            )
                            .await?;
                            return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                        }
                    }
                }

                if unbound_release_proof_is_complete_for_lease(&terminal_lease, &terminal_status) {
                    if !unbound_release_proof_acknowledged(&terminal_lease, &terminal_status) {
                        debug!(lease = %name, "retaining NeverBound proof until its exact attempt is acknowledged");
                        return Ok(Action::requeue(std::time::Duration::from_secs(30)));
                    }

                    info!(lease = %name, phase = %phase, "Retiring acknowledged NeverBound lease");
                    crate::metrics::LEASES_RETIRED_UNBOUND_TOTAL
                        .with_label_values(&[
                            terminal_lease.spec.pool_ref.as_str(),
                            phase.to_string().as_str(),
                        ])
                        .inc();
                    let terminal_lease =
                        remove_receipt_retention_finalizer(&ctx.client, &ns, &terminal_lease)
                            .await?;
                    delete_lease_crd(&leases_api, &terminal_lease).await;
                    return Ok(Action::await_change());
                }

                let never_bound_candidate = terminal_status.cluster_name.is_none()
                    && (terminal_status.binding.is_none()
                        || retained_unstarted_binding_matches_lease(
                            &terminal_lease,
                            &terminal_status,
                        ));
                if never_bound_candidate {
                    let creator_closed = terminal_status
                        .connect_token_creation
                        .as_ref()
                        .is_none_or(|creation| {
                            creation.phase == ConnectTokenCreationPhase::Closed
                                && creation.verified_absent_at.is_some()
                        });
                    if !creator_closed {
                        mark_binding_unverified(
                            &leases_api,
                            &terminal_lease,
                            "unbound_token_creator_not_closed",
                        )
                        .await?;
                        return Ok(Action::requeue(std::time::Duration::from_secs(30)));
                    }

                    if !unbound_release_proof_is_complete_for_lease(
                        &terminal_lease,
                        &terminal_status,
                    ) {
                        // Handles created before the new protocol may carry an
                        // owner-fenced token with no binding. The release
                        // attempt above is already durable; delete its exact
                        // live UID and observe 404 before recording proof.
                        if terminal_status.connect_token_creation.is_none() {
                            crate::api::connect::delete_unbound_lease_connect_token_verified(
                                &ctx.client,
                                &ns,
                                &name,
                                lease_uid_for(&terminal_lease)?,
                            )
                            .await
                            .map_err(LeaseError::Lifecycle)?;
                        }
                        let attempt = terminal_status
                            .teardown_attempt_id
                            .as_deref()
                            .expect("durable attempt checked above");
                        if !crate::receipt_authority::is_separate() {
                            let Some(verified_at) = authority_never_bound_observation(
                                &ctx.client,
                                &ns,
                                &terminal_lease,
                            )
                            .await?
                            else {
                                return Ok(Action::requeue(NEVER_BOUND_BACKSTOP));
                            };
                            record_unbound_release_proof(
                                &leases_api,
                                &terminal_lease,
                                &terminal_status,
                                attempt,
                                &verified_at,
                            )
                            .await?;
                        }
                        return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                    }
                    if !unbound_release_proof_acknowledged(&terminal_lease, &terminal_status) {
                        debug!(lease = %name, "retaining NeverBound proof until its exact attempt is acknowledged");
                        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
                    }

                    info!(lease = %name, phase = %phase, "Retiring acknowledged NeverBound lease");
                    crate::metrics::LEASES_RETIRED_UNBOUND_TOTAL
                        .with_label_values(&[
                            terminal_lease.spec.pool_ref.as_str(),
                            phase.to_string().as_str(),
                        ])
                        .inc();
                    let terminal_lease =
                        remove_receipt_retention_finalizer(&ctx.client, &ns, &terminal_lease)
                            .await?;
                    delete_lease_crd(&leases_api, &terminal_lease).await;
                    return Ok(Action::await_change());
                }
            }

            let Some(lease_uid) = terminal_lease.metadata.uid.as_deref() else {
                mark_binding_unverified(&leases_api, &terminal_lease, "lease_uid_missing").await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            };

            // Standard cleanup revokes by exact live owner immediately. A
            // VerifiedDestroy binding MUST defer deletion to the instance gate:
            // that gate first persists the attempt nonce, then deletes the
            // immutable `binding.connectToken` UID and records the observed
            // absence in the same attempt's receipt. Deleting here would make
            // that evidence post-hoc and could launder a same-name replacement.
            let token_delete_result = if verified_cleanup {
                Ok(())
            } else {
                crate::api::connect::delete_lease_connect_token(&ctx.client, &ns, &name, lease_uid)
                    .await
            };
            if let Err(error) = &token_delete_result {
                warn!(lease = %name, "connect-token delete failed: {error:#}");
            }

            let resolved = match crate::lease_binding::resolve_lease_binding(
                &ctx.client,
                &ns,
                &name,
                lease_uid,
                crate::lease_binding::BindingResolveMode::Lifecycle,
            )
            .await
            {
                Ok(resolved) => resolved,
                // A terminal lease that names NOTHING — no binding and no
                // clusterName — never held capacity: it expired while still
                // queued. There is nothing to recycle, nothing to quarantine,
                // and no receipt to preserve, and no amount of retrying will
                // make a binding appear. Retire it.
                //
                // Before #150 this fell into the arm below and requeued every
                // 30s forever: 75 such leases on int-pro re-reconciled for two
                // days straight, and every future one joined them permanently.
                // Access is already revoked here — the connect-token Secret is
                // deleted above, before this point.
                //
                // `clusterName` without a binding is deliberately NOT retired.
                // That is the legacy pre-UID-fence shape (a controller that
                // crashed after writing only the name), so an instance may still
                // exist under that name and this lease is the sole pointer to
                // it. Same reasoning as `backfill_legacy_binding`: a bare name
                // is never promoted to authority, and it is not discarded
                // either.
                //
                // Likewise ONLY `binding_missing` is terminal. Every mismatch
                // code (uid / provenance / reciprocal / malformed / …) means an
                // instance may exist in an inconsistent state, and lookup
                // failures are transient. Both still fall through to the arm
                // below and wait.
                Err(BindingResolutionError::BindingMissing)
                    if terminal_status.cluster_name.is_none()
                        && !sandbox_composition_requires_outer_retirement(&terminal_lease)
                        && !teardown_receipt_unconsumed(&terminal_lease, &terminal_status) =>
                {
                    debug_assert!(!verified_cleanup, "verified unbound path returned above");
                    info!(
                        lease = %name,
                        phase = %phase,
                        "Retiring terminal lease: no binding was ever recorded"
                    );
                    crate::metrics::LEASES_RETIRED_UNBOUND_TOTAL
                        .with_label_values(&[
                            terminal_lease.spec.pool_ref.as_str(),
                            phase.to_string().as_str(),
                        ])
                        .inc();
                    let terminal_lease =
                        remove_receipt_retention_finalizer(&ctx.client, &ns, &terminal_lease)
                            .await?;
                    return Ok(if delete_lease_crd(&leases_api, &terminal_lease).await {
                        Action::await_change()
                    } else {
                        Action::requeue(std::time::Duration::from_secs(15))
                    });
                }
                Err(err) => {
                    // A reservation intent that never reached Bound, whose
                    // exact instance is gone, holds nothing: retire it. Before
                    // this arm such leases re-reconciled every 30s forever.
                    // Boxed to keep its awaits off this future's frame.
                    if token_delete_result.is_ok()
                        && let Some(action) = Box::pin(retire_orphaned_standard_intent(
                            &ctx.client,
                            &ns,
                            &leases_api,
                            &terminal_lease,
                            &terminal_status,
                            verified_cleanup,
                            err.reason_code(),
                        ))
                        .await?
                    {
                        return Ok(action);
                    }
                    mark_binding_unverified(&leases_api, &terminal_lease, err.reason_code())
                        .await?;
                    return Ok(Action::requeue(std::time::Duration::from_secs(30)));
                }
            };

            // Capture diagnostics BEFORE flipping to Recycling: the cluster is
            // still alive (we mark the instance recycling only after the patch
            // below), and recording the URL in the SAME patch that advances the
            // phase means a transient status-write failure is retried — via the
            // `?` below, while the lease is still Released/Expired — instead of
            // losing the URL (the Recycling arm never re-captures).
            let mut diag_url: Option<String> = None;
            let cluster_name = &resolved.binding.instance.name;
            if let Some(ref diag_config) = resolved.pool.spec.diagnostics
                && diag_config.enabled
            {
                let factory = ctx.factory.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("backend factory unavailable for pinned diagnostics")
                })?;
                let backend = factory
                    .backend_for_provenance(&resolved.binding.backend)
                    .map_err(LeaseError::Lifecycle)?;
                info!(lease = %name, "Capturing diagnostic bundle");
                match diagnostics::capture_bundle(cluster_name, &ns, diag_config, &name, &backend)
                    .await
                {
                    Ok(url) => diag_url = Some(url),
                    Err(e) => warn!(
                        lease = %name,
                        cluster = %cluster_name,
                        "Failed to capture diagnostic bundle: {e:#}"
                    ),
                }
            }

            if !mark_instance_recycling(&ctx.client, &ns, &resolved.binding).await? {
                mark_binding_unverified(
                    &leases_api,
                    &terminal_lease,
                    "instance_recycle_fence_failed",
                )
                .await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            }

            // Field-level transition only. Replacing `/status` re-serializes the
            // whole object and omits `skip_serializing_if` Nones, which drops
            // live `teardownAttemptId` / receipt / creationManifest and the CRD
            // rejects the write with 422. Child sandboxes then stay Releasing
            // and fill the admission quota.
            let mut recycling_view = terminal_status.clone();
            recycling_view.phase = LeasePhase::Recycling;
            let conditions = derive_lease_conditions(
                &recycling_view,
                &terminal_status.conditions,
                None,
                &chrono::Utc::now().to_rfc3339(),
            );
            let lease_rv = terminal_lease
                .resource_version()
                .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
            let mut operations = vec![
                serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid }),
                serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv }),
                serde_json::json!({ "op": "test", "path": "/status/phase", "value": terminal_status.phase }),
                serde_json::json!({ "op": "test", "path": "/status/binding", "value": resolved.binding }),
                serde_json::json!({ "op": "add", "path": "/status/phase", "value": "Recycling" }),
                serde_json::json!({ "op": "add", "path": "/status/conditions", "value": conditions }),
            ];
            if let Some(url) = diag_url {
                operations.push(serde_json::json!({
                    "op": "add",
                    "path": "/status/diagnosticsUrl",
                    "value": url
                }));
            }
            let patch = json_patch(serde_json::Value::Array(operations));
            match leases_api
                .patch_status(&name, &PatchParams::default(), &Patch::<()>::Json(patch))
                .await
            {
                Ok(_) => {}
                Err(error) if optimistic_conflict(&error) => {
                    return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                }
                Err(error) => return Err(error.into()),
            }
            debug!(cluster = %cluster_name, "Marked exact ClusterInstance recycling");

            Ok(Action::requeue(std::time::Duration::from_secs(10)))
        }

        // Terminal until the same exact subject produces a verified receipt.
        // Access is already revoked and the binding/finalizers are deliberately
        // retained as cleanup handles, so there is nothing to reconcile here.
        // The transitions INTO this phase, and the retry that can leave it,
        // belong to the verified-teardown controller work.
        //
        // An operator override naming this lease's UID is the one other way
        // out (`crate::quarantine`). Boxed to keep its awaits off this
        // future's frame.
        LeasePhase::Quarantined if crate::quarantine::release_requested(&lease.metadata) => {
            Box::pin(release_quarantined_lease(
                &ctx.client,
                &ns,
                &leases_api,
                &lease,
            ))
            .await
        }
        LeasePhase::Quarantined => Ok(Action::requeue(std::time::Duration::from_secs(300))),

        // The instance watch wakes this lease when its instance is deleted;
        // the timers below only back that up.
        LeasePhase::Recycling => {
            let mut read_failed = false;
            let cluster_gone = if let Some(binding) = &status.binding {
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
                match instances_api.get(&binding.instance.name).await {
                    Ok(instance) => {
                        if instance.metadata.uid.as_deref() != Some(binding.instance.uid.as_str()) {
                            warn!(
                                lease = %name,
                                cluster = %binding.instance.name,
                                reason = "instance_uid_mismatch",
                                "Same-named replacement is not recycling completion"
                            );
                        } else if !mark_instance_recycling(&ctx.client, &ns, binding).await? {
                            warn!(lease = %name, reason = "reciprocal_binding_mismatch", "Exact instance is not safe to recycle");
                        }
                        false
                    }
                    Err(kube::Error::Api(ae)) if ae.code == 404 => true,
                    Err(e) => {
                        warn!(lease = %name, cluster = %binding.instance.name, "Failed to query ClusterInstance during recycle: {e}");
                        read_failed = true;
                        false
                    }
                }
            } else {
                mark_binding_unverified(&leases_api, &lease, "binding_missing").await?;
                false
            };

            if cluster_gone {
                // A receipt-required lease carries the ONLY durable proof that
                // its capacity was destroyed, and it is read after the instance
                // is gone — which is exactly the moment this branch fires. So
                // deleting the lease here would destroy the evidence at the
                // instant it becomes relevant, and #74's owning SandboxLease
                // would have nothing to consume.
                //
                // Retain it until a consumer acknowledges. Deliberately not a
                // timeout: evidence that expires on a clock is evidence you
                // cannot rely on having.
                if teardown_receipt_unconsumed(&lease, &status) {
                    debug!(
                        lease = %name,
                        "retaining recycled lease: its teardown receipt has not been consumed"
                    );
                    return Ok(Action::requeue(std::time::Duration::from_secs(300)));
                }
                let lease = if status.teardown_receipt.is_some() {
                    remove_receipt_retention_finalizer(&ctx.client, &ns, &lease).await?
                } else {
                    (*lease).clone()
                };
                if sandbox_composition_requires_outer_retirement(&lease)
                    && !stale_sandbox_composition_was_rejected(&lease)
                {
                    // ACK alone is not evidence that the new retention
                    // finalizer is installed. The outer controller owns the
                    // fenced delete for ordinary compositions; only an exact
                    // autonomous stale rejection may retire itself here.
                    debug!(lease = %name, "retaining Sandbox composition receipt for outer retirement");
                    return Ok(Action::requeue(std::time::Duration::from_secs(300)));
                }
                info!(lease = %name, "Recycling complete, deleting lease CRD");
                Ok(if delete_lease_crd(&leases_api, &lease).await {
                    Action::await_change()
                } else {
                    Action::requeue(std::time::Duration::from_secs(15))
                })
            } else {
                debug!(lease = %name, "Lease in recycling phase, waiting for cluster cleanup");
                Ok(Action::requeue(if read_failed {
                    RECYCLING_READ_RETRY
                } else {
                    RECYCLING_BACKSTOP
                }))
            }
        }
    }
}

/// Release a quarantined lease on operator override, without a verified
/// teardown receipt.
///
/// Revokes access first: the connect-token Secret must be gone (or proven
/// absent) before the lease that owns it is deleted. Then drops the receipt
/// retention finalizer and deletes the lease under UID + resourceVersion
/// preconditions. The bound instance is not touched; it carries its own
/// quarantine and needs its own override.
///
/// A Sandbox composition lease is refused. Its receipt belongs to the owning
/// SandboxLease, which retires it; deleting it here would leave that owner
/// waiting for evidence that can no longer arrive.
async fn release_quarantined_lease(
    client: &Client,
    namespace: &str,
    leases_api: &Api<ClusterLease>,
    lease: &ClusterLease,
) -> Result<Action, LeaseError> {
    let name = lease.name_any();
    let pool = lease.spec.pool_ref.as_str();
    let lease_uid = lease_uid_for(lease)?;
    if sandbox_composition_requires_outer_retirement(lease) {
        // Once per lease per process: the refusal does not change on requeue,
        // and a Warning event every five minutes would bury everything else.
        if crate::quarantine::first_refusal(lease_uid) {
            warn!(
                lease = %name,
                "QUARANTINE OVERRIDE refused: a Sandbox composition lease is retired through its SandboxLease"
            );
            crate::quarantine::publish_warning(
                client,
                &lease.object_ref(&()),
                "QuarantineReleaseRefused",
                "Sandbox composition leases are released through their SandboxLease".into(),
            )
            .await;
        }
        return Ok(Action::requeue(std::time::Duration::from_secs(300)));
    }
    if let Err(error) =
        crate::api::connect::delete_lease_connect_token(client, namespace, &name, lease_uid).await
    {
        warn!(lease = %name, "QUARANTINE OVERRIDE waiting: connect-token revoke failed: {error:#}");
        return Ok(Action::requeue(std::time::Duration::from_secs(30)));
    }
    let held_retention = lease
        .finalizers()
        .iter()
        .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER);
    let lease = remove_receipt_retention_finalizer(client, namespace, lease).await?;
    // Record only a release that happened. A failed finalizer write (for
    // example the split-authority admission policy refusing it) or delete
    // returns above or requeues below without counting, so a retry loop
    // cannot inflate the counter or repeat the event.
    let released = if lease.metadata.deletion_timestamp.is_some() {
        // Already deleting: dropping our finalizer was the release, and only
        // if it was still there. A lease this path deleted earlier, held open
        // by another finalizer, was counted then.
        held_retention
    } else if delete_lease_crd(leases_api, &lease).await {
        true
    } else {
        return Ok(Action::requeue(std::time::Duration::from_secs(15)));
    };
    if released {
        warn!(
            lease = %name,
            pool,
            annotation = crate::quarantine::RELEASE_QUARANTINE_ANNOTATION,
            "QUARANTINE OVERRIDE: released quarantined lease without a verified teardown receipt"
        );
        crate::quarantine::record_release(
            client,
            &lease.object_ref(&()),
            crate::quarantine::QuarantinedKind::Lease,
            pool,
            "released by operator override without a verified teardown receipt; access revoked"
                .into(),
        )
        .await;
    }
    Ok(Action::await_change())
}

/// The binding of a terminal Standard lease that only ever held a reservation
/// intent: it never reached Bound (no `clusterName`), and nothing else keeps it
/// (no unconsumed receipt, no outer Sandbox retirement, not verified cleanup).
///
/// Such a lease is retireable once its exact instance holds nothing for it (see
/// [`exact_instance_holds_nothing_for`]). While that instance still carries the
/// reservation the lease stays: the instance controller recycles a Leased
/// instance whose exact lease is terminal, and the lease is its handle.
fn orphaned_standard_intent<'a>(
    lease: &ClusterLease,
    status: &'a ClusterLeaseStatus,
    verified_cleanup: bool,
) -> Option<&'a LeaseBinding> {
    let binding = status.binding.as_ref()?;
    (!verified_cleanup
        && matches!(status.phase, LeasePhase::Released | LeasePhase::Expired)
        && status.cluster_name.is_none()
        && binding.cleanup_mode == CleanupMode::Standard
        && lease.spec.cleanup_mode.unwrap_or_default() == CleanupMode::Standard
        && !sandbox_composition_requires_outer_retirement(lease)
        && !teardown_receipt_unconsumed(lease, status))
    .then_some(binding)
}

/// Retire a terminal lease matching [`orphaned_standard_intent`] whose exact
/// instance is gone or no longer reserved for it. `None` leaves the lease to
/// the caller.
async fn retire_orphaned_standard_intent(
    client: &Client,
    namespace: &str,
    leases_api: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
    verified_cleanup: bool,
    reason: &str,
) -> Result<Option<Action>, LeaseError> {
    let Some(binding) = orphaned_standard_intent(lease, status, verified_cleanup) else {
        return Ok(None);
    };
    let Some(lease_uid) = lease.metadata.uid.as_deref() else {
        return Ok(None);
    };
    let Some(release) =
        exact_instance_holds_nothing_for(client, namespace, lease_uid, binding).await?
    else {
        return Ok(None);
    };
    info!(
        lease = %lease.name_any(),
        phase = %status.phase,
        instance = %binding.instance.name,
        reason,
        release = release.as_str(),
        "Retiring terminal lease: its unbound reservation intent holds no instance"
    );
    crate::metrics::LEASES_RETIRED_UNBOUND_TOTAL
        .with_label_values(&[
            lease.spec.pool_ref.as_str(),
            status.phase.to_string().as_str(),
        ])
        .inc();
    let lease = remove_receipt_retention_finalizer(client, namespace, lease).await?;
    Ok(Some(if delete_lease_crd(leases_api, &lease).await {
        Action::await_change()
    } else {
        Action::requeue(std::time::Duration::from_secs(15))
    }))
}

/// Why the exact instance a reservation intent names holds nothing for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentRelease {
    /// The instance is gone: 404, or the name belongs to a replacement.
    InstanceGone,
    /// The same instance exists but neither its `binding` nor its `leaseRef`
    /// names this lease. The instance controller released the orphan
    /// reservation (`ReleaseOrphan`), or another lease reserved it since.
    ReservationReleased,
}

impl IntentRelease {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InstanceGone => "instance_gone",
            Self::ReservationReleased => "reservation_released",
        }
    }
}

/// Whether the exact instance a binding names holds nothing for the lease
/// with `lease_uid`, and why. `None` means it may still hold the reservation.
///
/// Read from the instance, which is where a reservation lives: reserving is
/// a resourceVersion-fenced write of `status.binding` and `status.leaseRef`,
/// and releasing an orphan clears both. An instance that names this lease in
/// either field still holds it. Lookup failures are errors, never absence.
async fn exact_instance_holds_nothing_for(
    client: &Client,
    namespace: &str,
    lease_uid: &str,
    binding: &LeaseBinding,
) -> Result<Option<IntentRelease>, LeaseError> {
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instance = match instances.get(&binding.instance.name).await {
        Ok(instance) => instance,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Ok(Some(IntentRelease::InstanceGone));
        }
        Err(error) => return Err(error.into()),
    };
    if instance.metadata.uid.as_deref() != Some(binding.instance.uid.as_str()) {
        return Ok(Some(IntentRelease::InstanceGone));
    }
    Ok((!instance_names_lease(&instance, lease_uid)).then_some(IntentRelease::ReservationReleased))
}

/// Whether an instance's reservation fields name the lease with `lease_uid`.
fn instance_names_lease(instance: &ClusterInstance, lease_uid: &str) -> bool {
    let Some(status) = instance.status.as_ref() else {
        return false;
    };
    let by_binding = status
        .binding
        .as_ref()
        .is_some_and(|binding| binding.lease.uid.as_deref() == Some(lease_uid));
    let by_ref = status
        .lease_ref
        .as_ref()
        .is_some_and(|reference| reference.uid.as_deref() == Some(lease_uid));
    by_binding || by_ref
}

fn requires_attempt_bound_token_deletion(lease: &ClusterLease) -> bool {
    lease
        .spec
        .cleanup_mode
        .unwrap_or_default()
        .requires_receipt()
}

/// Extend a lease's TTL.
pub async fn extend_lease_ttl(
    client: &Client,
    namespace: &str,
    lease_name: &str,
    extend_by: &str,
    expected_lease_uid: &str,
    authenticator: &JwtAuthenticator,
) -> Result<String, LeaseError> {
    let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = leases_api.get(lease_name).await?;

    // The caller authorized a specific object, not a name. A name-reused
    // replacement belongs to whoever created it, so deny before touching it.
    if lease.metadata.uid.as_deref() != Some(expected_lease_uid) {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Cannot extend TTL: lease identity changed"
        )));
    }
    let lease_rv = lease
        .resource_version()
        .ok_or_else(|| LeaseError::Lifecycle(anyhow::anyhow!("Lease has no resourceVersion")))?;

    let status = lease.status.clone().unwrap_or_default();

    if status.phase != LeasePhase::Bound {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Cannot extend TTL: lease is not in Bound phase (current: {})",
            status.phase
        )));
    }

    if status.extensions_count >= status.max_extensions {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Maximum extensions ({}) reached",
            status.max_extensions
        )));
    }

    let extension = parse_duration(extend_by)
        .ok_or_else(|| LeaseError::Lifecycle(anyhow::anyhow!("Invalid duration: {extend_by}")))?;

    let current_expiry = status
        .expires_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);

    let new_expiry = current_expiry + extension;

    let bound_at = status
        .bound_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            LeaseError::Lifecycle(anyhow::anyhow!("Lease has no valid bound_at timestamp"))
        })?;

    // Fail closed: the bound_at + max_ttl ceiling is a hard cap, so a lease whose
    // policy can no longer be resolved (e.g. the AuthPolicy was renamed/removed
    // after the lease was minted) must NOT be extendable without a ceiling.
    // Treating a missing policy as "no cap" would let a requester extend a Bound
    // lease arbitrarily, up to max_extensions.
    let policy = authenticator
        .policy_for_requester_type(&lease.spec.requester.requester_type)
        .await
        .ok_or_else(|| {
            LeaseError::Lifecycle(anyhow::anyhow!(
                "Cannot extend TTL: no policy resolves requester type '{}' \
                 (the AuthPolicy may have been renamed or removed); refusing to \
                 extend without a maximum-TTL ceiling",
                lease.spec.requester.requester_type
            ))
        })?;
    let max_expiry = bound_at + policy.max_ttl;
    if new_expiry > max_expiry {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Extension would exceed maximum TTL ({}). Max expiry: {}",
            crate::api::policy::format_duration(&policy.max_ttl),
            max_expiry.to_rfc3339()
        )));
    }

    // JSON Patch, not Merge: `extensionsCount` is a read-modify-write, so the
    // write must be conditional on the exact object and count we read.
    // Otherwise two concurrent extends both observe N and both write N+1,
    // spending one extension and letting the pair slip past `maxExtensions`.
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": expected_lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
        { "op": "test", "path": "/status/extensionsCount", "value": status.extensions_count },
        { "op": "add", "path": "/status/expiresAt", "value": new_expiry.to_rfc3339() },
        { "op": "add", "path": "/status/extensionsCount", "value": status.extensions_count + 1 }
    ]));
    leases_api
        .patch_status(
            lease_name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await?;

    crate::metrics::CLAIMS_TOTAL
        .with_label_values(&[lease.spec.pool_ref.as_str(), "extended"])
        .inc();

    info!(
        lease = lease_name,
        new_expiry = %new_expiry,
        extension_number = status.extensions_count + 1,
        "Lease TTL extended"
    );

    Ok(new_expiry.to_rfc3339())
}

fn created_at_for(lease: &ClusterLease) -> chrono::DateTime<chrono::Utc> {
    lease
        .metadata
        .creation_timestamp
        .as_ref()
        .and_then(|timestamp| {
            chrono::DateTime::parse_from_rfc3339(&timestamp.0.to_string())
                .ok()
                .map(|value| value.with_timezone(&chrono::Utc))
        })
        .unwrap_or_else(chrono::Utc::now)
}

/// Enforce the durable Sandbox authority around final publication.
///
/// A legacy composition that is already exactly `Bound` may finish recovery:
/// this helper is not granting new access in that case. Every Pending intent,
/// including one from a legacy producer, must still prove the outer authority,
/// its exact live pool, and the binding pool before `Bound` can be published.
async fn sandbox_composition_finalization_is_authorized<B: ClusterBackend>(
    ctx: &LeaseContext<B>,
    namespace: &str,
    leases_api: &Api<ClusterLease>,
    lease: &ClusterLease,
    binding: &LeaseBinding,
    already_bound: bool,
) -> Result<bool, LeaseError> {
    match sandbox_composition_allocation_gate(&ctx.client, namespace, lease).await {
        SandboxCompositionGate::NotComposition => {
            if lease.metadata.deletion_timestamp.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "lease was deleted while finalizing binding"
                )));
            }
            Ok(true)
        }
        SandboxCompositionGate::Authorized(authority)
            if binding_pool_matches_sandbox_authority(binding, &authority) =>
        {
            Ok(true)
        }
        SandboxCompositionGate::LegacyBoundRecovery if already_bound => Ok(true),
        SandboxCompositionGate::LegacyBoundRecovery => Ok(false),
        SandboxCompositionGate::Authorized(_) | SandboxCompositionGate::Invalid => {
            if !mark_instance_recycling(&ctx.client, namespace, binding).await? {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "invalid Sandbox reservation could not be fenced for recycling"
                )));
            }
            let _ = quarantine_invalid_sandbox_composition(leases_api, lease).await?;
            Ok(false)
        }
        SandboxCompositionGate::NeedsMigration(identity) => {
            let _ =
                migrate_sandbox_composition_retention_fence(leases_api, lease, &identity).await?;
            Ok(false)
        }
        SandboxCompositionGate::Closed(identity) => {
            let _ = close_stale_sandbox_composition(
                &ctx.client,
                namespace,
                leases_api,
                lease,
                &identity,
            )
            .await?;
            Ok(false)
        }
        SandboxCompositionGate::Retry => Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "Sandbox composition authorization unavailable while finalizing binding"
        ))),
    }
}

const FINALIZE_BINDING_ATTEMPTS: usize = 3;

fn model_lease_phase(phase: &LeasePhase) -> ModelLeasePhase {
    match phase {
        LeasePhase::Pending => ModelLeasePhase::Pending,
        LeasePhase::Bound => ModelLeasePhase::Bound,
        LeasePhase::Released => ModelLeasePhase::Released,
        LeasePhase::Expired => ModelLeasePhase::Expired,
        LeasePhase::Recycling => ModelLeasePhase::Recycling,
        LeasePhase::Quarantined => ModelLeasePhase::Quarantined,
    }
}

fn model_instance_phase(phase: &ClusterInstancePhase) -> ModelInstancePhase {
    match phase {
        ClusterInstancePhase::Creating => ModelInstancePhase::Creating,
        ClusterInstancePhase::Ready => ModelInstancePhase::Ready,
        ClusterInstancePhase::Leased => ModelInstancePhase::Leased,
        ClusterInstancePhase::Recycling => ModelInstancePhase::Recycling,
        ClusterInstancePhase::Unhealthy => ModelInstancePhase::Unhealthy,
        ClusterInstancePhase::Failed => ModelInstancePhase::Failed,
        ClusterInstancePhase::Quarantined => ModelInstancePhase::Quarantined,
    }
}

fn model_binding_state(
    observed: Option<&LeaseBinding>,
    expected: &LeaseBinding,
) -> ModelBindingState {
    match observed {
        Some(binding) if binding == expected => ModelBindingState::Expected,
        None => ModelBindingState::Absent,
        Some(_) => ModelBindingState::Foreign,
    }
}

/// Complete a previously persisted two-sided reservation.
///
/// Returns `true` only when `Bound` is already or successfully published. If a
/// Sandbox allocation fence closed after reservation, the exact instance is
/// first moved to `Recycling`, the handle is terminalized behind its retention
/// fence, and `false` asks the caller for a short convergence requeue. Thus the
/// cross-object gate-to-reserve window can consume capacity transiently but
/// can neither publish `Bound` nor strand that capacity.
async fn finalize_binding<B: ClusterBackend>(
    ctx: &LeaseContext<B>,
    namespace: &str,
    binding: &LeaseBinding,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, LeaseError> {
    let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), namespace);
    let instances: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), namespace);
    for attempt in 1..=FINALIZE_BINDING_ATTEMPTS {
        let lease = leases_api.get(&binding.lease.name).await?;
        if lease.metadata.uid.as_deref() != binding.lease.uid.as_deref() {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "lease UID changed while finalizing binding"
            )));
        }
        let status = lease.status.clone().unwrap_or_default();
        let lease_binding_state = model_binding_state(status.binding.as_ref(), binding);
        let already_bound =
            status.phase == LeasePhase::Bound && lease_binding_state == ModelBindingState::Expected;
        if !already_bound
            && (status.phase != LeasePhase::Pending
                || lease_binding_state != ModelBindingState::Expected)
        {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "lease binding intent changed before finalization"
            )));
        }
        if !sandbox_composition_finalization_is_authorized(
            ctx,
            namespace,
            &leases_api,
            &lease,
            binding,
            already_bound,
        )
        .await?
        {
            return Ok(false);
        }
        let instance = instances.get(&binding.instance.name).await?;
        if !instance_matches_binding_subject(&instance, binding) {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "instance reciprocal binding changed before finalization"
            )));
        }
        let instance_status = instance.status.clone().unwrap_or_default();
        let decision = exact_binding_finalization(
            model_lease_phase(&status.phase),
            model_binding_state(status.binding.as_ref(), binding),
            model_instance_phase(&instance_status.phase),
            model_binding_state(instance_status.binding.as_ref(), binding),
        );
        if decision == FinalizationDecision::Superseded {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "exact reciprocal binding changed before finalization"
            )));
        }
        debug_assert_eq!(
            already_bound,
            decision == FinalizationDecision::AlreadyBound
        );
        validate_binding_eligibility(ctx.factory.as_ref(), namespace, &lease, &instance, binding)
            .await
            .map_err(LeaseError::Lifecycle)?;
        if binding.cleanup_mode.requires_receipt() {
            crate::api::connect::ensure_lease_connect_token(
                &ctx.client,
                namespace,
                &lease,
                binding,
            )
            .await
            .map_err(LeaseError::Lifecycle)?;
        }
        if already_bound {
            return Ok(true);
        }

        let lease_uid = binding
            .lease
            .uid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("binding missing lease UID"))?;
        let lease_rv = lease
            .resource_version()
            .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
        let ttl = parse_duration(&lease.spec.ttl).unwrap_or_else(|| chrono::Duration::hours(1));
        let now = chrono::Utc::now();
        let expires_at = now + ttl;
        let max_extensions = ctx
            .authenticator
            .policy_for_requester_type(&lease.spec.requester.requester_type)
            .await
            .map(|policy| policy.max_extensions)
            .unwrap_or(2);
        let mut new_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some(binding.instance.name.clone()),
            binding: Some(binding.clone()),
            bound_at: Some(now.to_rfc3339()),
            expires_at: Some(expires_at.to_rfc3339()),
            queue_position: 0,
            diagnostics_url: None,
            extensions_count: 0,
            max_extensions,
            message: None,
            conditions: Vec::new(),
            teardown_receipt: None,
            teardown_evidence: None,
            teardown_attempt_id: None,
            connect_token_creation: status.connect_token_creation.clone(),
            unbound_release_verified_at: None,
            teardown_acknowledgement: None,
        };
        new_status.conditions =
            derive_lease_conditions(&new_status, &status.conditions, None, &now.to_rfc3339());

        // Re-read the outer and exact live pool immediately before publishing
        // `Bound`. This closes replacement races during instance/token validation.
        if !sandbox_composition_finalization_is_authorized(
            ctx,
            namespace,
            &leases_api,
            &lease,
            binding,
            false,
        )
        .await?
        {
            return Ok(false);
        }

        let mut operations = vec![
            serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid }),
            serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv }),
            serde_json::json!({ "op": "test", "path": "/status/phase", "value": "Pending" }),
            serde_json::json!({ "op": "test", "path": "/status/binding", "value": binding }),
            serde_json::json!({ "op": "add", "path": "/status/phase", "value": "Bound" }),
            serde_json::json!({ "op": "add", "path": "/status/clusterName", "value": binding.instance.name }),
            serde_json::json!({ "op": "add", "path": "/status/boundAt", "value": new_status.bound_at }),
            serde_json::json!({ "op": "add", "path": "/status/expiresAt", "value": new_status.expires_at }),
            serde_json::json!({ "op": "add", "path": "/status/queuePosition", "value": 0 }),
            serde_json::json!({ "op": "add", "path": "/status/extensionsCount", "value": 0 }),
            serde_json::json!({ "op": "add", "path": "/status/maxExtensions", "value": max_extensions }),
            serde_json::json!({ "op": "add", "path": "/status/conditions", "value": new_status.conditions }),
        ];
        if status.message.is_some() {
            operations.push(serde_json::json!({ "op": "remove", "path": "/status/message" }));
        }
        let patch = json_patch(serde_json::Value::Array(operations));
        match leases_api
            .patch_status(
                &binding.lease.name,
                &PatchParams::default(),
                &Patch::<()>::Json(patch),
            )
            .await
        {
            Ok(_) => {
                let bind_duration =
                    (chrono::Utc::now() - created_at).num_milliseconds() as f64 / 1000.0;
                crate::metrics::CLAIM_BIND_DURATION
                    .with_label_values(&[lease.spec.pool_ref.as_str()])
                    .observe(bind_duration);
                crate::metrics::LEASE_QUEUE_WAIT_SECONDS
                    .with_label_values(&[lease.spec.pool_ref.as_str(), "bound"])
                    .observe(bind_duration);
                crate::metrics::CLAIMS_TOTAL
                    .with_label_values(&[lease.spec.pool_ref.as_str(), "bound"])
                    .inc();
                info!(
                    lease = %binding.lease.name,
                    cluster = %binding.instance.name,
                    expires_at = %expires_at,
                    bind_seconds = bind_duration,
                    "Lease bound to exact ClusterInstance"
                );
                return Ok(true);
            }
            Err(error) if optimistic_conflict(&error) && attempt < FINALIZE_BINDING_ATTEMPTS => {
                debug!(
                    lease = %binding.lease.name,
                    attempt,
                    "binding finalization lost a race; re-reading both sides before retry"
                );
            }
            Err(error) => return Err(error.into()),
        }
    }

    unreachable!("bounded binding-finalization loop always returns")
}

/// Message stamped on a lease whose binding could not be verified.
const BINDING_UNVERIFIED_MESSAGE: &str =
    "binding unverified; access revoked; recycle/quarantine required";

/// Delete a lease CRD, fenced on the exact object we just read.
///
/// The uid + resourceVersion preconditions mean a same-named replacement or a
/// concurrently-modified lease is never the thing deleted. A 404 is success:
/// something else already removed it.
async fn delete_lease_crd(leases_api: &Api<ClusterLease>, lease: &ClusterLease) -> bool {
    let name = lease.name_any();
    let delete_params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: lease.metadata.uid.clone(),
            resource_version: lease.resource_version(),
        }),
        ..Default::default()
    };
    match leases_api.delete(&name, &delete_params).await {
        Ok(_) => true,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // Already deleted, that's fine
            true
        }
        Err(e) => {
            warn!(lease = %name, "Failed to delete lease CRD: {e}");
            false
        }
    }
}

/// True when a terminal lease still owes someone its teardown receipt.
///
/// Mirrors the retention rule the Recycling arm applies: a receipt is the only
/// durable proof that capacity was destroyed, so it outlives the lease until a
/// consumer acknowledges it.
fn teardown_receipt_unconsumed(lease: &ClusterLease, status: &ClusterLeaseStatus) -> bool {
    let Some(receipt) = status.teardown_receipt.as_ref() else {
        return false;
    };
    if stale_sandbox_composition_was_rejected(lease) {
        return receipt.acknowledgement_token().is_none();
    }
    !teardown_receipt_acknowledged(lease, status)
}

fn sandbox_composition_requires_outer_retirement(lease: &ClusterLease) -> bool {
    lease.spec.requester.requester_type == "kobe:sandbox-composition"
        && !lease.spec.requester.identity.is_empty()
        && lease.spec.cleanup_mode == Some(crate::crd::CleanupMode::VerifiedDestroy)
}

fn stale_sandbox_composition_was_rejected(lease: &ClusterLease) -> bool {
    let labels = lease.labels();
    let annotations = lease.annotations();
    let Some(outer_uid) = labels
        .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL)
        .filter(|uid| !uid.is_empty())
    else {
        return false;
    };
    let Some(outer_name) = annotations
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION)
        .filter(|name| !name.is_empty())
    else {
        return false;
    };
    let retention_deadline_is_valid = annotations
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some();

    lease.name_any() == crate::controllers::sandbox_child::internal_lease_name(outer_name)
        && lease.namespace().is_some()
        && lease
            .metadata
            .owner_references
            .as_ref()
            .is_none_or(Vec::is_empty)
        && labels
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
        && labels
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL)
            .is_some_and(|value| value == "true")
        && lease.spec.requester.requester_type == "kobe:sandbox-composition"
        && lease.spec.requester.identity == *outer_uid
        && lease.spec.cleanup_mode == Some(crate::crd::CleanupMode::VerifiedDestroy)
        && annotations
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION)
            == Some(outer_uid)
        && retention_deadline_is_valid
        && lease.finalizers().iter().any(|finalizer| {
            finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
        })
}

/// Exact acknowledgement token for a terminal lease that never bound.
///
/// Both the durable teardown attempt and its API-server-observed absence
/// timestamp participate, so an acknowledgement from an earlier attempt
/// cannot retire a later proof-bearing handle.
pub(crate) fn unbound_release_acknowledgement_token(status: &ClusterLeaseStatus) -> Option<String> {
    if !unbound_release_proof_is_complete(status) {
        return None;
    }
    let attempt = status
        .teardown_attempt_id
        .as_deref()
        .filter(|attempt| !attempt.trim().is_empty())?;
    let verified_at = status.unbound_release_verified_at.as_deref()?;
    Some(format!("{attempt}:{verified_at}"))
}

/// Acknowledgement is bound to the exact terminal receipt, not a boolean flag.
/// The Sandbox consumer must first call `permits_release_for` with its trusted
/// scope and then write this token; a stale attempt annotation never releases a
/// newer receipt.
fn teardown_receipt_acknowledged(lease: &ClusterLease, status: &ClusterLeaseStatus) -> bool {
    status
        .teardown_receipt
        .as_ref()
        .and_then(|receipt| receipt.acknowledgement_token())
        .zip(status.teardown_receipt.as_ref())
        .is_some_and(|(expected, receipt)| {
            if crate::receipt_authority::is_separate() {
                return status.teardown_acknowledgement.as_ref().is_some_and(|ack| {
                    ack.attempt_id == receipt.attempt_id
                        && ack.proof.kind == TeardownAcknowledgedProofKind::Receipt
                        && ack.proof.receipt_token.as_deref() == Some(expected.as_str())
                        && ack.proof.evidence.as_ref().is_some_and(|evidence| {
                            status.teardown_evidence.as_ref() == Some(evidence)
                        })
                });
            }
            lease
                .annotations()
                .get(TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION)
                == Some(&expected)
        })
}

/// A `NeverBound` proof is attempt-bound and may exist only after the
/// create-capable token state is absent or durably Closed.
///
/// A verified binding intent is deliberately retained when its creator was
/// closed directly from `Prepared`. Keeping that exact identity prevents a
/// later reader from mistaking "no reciprocal allocation" for "no intent ever
/// existed", while the closed creator makes delayed token creation impossible.
fn unbound_release_proof_is_complete(status: &ClusterLeaseStatus) -> bool {
    let attempt = status
        .teardown_attempt_id
        .as_deref()
        .filter(|attempt| !attempt.trim().is_empty());
    let verified_at = status
        .unbound_release_verified_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
    let creator_closed = status
        .connect_token_creation
        .as_ref()
        .is_none_or(|creation| {
            creation.phase == ConnectTokenCreationPhase::Closed
                && creation.verified_absent_at.as_deref()
                    == status.unbound_release_verified_at.as_deref()
        });
    attempt.is_some()
        && verified_at.is_some()
        && matches!(status.phase, LeasePhase::Released | LeasePhase::Expired)
        && creator_closed
        && (status.binding.is_none() || retained_unstarted_binding_is_closed(status))
        && status.cluster_name.is_none()
        && status.teardown_receipt.is_none()
        && status.teardown_evidence.is_none()
        && status.conditions.iter().any(|condition| {
            condition.condition_type == ALLOCATION_ABSENT_CONDITION
                && condition.status == "True"
                && condition.reason == "NeverBound"
                && condition.message.contains(attempt.unwrap())
        })
}

fn unbound_release_proof_is_complete_for_lease(
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
) -> bool {
    unbound_release_proof_is_complete(status)
        && (status.binding.is_none() || retained_unstarted_binding_matches_lease(lease, status))
}

fn unbound_release_proof_acknowledged(lease: &ClusterLease, status: &ClusterLeaseStatus) -> bool {
    status.teardown_attempt_id.as_ref().is_some_and(|attempt| {
        if crate::receipt_authority::is_separate() {
            return status.teardown_acknowledgement.as_ref().is_some_and(|ack| {
                ack.attempt_id == *attempt
                    && ack.proof.kind == TeardownAcknowledgedProofKind::NeverBound
                    && ack
                        .proof
                        .unbound_release_verified_at
                        .as_ref()
                        .is_some_and(|verified_at| {
                            status.unbound_release_verified_at.as_ref() == Some(verified_at)
                        })
            });
        }
        lease
            .annotations()
            .get(UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION)
            == Some(attempt)
    })
}

/// Persist the release attempt before any token deletion or absence lookup.
async fn ensure_unbound_release_attempt(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
) -> Result<Option<String>, LeaseError> {
    if let Some(attempt) = status
        .teardown_attempt_id
        .as_ref()
        .filter(|attempt| !attempt.trim().is_empty())
    {
        return Ok(Some(attempt.clone()));
    }
    if status.teardown_attempt_id.is_some() || status.teardown_receipt.is_some() {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "unbound release has malformed or conflicting teardown evidence"
        )));
    }
    if crate::receipt_authority::is_separate() {
        // Only the dedicated authority may open a destructive attempt in the
        // split deployment. The lifecycle controller will requeue without
        // issuing a DELETE until that exact nonce is visible.
        return Ok(None);
    }
    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let attempt = uuid::Uuid::new_v4().to_string();
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "add", "path": "/status/teardownAttemptId", "value": attempt }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(None),
        Err(error) if optimistic_conflict(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn record_unbound_release_proof(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
    attempt: &str,
    verified_at: &str,
) -> Result<(), LeaseError> {
    if status.teardown_attempt_id.as_deref() != Some(attempt)
        || status.cluster_name.is_some()
        || (status.binding.is_some() && !retained_unstarted_binding_matches_lease(lease, status))
        || status.teardown_receipt.is_some()
    {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "NeverBound proof lost its exact release attempt"
        )));
    }
    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let mut conditions: Vec<_> = status
        .conditions
        .iter()
        .filter(|condition| condition.condition_type != ALLOCATION_ABSENT_CONDITION)
        .cloned()
        .collect();
    conditions.push(ClusterLeaseCondition {
        condition_type: ALLOCATION_ABSENT_CONDITION.into(),
        status: "True".into(),
        reason: "NeverBound".into(),
        message: format!("release attempt {attempt} proved no reciprocal allocation existed"),
        last_transition_time: Some(verified_at.to_string()),
    });
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "test", "path": "/status/teardownAttemptId", "value": attempt },
        { "op": "add", "path": "/status/unboundReleaseVerifiedAt", "value": verified_at },
        { "op": "add", "path": "/status/conditions", "value": conditions }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Close the only create-capable token attempt for a terminal verified lease.
///
/// Every destructive step is bound to the already-persisted teardown attempt.
/// `Creating` is observation-only: a 404 is ambiguous and therefore never
/// advances to `Closed`. `Closed` is reached only after either proving that the
/// attempt was still `Prepared` (so no POST was permitted) or deleting an exact
/// persisted Secret UID and observing its absence.
async fn close_terminal_connect_token_creation(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
    binding: &LeaseBinding,
) -> Result<Option<(ClusterLease, LeaseBinding)>, LeaseError> {
    let creation = status.connect_token_creation.as_ref().ok_or_else(|| {
        LeaseError::Lifecycle(anyhow::anyhow!(
            "verified terminal binding has no token creation checkpoint"
        ))
    })?;
    let teardown_attempt = status
        .teardown_attempt_id
        .as_deref()
        .filter(|attempt| !attempt.trim().is_empty())
        .ok_or_else(|| {
            LeaseError::Lifecycle(anyhow::anyhow!(
                "terminal token close has no durable teardown attempt"
            ))
        })?;
    if !matches!(status.phase, LeasePhase::Released | LeasePhase::Expired)
        || status.binding.as_ref() != Some(binding)
        || creation.attempt_id.trim().is_empty()
    {
        return Ok(None);
    }

    if creation.phase == ConnectTokenCreationPhase::Closed {
        let verified_at = creation
            .verified_absent_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
        let identity_matches = match creation.identity.as_ref() {
            Some(identity) => binding.connect_token.as_ref() == Some(identity),
            None => binding.connect_token.is_none(),
        };
        if verified_at.is_none() || !identity_matches {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "Closed connect-token attempt lacks exact absence evidence"
            )));
        }
        return Ok(Some((lease.clone(), binding.clone())));
    }

    let mut next_binding = binding.clone();
    let mut next_creation = creation.clone();
    match creation.phase {
        ConnectTokenCreationPhase::Prepared => {
            if creation.identity.is_some() || binding.connect_token.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Prepared token attempt unexpectedly carries an identity"
                )));
            }
            // The only code path allowed to POST first CASes Prepared to
            // Creating while the lease is Pending. This terminal observation
            // therefore proves no create was dispatched for this attempt.
            next_creation.phase = ConnectTokenCreationPhase::Closed;
            next_creation.verified_absent_at = Some(chrono::Utc::now().to_rfc3339());
            // No reservation can be in flight before Creating. Retain the
            // exact intent as an audit handle while closing its creator in the
            // same CAS; the authority may later prove the referenced instance
            // and every other reciprocal lease UID absent without pretending
            // the intent never existed.
        }
        ConnectTokenCreationPhase::Creating => {
            if creation.identity.is_some() || binding.connect_token.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Creating token attempt unexpectedly carries an identity"
                )));
            }
            let Some(identity) = crate::api::connect::observe_reserved_lease_connect_token(
                client,
                namespace,
                lease,
                &creation.attempt_id,
            )
            .await
            .map_err(LeaseError::Lifecycle)?
            else {
                // The original POST may still arrive. Never issue another POST
                // and never certify absence from this 404.
                return Ok(None);
            };
            next_binding.connect_token = Some(identity.clone());
            next_creation.identity = Some(identity);
            next_creation.phase = ConnectTokenCreationPhase::Closing;
        }
        ConnectTokenCreationPhase::Reserved | ConnectTokenCreationPhase::Ready => {
            if creation.identity.as_ref() != binding.connect_token.as_ref()
                || creation.identity.is_none()
            {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "reserved token identity differs from the binding"
                )));
            }
            next_creation.phase = ConnectTokenCreationPhase::Closing;
        }
        ConnectTokenCreationPhase::Closing => {
            let identity = creation.identity.as_ref().ok_or_else(|| {
                LeaseError::Lifecycle(anyhow::anyhow!(
                    "Closing token attempt has no exact identity"
                ))
            })?;
            if binding.connect_token.as_ref() != Some(identity) {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Closing token identity differs from the binding"
                )));
            }
            let check = crate::api::connect::delete_lease_connect_token_verified(
                client,
                namespace,
                &binding.lease.name,
                lease_uid_for(lease)?,
                identity,
            )
            .await;
            if check.result != crate::crd::CheckResult::Verified {
                return Ok(None);
            }
            next_creation.phase = ConnectTokenCreationPhase::Closed;
            next_creation.verified_absent_at = Some(chrono::Utc::now().to_rfc3339());
        }
        ConnectTokenCreationPhase::Closed => unreachable!("handled above"),
    }

    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let mut operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": resource_version }),
        serde_json::json!({ "op": "test", "path": "/status/phase", "value": status.phase }),
        serde_json::json!({ "op": "test", "path": "/status/teardownAttemptId", "value": teardown_attempt }),
        serde_json::json!({ "op": "test", "path": "/status/binding", "value": binding }),
        serde_json::json!({ "op": "test", "path": "/status/connectTokenCreation", "value": creation }),
    ];
    operations.push(serde_json::json!({
        "op": "add", "path": "/status/binding", "value": next_binding
    }));
    operations.push(serde_json::json!({
        "op": "add", "path": "/status/connectTokenCreation", "value": next_creation
    }));
    let patch = json_patch(serde_json::Value::Array(operations));
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(None),
        Err(error) if optimistic_conflict(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn remove_receipt_retention_finalizer(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<ClusterLease, LeaseError> {
    if !lease
        .finalizers()
        .iter()
        .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
    {
        return Ok(lease.clone());
    }
    let uid = lease_uid_for(lease)?;
    let rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let finalizers: Vec<String> = lease
        .finalizers()
        .iter()
        .filter(|finalizer| finalizer.as_str() != TEARDOWN_RECEIPT_RETENTION_FINALIZER)
        .cloned()
        .collect();
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "add", "path": "/metadata/finalizers", "value": finalizers }
    ]));
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    Ok(leases
        .patch(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await?)
}

async fn mark_binding_unverified(
    leases_api: &Api<ClusterLease>,
    lease: &ClusterLease,
    reason: &'static str,
) -> Result<(), LeaseError> {
    // Already stamped: the state is unchanged, so re-sending the identical
    // message buys nothing and re-warning drowns the signal. This WARN marks a
    // real safety condition (binding unverified => access revoked), and it is
    // only legible if it fires on the transition rather than on every requeue.
    // #150: 75 leases repeating it every 30s made up ~98% of operator WARN/ERROR
    // output, hiding any genuine occurrence.
    if lease
        .status
        .as_ref()
        .and_then(|s| s.message.as_deref())
        .is_some_and(|m| m == BINDING_UNVERIFIED_MESSAGE)
    {
        debug!(lease = %lease.name_any(), reason, "Lease binding is still unavailable");
        return Ok(());
    }

    let uid = lease
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("lease missing UID"))?;
    let rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "add", "path": "/status/message", "value": BINDING_UNVERIFIED_MESSAGE }
    ]));
    match leases_api
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => {
            warn!(lease = %lease.name_any(), reason, "Lease binding is unavailable");
            Ok(())
        }
        Err(err) if optimistic_conflict(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Upgrade a pre-schema name-only pair only when it is unique and all current
/// immutable identities/provenance agree. Ambiguity returns `None` and leaves
/// the objects unavailable for later verified teardown/quarantine.
async fn backfill_legacy_binding(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<Option<LeaseBinding>, LeaseError> {
    if lease
        .spec
        .cleanup_mode
        .unwrap_or_default()
        .requires_receipt()
    {
        // A name-only legacy pair never recorded the manifest digest, cleanup
        // mode, or connect-token UID before use. It cannot be upgraded into a
        // VerifiedDestroy capability after the fact.
        return Ok(None);
    }
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    let Some(cluster_name) = status.cluster_name.as_deref() else {
        return Ok(None);
    };
    if status.phase != LeasePhase::Pending || status.binding.is_some() {
        return Ok(None);
    }

    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instances = instances_api
        .list(
            &ListParams::default()
                .labels(&format!("kobe.kunobi.ninja/pool={}", lease.spec.pool_ref)),
        )
        .await?;
    let candidates: Vec<ClusterInstance> = instances
        .into_iter()
        .filter(|instance| {
            instance.name_any() == cluster_name
                && instance.status.as_ref().is_some_and(|instance_status| {
                    instance_status.phase == ClusterInstancePhase::Leased
                        && instance_status.binding.is_none()
                        && instance_status.lease_ref.as_ref().is_some_and(|reference| {
                            reference.name == lease.name_any() && reference.uid.is_none()
                        })
                })
        })
        .collect();
    if candidates.len() != 1 {
        return Ok(None);
    }

    // Prove there is no second lease claiming the same display handle.
    let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let claims = leases_api.list(&ListParams::default()).await?;
    let claimants = claims
        .iter()
        .filter(|candidate| {
            candidate
                .status
                .as_ref()
                .and_then(|candidate_status| candidate_status.cluster_name.as_deref())
                == Some(cluster_name)
        })
        .count();
    if claimants != 1 {
        return Ok(None);
    }

    let pools_api: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let pool = pools_api.get(&lease.spec.pool_ref).await?;
    let binding = match binding_from_observation(lease, &candidates[0], &pool) {
        Ok(binding) => binding,
        Err(reason) => {
            warn!(lease = %lease.name_any(), reason, "Legacy binding proof failed");
            return Ok(None);
        }
    };
    let lease_uid = lease
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("lease missing UID"))?;
    let lease_rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let intent_patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/clusterName", "value": cluster_name },
        { "op": "add", "path": "/status/binding", "value": binding }
    ]));
    match leases_api
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(intent_patch),
        )
        .await
    {
        Ok(_) => {}
        Err(err) if optimistic_conflict(&err) => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    match reserve_binding_instance(client, namespace, &binding).await? {
        ReservationOutcome::Reserved => Ok(Some(binding)),
        ReservationOutcome::Occupied => {
            clear_lease_binding_intent(client, namespace, lease_uid, &binding).await?;
            Ok(None)
        }
        ReservationOutcome::Retry => Ok(None),
    }
}

async fn ensure_receipt_retention_finalizer(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<ClusterLease, LeaseError> {
    if !lease
        .spec
        .cleanup_mode
        .unwrap_or_default()
        .requires_receipt()
        || (lease
            .finalizers()
            .iter()
            .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
            && lease
                .annotations()
                .get(CONNECT_TOKEN_CREATE_FENCE_ANNOTATION)
                .is_some_and(|value| value == "true"))
    {
        return Ok(lease.clone());
    }
    if lease.metadata.deletion_timestamp.is_some() {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "cannot start verified binding while lease deletion is pending"
        )));
    }
    let uid = lease_uid_for(lease)?;
    let rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let mut finalizers = lease.finalizers().to_vec();
    if !finalizers
        .iter()
        .any(|finalizer| finalizer == TEARDOWN_RECEIPT_RETENTION_FINALIZER)
    {
        finalizers.push(TEARDOWN_RECEIPT_RETENTION_FINALIZER.to_string());
    }
    let mut annotations = lease.annotations().clone();
    annotations.insert(CONNECT_TOKEN_CREATE_FENCE_ANNOTATION.into(), "true".into());
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "add", "path": "/metadata/finalizers", "value": finalizers },
        { "op": "add", "path": "/metadata/annotations", "value": annotations }
    ]));
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    Ok(leases
        .patch(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await?)
}

/// Revalidate immutable and live provenance before either side of a binding is
/// published. VerifiedDestroy requires the exact sealed manifest, a backend
/// that can prove it live, and (once provisioned) the exact connect-token UID.
async fn validate_binding_eligibility(
    factory: Option<&BackendFactory>,
    namespace: &str,
    lease: &ClusterLease,
    instance: &ClusterInstance,
    binding: &LeaseBinding,
) -> anyhow::Result<()> {
    let requested = lease.spec.cleanup_mode.unwrap_or_default();
    if binding.cleanup_mode != requested {
        anyhow::bail!("cleanup mode differs from immutable binding provenance");
    }
    if requested != CleanupMode::VerifiedDestroy {
        return Ok(());
    }
    let manifest = instance
        .status
        .as_ref()
        .and_then(|status| status.creation_manifest.as_ref())
        .ok_or_else(|| anyhow::anyhow!("verified placement requires a sealed creation manifest"))?;
    manifest
        .validate()
        .map_err(|reason| anyhow::anyhow!(reason.to_string()))?;
    if manifest.instance.name != binding.instance.name
        || manifest.instance.uid.as_deref() != Some(binding.instance.uid.as_str())
        || manifest.namespace != namespace
        || manifest.backend_type != binding.backend.backend_type
        || manifest.config_digest != binding.backend.config_digest
        || binding.creation_manifest.as_ref() != Some(manifest)
        || manifest.digest().ok().as_deref() != binding.creation_manifest_digest.as_deref()
    {
        anyhow::bail!("creation manifest does not match binding identity/provenance");
    }
    let factory = factory.ok_or_else(|| anyhow::anyhow!("backend factory unavailable"))?;
    let backend = factory.backend_for_provenance(&binding.backend)?;
    if !backend.supports_verified_destroy() {
        anyhow::bail!("backend does not support VerifiedDestroy");
    }
    backend
        .validate_creation_manifest_for_bind(&binding.instance.name, namespace, manifest)
        .await
}

/// Finish the create-capable part of a verified connect-token footprint.
///
/// The lease-side binding and `Prepared` attempt are durable first. This
/// function persists `Creating` and permits exactly one empty-Secret `POST` in
/// the same call. A later reconcile that observes `Creating` only observes the
/// original request; it never retries the `POST`. Once the exact UID is
/// durable, activation is a patch, so terminal release can close the creator,
/// delete that UID, and prove absence without a delayed create repopulating the
/// name.
async fn complete_connect_token_creation(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    binding: &LeaseBinding,
) -> Result<Option<(ClusterLease, LeaseBinding)>, LeaseError> {
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    let Some(mut creation) = status.connect_token_creation.clone() else {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "verified binding has no durable connect-token creation attempt"
        )));
    };
    if status.phase != LeasePhase::Pending
        || status.binding.as_ref() != Some(binding)
        || creation.attempt_id.trim().is_empty()
    {
        return Ok(None);
    }
    let lease_uid = lease_uid_for(lease)?.to_string();
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);

    let (lease, binding, creation) = match creation.phase {
        ConnectTokenCreationPhase::Prepared => {
            if binding.connect_token.is_some() || creation.identity.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Prepared connect-token attempt already carries an identity"
                )));
            }
            let observed_rv = lease
                .resource_version()
                .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
            let prepared_creation = creation.clone();
            creation.phase = ConnectTokenCreationPhase::Creating;
            let patch = json_patch(serde_json::json!([
                { "op": "test", "path": "/metadata/uid", "value": lease_uid },
                { "op": "test", "path": "/metadata/resourceVersion", "value": observed_rv },
                { "op": "test", "path": "/status/phase", "value": "Pending" },
                { "op": "test", "path": "/status/binding", "value": binding },
                { "op": "test", "path": "/status/connectTokenCreation", "value": prepared_creation },
                { "op": "add", "path": "/status/connectTokenCreation", "value": creation }
            ]));
            let dispatched = match leases
                .patch_status(
                    &binding.lease.name,
                    &PatchParams::default(),
                    &Patch::<()>::Json(patch),
                )
                .await
            {
                Ok(dispatched) => dispatched,
                Err(error) if optimistic_conflict(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let dispatched_creation = dispatched
                .status
                .as_ref()
                .and_then(|status| status.connect_token_creation.clone())
                .ok_or_else(|| {
                    LeaseError::Lifecycle(anyhow::anyhow!(
                        "dispatched connect-token attempt disappeared"
                    ))
                })?;
            if dispatched_creation.phase != ConnectTokenCreationPhase::Creating {
                return Ok(None);
            }
            let identity = crate::api::connect::reserve_lease_connect_token(
                client,
                namespace,
                &dispatched,
                &dispatched_creation.attempt_id,
            )
            .await
            .map_err(LeaseError::Lifecycle)?;
            let Some(sealed) = persist_reserved_connect_token(
                client,
                namespace,
                &dispatched,
                binding,
                &dispatched_creation,
                identity,
            )
            .await?
            else {
                return Ok(None);
            };
            sealed
        }
        ConnectTokenCreationPhase::Creating => {
            if binding.connect_token.is_some() || creation.identity.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "Creating connect-token attempt already carries an identity"
                )));
            }
            let Some(identity) = crate::api::connect::observe_reserved_lease_connect_token(
                client,
                namespace,
                lease,
                &creation.attempt_id,
            )
            .await
            .map_err(LeaseError::Lifecycle)?
            else {
                // The original POST may still be in flight. Retrying it would
                // reopen the create name after terminal teardown, so ambiguity
                // is retained and NeverBound remains impossible.
                return Ok(None);
            };
            let Some(sealed) = persist_reserved_connect_token(
                client, namespace, lease, binding, &creation, identity,
            )
            .await?
            else {
                return Ok(None);
            };
            sealed
        }
        ConnectTokenCreationPhase::Reserved | ConnectTokenCreationPhase::Ready => {
            if binding.connect_token.as_ref() != creation.identity.as_ref() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "connect-token binding and creation identities differ"
                )));
            }
            (lease.clone(), binding.clone(), creation)
        }
        ConnectTokenCreationPhase::Closing => {
            close_abandoned_pending_binding(client, namespace, lease, binding).await?;
            return Ok(None);
        }
        ConnectTokenCreationPhase::Closed => {
            // Verified intents are write-once. A candidate lost after token
            // creation therefore remains a closed, auditable handle instead
            // of being erased and replaced with a different capability.
            return Ok(None);
        }
    };

    if creation.phase == ConnectTokenCreationPhase::Ready {
        crate::api::connect::ensure_lease_connect_token(client, namespace, &lease, &binding)
            .await
            .map_err(LeaseError::Lifecycle)?;
        return Ok(Some((lease, binding)));
    }

    crate::api::connect::activate_reserved_lease_connect_token(
        client,
        namespace,
        &binding.lease.name,
        &lease_uid,
        &binding,
        &creation.attempt_id,
    )
    .await
    .map_err(LeaseError::Lifecycle)?;

    let current = leases.get(&binding.lease.name).await?;
    let current_status = current.status.as_ref().cloned().unwrap_or_default();
    let Some(mut current_creation) = current_status.connect_token_creation.clone() else {
        return Ok(None);
    };
    if current.metadata.uid.as_deref() != Some(lease_uid.as_str())
        || current_status.phase != LeasePhase::Pending
        || current_status.binding.as_ref() != Some(&binding)
        || current_creation != creation
    {
        return Ok(None);
    }
    let resource_version = current
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    current_creation.phase = ConnectTokenCreationPhase::Ready;
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "test", "path": "/status/connectTokenCreation", "value": creation },
        { "op": "add", "path": "/status/connectTokenCreation", "value": current_creation }
    ]));
    match leases
        .patch_status(
            &binding.lease.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(ready) => Ok(Some((ready, binding))),
        Err(error) if optimistic_conflict(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn persist_reserved_connect_token(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    binding: &LeaseBinding,
    creation: &ConnectTokenCreation,
    identity: crate::crd::KubernetesResourceIdentity,
) -> Result<Option<(ClusterLease, LeaseBinding, ConnectTokenCreation)>, LeaseError> {
    if creation.phase != ConnectTokenCreationPhase::Creating
        || creation.identity.is_some()
        || binding.connect_token.is_some()
    {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "only an unresolved Creating attempt can persist a token UID"
        )));
    }
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    if status.phase != LeasePhase::Pending
        || status.binding.as_ref() != Some(binding)
        || status.connect_token_creation.as_ref() != Some(creation)
    {
        return Ok(None);
    }
    let lease_uid = lease_uid_for(lease)?;
    let observed_rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let mut sealed_binding = binding.clone();
    sealed_binding.connect_token = Some(identity.clone());
    let mut sealed_creation = creation.clone();
    sealed_creation.phase = ConnectTokenCreationPhase::Reserved;
    sealed_creation.identity = Some(identity);
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": observed_rv },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "test", "path": "/status/connectTokenCreation", "value": creation },
        { "op": "add", "path": "/status/binding", "value": sealed_binding },
        { "op": "add", "path": "/status/connectTokenCreation", "value": sealed_creation }
    ]));
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    match leases
        .patch_status(
            &binding.lease.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(sealed) => Ok(Some((sealed, sealed_binding, sealed_creation))),
        Err(error) if optimistic_conflict(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Reserve a free Ready instance of the lease's pool, or resume the lease's
/// existing reservation intent.
///
/// `slot` is the lease's bind-window position (0 for the head) and limits
/// which free instances it may try (see [`candidates_for_slot`]).
async fn reserve_ready_instance(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    factory: Option<&BackendFactory>,
    slot: usize,
) -> Result<Option<LeaseBinding>, LeaseError> {
    // A resumed intent is already authority-bearing. Revalidate it before the
    // idempotent receipt-fence metadata upgrade so a replaced outer pool can
    // never cause even an unrelated write. The check is deliberately repeated
    // below after that CAS to close the metadata-update race.
    if let Some(binding) = lease
        .status
        .as_ref()
        .and_then(|status| status.binding.as_ref())
        && !sandbox_composition_binding_is_authorized(client, namespace, lease, binding).await?
    {
        warn!(lease = %lease.name_any(), "Cannot upgrade reservation whose pool differs from the outer Sandbox authority");
        return Ok(None);
    }
    let lease = ensure_receipt_retention_finalizer(client, namespace, lease).await?;
    if let Some(binding) = lease
        .status
        .as_ref()
        .and_then(|status| status.binding.clone())
    {
        if !sandbox_composition_binding_is_authorized(client, namespace, &lease, &binding).await? {
            warn!(lease = %lease.name_any(), "Cannot resume reservation whose pool differs from the outer Sandbox authority");
            return Ok(None);
        }
        let instance = Api::<ClusterInstance>::namespaced(client.clone(), namespace)
            .get(&binding.instance.name)
            .await?;
        if validate_binding_eligibility(factory, namespace, &lease, &instance, &binding)
            .await
            .is_err()
        {
            return Ok(None);
        }
        let (lease, binding) = if binding.cleanup_mode.requires_receipt() {
            match complete_connect_token_creation(client, namespace, &lease, &binding).await? {
                Some(ready) => ready,
                None => return Ok(None),
            }
        } else {
            (lease.clone(), binding)
        };
        return match reserve_binding_instance(client, namespace, &binding).await? {
            ReservationOutcome::Reserved => Ok(Some(binding)),
            ReservationOutcome::Occupied => {
                clear_lease_binding_intent(client, namespace, lease_uid_for(&lease)?, &binding)
                    .await?;
                Ok(None)
            }
            ReservationOutcome::Retry => Ok(None),
        };
    }

    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/pool={}", lease.spec.pool_ref));
    let instances = instances_api.list(&lp).await?;
    let ready: Vec<ClusterInstance> = instances
        .into_iter()
        .filter(instance_is_free_capacity)
        .collect();

    if ready.is_empty() {
        return Ok(None);
    }

    let lease_uid = lease
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("lease missing UID"))?;
    let lease_rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let pools_api: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let pool = pools_api.get(&lease.spec.pool_ref).await?;
    let current_hash = pool_spec_hash_for_bind(client, namespace, &pool, factory).await;
    let ready = candidates_for_slot(order_bind_candidates(ready, &current_hash), slot);

    for instance in ready {
        let mut binding = match binding_from_observation(&lease, &instance, &pool) {
            Ok(binding) => binding,
            Err(reason) => {
                warn!(
                    lease = %lease.name_any(),
                    instance = %instance.name_any(),
                    reason,
                    "Skipping Ready instance without provable UID/backend provenance"
                );
                continue;
            }
        };
        if let Err(error) =
            validate_binding_eligibility(factory, namespace, &lease, &instance, &binding).await
        {
            warn!(lease = %lease.name_any(), instance = %instance.name_any(), error = %error, "Skipping instance that cannot satisfy immutable cleanup provenance");
            continue;
        }
        if !sandbox_composition_binding_is_authorized(client, namespace, &lease, &binding).await? {
            warn!(lease = %lease.name_any(), "Refusing binding intent whose pool differs from the outer Sandbox authority");
            return Ok(None);
        }
        let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
        let token_creation =
            binding
                .cleanup_mode
                .requires_receipt()
                .then(|| ConnectTokenCreation {
                    attempt_id: uuid::Uuid::new_v4().to_string(),
                    phase: ConnectTokenCreationPhase::Prepared,
                    identity: None,
                    verified_absent_at: None,
                });
        let mut operations = vec![
            serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid }),
            serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv }),
            serde_json::json!({ "op": "test", "path": "/status/phase", "value": "Pending" }),
            serde_json::json!({ "op": "add", "path": "/status/binding", "value": binding }),
        ];
        if let Some(token_creation) = token_creation {
            operations.push(serde_json::json!({
                "op": "add",
                "path": "/status/connectTokenCreation",
                "value": token_creation
            }));
        }
        let intent_patch = json_patch(serde_json::Value::Array(operations));
        let intent_lease = match leases_api
            .patch_status(
                &lease.name_any(),
                &PatchParams::default(),
                &Patch::<()>::Json(intent_patch),
            )
            .await
        {
            Ok(intent) => intent,
            Err(err) if optimistic_conflict(&err) => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        if binding.cleanup_mode.requires_receipt() {
            let Some((_, completed)) =
                complete_connect_token_creation(client, namespace, &intent_lease, &binding).await?
            else {
                return Ok(None);
            };
            binding = completed;
        }

        match reserve_binding_instance(client, namespace, &binding).await? {
            ReservationOutcome::Reserved => return Ok(Some(binding)),
            ReservationOutcome::Occupied => {
                // Only a fresh read proving the target replaced or owned by a
                // foreign binding permits this exact intent to be cleared.
                // An exact adoption always proceeds to finalization and, if
                // release won, through its teardown receipt.
                clear_lease_binding_intent(client, namespace, lease_uid, &binding).await?;
                return Ok(None);
            }
            ReservationOutcome::Retry => return Ok(None),
        }
    }

    Ok(None)
}

/// The free instances the lease at bind-window `slot` may try, from the
/// already-ordered free list (current template first; see
/// [`order_bind_candidates`]).
///
/// The head (slot 0) tries every instance. Any other slot tries only the
/// instance at its own index, and none if the list is shorter than its slot
/// (the window was sized from a store that has since moved on). Concurrent
/// leases stay off each other's instance, and a lower-priority lease never
/// takes the instance the head tries first.
///
/// This does not fully preserve priority. If the head cannot accept instance
/// 0 (its cleanup mode or provenance does not match) but could accept the
/// instance slot 1 just took, the head waits for the next free instance or
/// its queue timeout. Ruling that out would mean checking every
/// higher-priority lease's eligibility before each reservation.
fn candidates_for_slot<T>(candidates: Vec<T>, slot: usize) -> Vec<T> {
    if slot == 0 {
        return candidates;
    }
    candidates.into_iter().nth(slot).into_iter().collect()
}

/// Order free Ready instances so a new lease prefers the current template.
///
/// Current-spec members (the stamped-hash check drift recycle uses) come
/// first. Within each group, oldest `stateSince` first so stale members
/// that do get bound leave through ordinary use sooner, and current
/// members rotate FIFO. Name is the last tie-break so the slot window
/// stays deterministic.
fn order_bind_candidates(
    mut ready: Vec<ClusterInstance>,
    current_hash: &str,
) -> Vec<ClusterInstance> {
    ready.sort_by(|a, b| {
        let a_current = spec_hash_is_current(
            a.status
                .as_ref()
                .and_then(|status| status.spec_hash.as_deref()),
            current_hash,
        );
        let b_current = spec_hash_is_current(
            b.status
                .as_ref()
                .and_then(|status| status.spec_hash.as_deref()),
            current_hash,
        );
        b_current
            .cmp(&a_current)
            .then_with(|| match (bind_state_since(a), bind_state_since(b)) {
                (Some(a_since), Some(b_since)) => a_since.cmp(&b_since),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.name_any().cmp(&b.name_any()))
    });
    ready
}

fn bind_state_since(instance: &ClusterInstance) -> Option<chrono::DateTime<chrono::Utc>> {
    instance
        .status
        .as_ref()
        .and_then(|status| status.state_since.as_deref())
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// The pool spec hash stamped on new members, computed the same way the
/// pool controller does: resolved bootstrap content, operator render
/// context, backend fingerprint when the factory can name one.
async fn pool_spec_hash_for_bind(
    client: &Client,
    namespace: &str,
    pool: &ClusterPool,
    factory: Option<&BackendFactory>,
) -> crate::pool::SpecHash {
    let bootstrap_specs = resolve_bootstrap_specs(client, namespace, pool).await;
    let fingerprint = factory
        .and_then(|factory| factory.backend_for(pool).ok())
        .and_then(|backend| backend.render_fingerprint(&pool.spec.cluster));
    profile_spec_hash(
        pool,
        &RenderContext::from_env(),
        &bootstrap_specs,
        fingerprint.as_deref(),
    )
}

fn lease_uid_for(lease: &ClusterLease) -> Result<&str, LeaseError> {
    lease
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| LeaseError::Lifecycle(anyhow::anyhow!("lease missing UID")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationOutcome {
    Reserved,
    Occupied,
    Retry,
}

fn instance_carries_compatible_reservation(
    instance: &ClusterInstance,
    status: &crate::crd::ClusterInstanceStatus,
    binding: &LeaseBinding,
) -> bool {
    instance.name_any() == binding.instance.name
        && instance.metadata.uid.as_deref() == Some(binding.instance.uid.as_str())
        && (status.binding.as_ref() == Some(binding)
            || status.lease_ref.as_ref().is_some_and(|reference| {
                reference.name == binding.lease.name
                    && (reference.uid.is_none() || reference.uid == binding.lease.uid)
            }))
}

/// Reserve the exact instance named by an already-persisted lease intent.
///
/// An optimistic conflict is re-read before classification. Another replica
/// may have installed this same binding, in which case clearing the lease-side
/// intent would strand an adopted instance and manufacture a false NeverBound
/// proof. Only a fresh read of the same name proving a foreign or already-held
/// object returns [`ReservationOutcome::Occupied`]; absence remains retryable.
async fn reserve_binding_instance(
    client: &Client,
    namespace: &str,
    binding: &LeaseBinding,
) -> Result<ReservationOutcome, LeaseError> {
    // Close the stale-reconcile window at the last boundary before an instance
    // status mutation. A token creator or allocator that read Pending before a
    // concurrent release cannot reserve after that release has moved the lease
    // or its creation state to Closing.
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = match leases.get(&binding.lease.name).await {
        Ok(lease) => lease,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Ok(ReservationOutcome::Retry);
        }
        Err(error) => return Err(error.into()),
    };
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    let token_ready = !binding.cleanup_mode.requires_receipt()
        || status
            .connect_token_creation
            .as_ref()
            .is_some_and(|creation| {
                creation.phase == ConnectTokenCreationPhase::Ready
                    && creation.identity.as_ref() == binding.connect_token.as_ref()
            });
    if lease.metadata.uid.as_deref() != binding.lease.uid.as_deref()
        || lease.metadata.deletion_timestamp.is_some()
        || status.phase != LeasePhase::Pending
        || status.binding.as_ref() != Some(binding)
        || !token_ready
    {
        // A terminal transition or exact adopted intent is not evidence that
        // another subject occupied the instance. Preserve the lease-side
        // handle; the terminal controller will adopt it into teardown.
        return Ok(ReservationOutcome::Retry);
    }
    reserve_binding_instance_after_lease_fence(client, namespace, binding).await
}

/// Reserve an instance after the caller has closed or validated the exact
/// lease-side creator fence. The ordinary bind path must use
/// [`reserve_binding_instance`]; terminal close uses this only to force an
/// already-selected free instance into the teardown path, eliminating the
/// `NeverBound` versus stale-reserve ambiguity.
async fn reserve_binding_instance_after_lease_fence(
    client: &Client,
    namespace: &str,
    binding: &LeaseBinding,
) -> Result<ReservationOutcome, LeaseError> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instance = match instances_api.get(&binding.instance.name).await {
        Ok(instance) => instance,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            return Ok(ReservationOutcome::Retry);
        }
        Err(err) => return Err(err.into()),
    };
    let status = instance.status.clone().unwrap_or_default();
    if !instance_matches_binding_subject(&instance, binding) {
        return Ok(
            if instance_carries_compatible_reservation(&instance, &status, binding) {
                // Preserve the exact adopted pair even when another provenance
                // field became inconsistent. Clearing the intent would manufacture
                // NeverBound; a later lifecycle pass must repair or quarantine it.
                ReservationOutcome::Retry
            } else {
                ReservationOutcome::Occupied
            },
        );
    }
    let lease_ref_exact = status.lease_ref.as_ref().is_some_and(|reference| {
        reference.name == binding.lease.name && reference.uid == binding.lease.uid
    });
    if status.phase == ClusterInstancePhase::Leased
        && status.binding.as_ref() == Some(binding)
        && lease_ref_exact
    {
        return Ok(ReservationOutcome::Reserved);
    }
    if status.binding.as_ref() == Some(binding)
        && (status.phase == ClusterInstancePhase::Leased
            || (status.phase == ClusterInstancePhase::Ready
                && status.lease_ref.as_ref().is_none_or(|reference| {
                    reference.name == binding.lease.name && reference.uid == binding.lease.uid
                })))
    {
        // The reciprocal binding is the authority. A stale full-status writer
        // may have dropped/reverted the display leaseRef or even the phase
        // after adoption; repair those projections instead of clearing the
        // lease-side intent and stranding capacity outside the verified
        // teardown path. Other phases (notably Recycling/Quarantined) remain a
        // retry so reservation can never roll teardown back to Leased.
        let uid = instance
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("instance missing UID"))?;
        let rv = instance
            .resource_version()
            .ok_or_else(|| anyhow::anyhow!("instance missing resourceVersion"))?;
        let patch = json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
            { "op": "test", "path": "/status/phase", "value": status.phase },
            { "op": "test", "path": "/status/binding", "value": binding },
            { "op": "add", "path": "/status/phase", "value": "Leased" },
            { "op": "add", "path": "/status/leaseRef", "value": binding.lease }
        ]));
        return match instances_api
            .patch_status(
                &binding.instance.name,
                &PatchParams::default(),
                &Patch::<()>::Json(patch),
            )
            .await
        {
            Ok(_) => Ok(ReservationOutcome::Reserved),
            Err(error) if optimistic_conflict(&error) => Ok(ReservationOutcome::Retry),
            Err(error) => Err(error.into()),
        };
    }
    if status.binding.as_ref() == Some(binding) {
        // Recycling/Quarantined (or any future non-reservable phase) is still
        // an exact adopted handle. Preserve the lease intent so lifecycle can
        // consume its receipt; never classify the same binding as occupied by
        // somebody else.
        return Ok(ReservationOutcome::Retry);
    }

    let is_free = status.phase == ClusterInstancePhase::Ready
        && status.binding.is_none()
        && status.lease_ref.is_none();
    let is_provable_existing_pair = status.binding.is_none()
        && status.lease_ref.as_ref().is_some_and(|reference| {
            reference.name == binding.lease.name
                && (reference.uid == binding.lease.uid
                    || (status.phase == ClusterInstancePhase::Leased && reference.uid.is_none()))
        })
        && (status.phase == ClusterInstancePhase::Leased
            || status.phase == ClusterInstancePhase::Ready);
    if !is_free && !is_provable_existing_pair {
        return Ok(if status.binding.is_some() || status.lease_ref.is_some() {
            ReservationOutcome::Occupied
        } else {
            ReservationOutcome::Retry
        });
    }

    let uid = instance
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("instance missing UID"))?;
    let rv = instance
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("instance missing resourceVersion"))?;
    let expected_phase = if is_free {
        ClusterInstancePhase::Ready
    } else {
        status.phase.clone()
    };
    let expected_lease_ref = if is_free {
        serde_json::Value::Null
    } else {
        serde_json::json!(status.lease_ref.as_ref())
    };
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": expected_phase },
        { "op": "test", "path": "/status/leaseRef", "value": expected_lease_ref },
        { "op": "add", "path": "/status/phase", "value": "Leased" },
        { "op": "add", "path": "/status/leaseRef", "value": binding.lease },
        { "op": "add", "path": "/status/binding", "value": binding },
        { "op": "add", "path": "/status/idleSince", "value": null },
        { "op": "add", "path": "/status/stateSince", "value": chrono::Utc::now().to_rfc3339() }
    ]));
    match instances_api
        .patch_status(
            &binding.instance.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(ReservationOutcome::Reserved),
        Err(err) if optimistic_conflict(&err) => {
            let current = match instances_api.get(&binding.instance.name).await {
                Ok(current) => current,
                Err(kube::Error::Api(response)) if response.code == 404 => {
                    return Ok(ReservationOutcome::Retry);
                }
                Err(error) => return Err(error.into()),
            };
            let status = current.status.as_ref().cloned().unwrap_or_default();
            if !instance_matches_binding_subject(&current, binding) {
                return Ok(
                    if instance_carries_compatible_reservation(&current, &status, binding) {
                        ReservationOutcome::Retry
                    } else {
                        ReservationOutcome::Occupied
                    },
                );
            }
            let lease_ref_exact = status.lease_ref.as_ref().is_some_and(|reference| {
                reference.name == binding.lease.name && reference.uid == binding.lease.uid
            });
            if status.phase == ClusterInstancePhase::Leased
                && status.binding.as_ref() == Some(binding)
                && lease_ref_exact
            {
                Ok(ReservationOutcome::Reserved)
            } else if status.binding.as_ref() == Some(binding) {
                // Preserve every exact adopted pair. A fresh pass either
                // repairs a stale Ready/leaseRef projection or observes the
                // teardown/quarantine phase without ever clearing intent.
                Ok(ReservationOutcome::Retry)
            } else if status.phase == ClusterInstancePhase::Ready
                && status.binding.is_none()
                && status.lease_ref.is_none()
            {
                Ok(ReservationOutcome::Retry)
            } else if status
                .binding
                .as_ref()
                .is_some_and(|current| current != binding)
                || status.lease_ref.as_ref().is_some_and(|reference| {
                    reference.name != binding.lease.name
                        || (reference.uid.is_some() && reference.uid != binding.lease.uid)
                })
            {
                Ok(ReservationOutcome::Occupied)
            } else {
                Ok(ReservationOutcome::Retry)
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// Close a connect-token attempt whose exact instance reservation lost.
///
/// `Closing` is persisted before deleting the exact Secret UID. A crash after
/// deletion therefore resumes deletion/absence observation instead of trying
/// to activate or recreate the credential. Verified binding intent is retained
/// with the Closed attempt: it is an immutable audit handle, not a slot that
/// may be silently rewritten to a different candidate.
async fn close_abandoned_pending_binding(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    binding: &LeaseBinding,
) -> Result<(), LeaseError> {
    let status = lease.status.as_ref().cloned().unwrap_or_default();
    let creation = status.connect_token_creation.as_ref().ok_or_else(|| {
        LeaseError::Lifecycle(anyhow::anyhow!(
            "verified binding rollback has no token creation checkpoint"
        ))
    })?;
    let identity = creation.identity.as_ref().ok_or_else(|| {
        LeaseError::Lifecycle(anyhow::anyhow!(
            "verified binding rollback has no exact token identity"
        ))
    })?;
    if status.phase != LeasePhase::Pending
        || status.binding.as_ref() != Some(binding)
        || binding.connect_token.as_ref() != Some(identity)
    {
        return Ok(());
    }
    let uid = lease_uid_for(lease)?;
    let resource_version = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);

    if matches!(
        creation.phase,
        ConnectTokenCreationPhase::Reserved | ConnectTokenCreationPhase::Ready
    ) {
        let mut closing = creation.clone();
        closing.phase = ConnectTokenCreationPhase::Closing;
        let patch = json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            { "op": "test", "path": "/status/phase", "value": "Pending" },
            { "op": "test", "path": "/status/binding", "value": binding },
            { "op": "test", "path": "/status/connectTokenCreation", "value": creation },
            { "op": "add", "path": "/status/connectTokenCreation", "value": closing }
        ]));
        return match leases
            .patch_status(
                &binding.lease.name,
                &PatchParams::default(),
                &Patch::<()>::Json(patch),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if optimistic_conflict(&error) => Ok(()),
            Err(error) => Err(error.into()),
        };
    }
    if creation.phase != ConnectTokenCreationPhase::Closing {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "verified binding rollback did not enter Closing"
        )));
    }

    let check = crate::api::connect::delete_lease_connect_token_verified(
        client,
        namespace,
        &binding.lease.name,
        uid,
        identity,
    )
    .await;
    if check.result != crate::crd::CheckResult::Verified {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "cannot clear a verified binding while its token footprint is unproven"
        )));
    }
    let mut closed = creation.clone();
    closed.phase = ConnectTokenCreationPhase::Closed;
    closed.verified_absent_at = Some(chrono::Utc::now().to_rfc3339());
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "test", "path": "/status/connectTokenCreation", "value": creation },
        { "op": "add", "path": "/status/connectTokenCreation", "value": closed }
    ]));
    match leases
        .patch_status(
            &binding.lease.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn clear_lease_binding_intent(
    client: &Client,
    namespace: &str,
    lease_uid: &str,
    binding: &LeaseBinding,
) -> Result<(), LeaseError> {
    let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = match leases_api.get(&binding.lease.name).await {
        Ok(lease) => lease,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if lease.metadata.uid.as_deref() != Some(lease_uid)
        || lease.status.as_ref().and_then(|s| s.binding.as_ref()) != Some(binding)
        || lease.status.as_ref().map(|s| &s.phase) != Some(&LeasePhase::Pending)
    {
        return Ok(());
    }
    let rv = lease
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
    if binding.cleanup_mode.requires_receipt() {
        return close_abandoned_pending_binding(client, namespace, &lease, binding).await;
    }
    let operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": lease_uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": rv }),
        serde_json::json!({ "op": "test", "path": "/status/phase", "value": "Pending" }),
        serde_json::json!({ "op": "test", "path": "/status/binding", "value": binding }),
        serde_json::json!({ "op": "remove", "path": "/status/binding" }),
    ];
    let patch = json_patch(serde_json::Value::Array(operations));
    match leases_api
        .patch_status(
            &binding.lease.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(err) if optimistic_conflict(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

// NOTE: the lease-side `rollback_instance_reservation` that `main` called on a
// failed bind patch is deliberately gone. Under the two-sided reservation the
// instance record is durable, so an uncertain bind response must NOT roll back
// (see `finalize_binding` — a replay finishes the same exact pair). Reclaiming
// a reservation whose lease never materialized now belongs to the instance
// controller's `LeaseNotFound` arm, which is grace-gated and UID-fenced and
// still fires if this controller dies mid-bind.

async fn mark_instance_recycling(
    client: &Client,
    namespace: &str,
    binding: &LeaseBinding,
) -> Result<bool, LeaseError> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instance = match instances_api.get(&binding.instance.name).await {
        Ok(instance) => instance,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let status = instance.status.clone().unwrap_or_default();
    // The generation equality holds only while the instance is live: the
    // apiserver bumps `metadata.generation` when it stamps `deletionTimestamp`
    // on a finalizer-bearing object, so an instance whose delete is already in
    // flight reads one generation ahead of the binding and would be judged
    // "not safe to recycle" forever. Identity is still pinned by the UID,
    // reciprocal-binding, and lease-reference checks around it.
    let generation_matches = instance.metadata.deletion_timestamp.is_some()
        || instance.metadata.generation == Some(binding.instance.observed_generation);
    if instance.metadata.uid.as_deref() != Some(binding.instance.uid.as_str())
        || !generation_matches
        || status.binding.as_ref() != Some(binding)
        || status.lease_ref.as_ref().is_none_or(|reference| {
            reference.name != binding.lease.name || reference.uid != binding.lease.uid
        })
    {
        return Ok(false);
    }
    if status.phase == ClusterInstancePhase::Recycling {
        return Ok(true);
    }
    // An exact reciprocal binding is still an adopted allocation if a stale
    // profile write reverted only its phase to Ready. Release must route that
    // instance through receipt-backed recycling; refusing the transition here
    // would strand the binding precisely after the allocation gate closes.
    if status.phase != ClusterInstancePhase::Leased && status.phase != ClusterInstancePhase::Ready {
        return Ok(false);
    }
    let previous_phase = status.phase.clone();
    let rv = instance
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("instance missing resourceVersion"))?;
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": binding.instance.uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": previous_phase },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "add", "path": "/status/phase", "value": "Recycling" },
        { "op": "add", "path": "/status/idleSince", "value": null },
        { "op": "add", "path": "/status/stateSince", "value": chrono::Utc::now().to_rfc3339() }
    ]));
    match instances_api
        .patch_status(
            &binding.instance.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(err) if optimistic_conflict(&err) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn binding_from_observation(
    lease: &ClusterLease,
    instance: &ClusterInstance,
    pool: &ClusterPool,
) -> Result<LeaseBinding, &'static str> {
    let lease_uid = lease.metadata.uid.clone().ok_or("lease_uid_missing")?;
    let pool_uid = pool.metadata.uid.clone().ok_or("pool_uid_missing")?;
    if pool.name_any() != lease.spec.pool_ref || pool.metadata.deletion_timestamp.is_some() {
        return Err("pool_identity_mismatch");
    }
    let instance_uid = instance
        .metadata
        .uid
        .clone()
        .ok_or("instance_uid_missing")?;
    let instance_generation = instance
        .metadata
        .generation
        .filter(|generation| *generation > 0)
        .ok_or("instance_generation_missing")?;
    let instance_status = instance.status.as_ref().ok_or("instance_status_missing")?;
    let spec_digest = instance_status
        .spec_hash
        .clone()
        .ok_or("instance_spec_digest_missing")?;
    let created_with = instance_status
        .created_with
        .as_ref()
        .ok_or("instance_provenance_missing")?;
    let backend = created_with
        .backend
        .clone()
        .ok_or("backend_provenance_missing")?;
    let current_backend =
        BackendProvenance::from_config(&pool.spec.backend).map_err(|_| "backend_digest_failed")?;
    if backend != current_backend
        || created_with.pool_uid.as_deref() != Some(pool_uid.as_str())
        || created_with.backend_type.as_ref() != Some(&backend.backend_type)
    {
        return Err("backend_provenance_mismatch");
    }
    if !instance.spec.pool_ref.as_ref().is_some_and(|reference| {
        reference.name == pool.name_any() && reference.uid.as_deref() == Some(pool_uid.as_str())
    }) {
        return Err("pool_reference_mismatch");
    }
    if !instance
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.iter().any(|owner| {
                owner.api_version == "kobe.kunobi.ninja/v1alpha1"
                    && owner.kind == "ClusterPool"
                    && owner.name == pool.name_any()
                    && owner.uid == pool_uid
            })
        })
    {
        return Err("pool_owner_mismatch");
    }

    let cleanup_mode = lease.spec.cleanup_mode.unwrap_or_default();
    let creation_manifest = match instance_status.creation_manifest.as_ref() {
        Some(manifest)
            if manifest.validate().is_ok()
                && manifest.instance.name == instance.name_any()
                && manifest.instance.uid.as_deref() == Some(instance_uid.as_str())
                && manifest.namespace == instance.namespace().unwrap_or_default()
                && manifest.backend_type == backend.backend_type
                && manifest.config_digest == backend.config_digest =>
        {
            Some(manifest.clone())
        }
        Some(_) if cleanup_mode.requires_receipt() => return Err("creation_manifest_invalid"),
        None if cleanup_mode.requires_receipt() => return Err("creation_manifest_missing"),
        _ => None,
    };
    let creation_manifest_digest = creation_manifest
        .as_ref()
        .and_then(|manifest| manifest.digest().ok());
    if cleanup_mode.requires_receipt() && creation_manifest_digest.is_none() {
        return Err("creation_manifest_digest_failed");
    }

    Ok(LeaseBinding {
        binding_id: uuid::Uuid::new_v4().to_string(),
        lease: ResourceRef {
            name: lease.name_any(),
            uid: Some(lease_uid),
        },
        instance: BoundInstanceRef {
            name: instance.name_any(),
            uid: instance_uid,
            observed_generation: instance_generation,
        },
        pool: ResourceRef {
            name: pool.name_any(),
            uid: Some(pool_uid),
        },
        backend,
        instance_spec_digest: spec_digest,
        cleanup_mode,
        creation_manifest_digest,
        creation_manifest,
        connect_token: None,
    })
}

fn instance_matches_binding_subject(instance: &ClusterInstance, binding: &LeaseBinding) -> bool {
    let status = instance.status.as_ref();
    instance.name_any() == binding.instance.name
        && instance.metadata.uid.as_deref() == Some(binding.instance.uid.as_str())
        && instance.metadata.generation == Some(binding.instance.observed_generation)
        && instance.spec.pool_ref.as_ref().is_some_and(|reference| {
            reference.name == binding.pool.name && reference.uid == binding.pool.uid
        })
        && status.and_then(|s| s.spec_hash.as_deref())
            == Some(binding.instance_spec_digest.as_str())
        && status
            .and_then(|s| s.created_with.as_ref())
            .is_some_and(|created| {
                created.pool_uid == binding.pool.uid
                    && created.backend.as_ref() == Some(&binding.backend)
                    && created.backend_type.as_ref() == Some(&binding.backend.backend_type)
            })
}

/// True when an API error means "someone else wrote first", not "this request
/// was wrong".
///
/// Every fenced write in this repo is a JSON Patch whose leading `test` ops
/// assert the uid and resourceVersion we read. The apiserver reports the two
/// ways that fence can lose differently:
///
///   - **409 Conflict** — a failed `Preconditions` check (fenced delete/replace).
///     Unambiguous: 409 only ever means a concurrent modification.
///   - **422 Invalid** — a failed `test` op. Shares its status code with genuine
///     request validation, which is why the code alone is not enough.
///
/// A 422 is only treated as a lost race when it carries **no field-level
/// causes**. A failed `test` op yields the generic "the server rejected our
/// request due to an error in our request" with `details.causes` empty; a real
/// validation failure (schema violation, bad field) populates `causes` with the
/// offending paths. Blanket-matching 422 would swallow that second class
/// entirely and requeue forever against a request that can never succeed —
/// the same silent-infinite-retry shape as #150. So when in doubt, this returns
/// false and the error stays loud.
pub(crate) fn optimistic_conflict(err: &kube::Error) -> bool {
    let kube::Error::Api(response) = err else {
        return false;
    };
    match response.code {
        409 => true,
        422 => response
            .details
            .as_ref()
            .is_none_or(|details| details.causes.is_empty()),
        _ => false,
    }
}

pub(crate) fn json_patch(value: serde_json::Value) -> json_patch::Patch {
    serde_json::from_value(value).expect("controller JSON Patch must be well formed")
}

/// Background reaper that force-expires overdue Bound leases.
async fn run_reaper<B: ClusterBackend>(
    ctx: Arc<LeaseContext<B>>,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.cancelled() => {
                info!("Reaper shutting down");
                return;
            },
        }

        let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), namespace);
        let leases = match leases_api.list(&ListParams::default()).await {
            Ok(list) => list,
            Err(e) => {
                error!("Reaper: failed to list leases: {e}");
                continue;
            }
        };

        let now = chrono::Utc::now();

        // Reconcile the in-memory queues against what the apiserver
        // actually holds. This is the only place a lease deleted outside
        // a reconcile can be evicted — see `prune_queues_against_live`
        // for why the reconcile path cannot do it — and a stranded entry
        // head-blocks its whole pool, so it is worth the one pass over an
        // already-fetched list.
        {
            let live_pending: std::collections::HashSet<String> = leases
                .iter()
                .filter(|l| {
                    l.status
                        .as_ref()
                        .map(|s| s.phase == LeasePhase::Pending)
                        .unwrap_or(true)
                })
                .map(|l| l.name_any())
                .collect();

            let (evicted, pools) = {
                let mut queues = ctx.queues.write().await;
                let evicted = prune_queues_against_live(&mut queues, &live_pending);
                (evicted, queues.keys().cloned().collect::<Vec<_>>())
            };
            if !evicted.is_empty() {
                warn!(
                    leases = ?evicted,
                    "Reaper: evicted queue entries with no live Pending lease (would otherwise head-block the pool)"
                );
                // Evictions shift the window; wake it rather than leave the
                // new front to its backstop.
                for pool in pools {
                    ctx.wake_window(&pool).await;
                }
            }
        }

        for lease in leases {
            let name = lease.name_any();
            let status = lease.status.clone().unwrap_or_default();

            if status.phase != LeasePhase::Bound {
                continue;
            }

            if let Some(expires_at_str) = &status.expires_at {
                match chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                    Ok(expires_at) => {
                        if now > expires_at.with_timezone(&chrono::Utc) {
                            warn!(lease = %name, "Reaper: force-expiring overdue lease");
                            if let Err(e) = expire_lease_fenced(&leases_api, &lease).await {
                                error!(
                                    lease = %name,
                                    "Reaper: failed to force-expire overdue lease: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            lease = %name,
                            expires_at = %expires_at_str,
                            "Reaper: failed to parse expires_at, force-expiring lease: {e}"
                        );
                        if let Err(e) = expire_lease_fenced(&leases_api, &lease).await {
                            error!(
                                lease = %name,
                                "Reaper: failed to expire lease with corrupt timestamp: {e}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Remove `lease_name` from `profile`'s queue, returning the position it held.
async fn remove_from_queue(
    queues: &RwLock<HashMap<String, Vec<PendingLease>>>,
    profile: &str,
    lease_name: &str,
) -> Option<usize> {
    let mut queues = queues.write().await;
    let queue = queues.get_mut(profile)?;
    let position = queue.iter().position(|p| p.lease_name == lease_name)?;
    queue.remove(position);
    Some(position)
}

/// Drop queue entries whose lease is no longer `Pending` on the
/// apiserver, returning the names evicted.
///
/// This is the backstop for [`lease_deletion_evictions`], which evicts
/// deletes as they happen but cannot see one that landed while its watch
/// was relisting. The reconcile path cannot do either: kube-runtime's
/// `Controller` is driven by `applied_objects()`, which drops Deleted
/// events, and every scheduled requeue resolves through the reflector
/// store first — so once a deleted lease leaves the store, **no reconcile
/// ever runs for it**. The 404 branch in `reconcile_lease` only catches
/// the narrow race where a delete lands mid-reconcile.
///
/// That matters because a stranded entry is not a leak but a deadlock:
/// the queue is sorted oldest-first within a priority, so the ghost sits
/// at the head and every later lease for that pool sees `is_head ==
/// false` and never binds.
///
/// Sweeping from a LIST is safe against the obvious race — a lease
/// created after the LIST could be pruned here, but the queue insert in
/// `reconcile_lease` is idempotent, so it re-inserts itself on its next
/// pass (at the latest, its Pending backstop). A transient drop self-heals; a
/// permanent ghost does not.
fn prune_queues_against_live(
    queues: &mut HashMap<String, Vec<PendingLease>>,
    live_pending: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut evicted = Vec::new();
    for queue in queues.values_mut() {
        queue.retain(|p| {
            let keep = live_pending.contains(&p.lease_name);
            if !keep {
                evicted.push(p.lease_name.clone());
            }
            keep
        });
    }
    evicted
}

async fn expire_lease_fenced(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
) -> Result<ClusterLease, kube::Error> {
    let uid =
        lease.metadata.uid.as_deref().ok_or_else(|| {
            kube::Error::Service(Box::new(std::io::Error::other("lease has no UID")))
        })?;
    let rv = lease.resource_version().ok_or_else(|| {
        kube::Error::Service(Box::new(std::io::Error::other(
            "lease has no resourceVersion",
        )))
    })?;
    let mut status = lease.status.clone().unwrap_or_default();
    let observed_phase = status.phase.clone();
    status.phase = LeasePhase::Expired;
    status.conditions = derive_lease_conditions(
        &status,
        lease
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or(&[]),
        None,
        &chrono::Utc::now().to_rfc3339(),
    );
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": observed_phase },
        { "op": "add", "path": "/status", "value": status }
    ]));
    leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await
}

fn try_start_reconcile<'a, B: ClusterBackend>(
    ctx: &'a LeaseContext<B>,
    lease_name: &str,
) -> Result<Option<ActiveLeaseReconcileGuard<'a>>, LeaseError> {
    let mut active_reconciles = ctx.active_reconciles.lock().map_err(|err| {
        LeaseError::Lifecycle(anyhow::anyhow!("lease reconcile guard poisoned: {err}"))
    })?;

    if !active_reconciles.insert(lease_name.to_string()) {
        return Ok(None);
    }
    drop(active_reconciles);

    Ok(Some(ActiveLeaseReconcileGuard {
        active_reconciles: &ctx.active_reconciles,
        lease_name: lease_name.to_string(),
    }))
}

/// Derive the standard condition set for a `ClusterLease` from its status.
/// PURE: no I/O, no clock — `now` is passed in so callers control the
/// timestamp and tests are deterministic. Mirrors
/// `controllers::instance::derive_instance_conditions`.
///
/// Emits two conditions:
/// - `Bound`: `True` iff `phase == Bound` (a cluster is assigned). Reason is
///   always the phase, so `False` names what's blocking (Pending/Expired/…).
/// - `Satisfiable`: `False` only on the no-Ready-cluster path (signalled by
///   `unsatisfiable_reason = Some(reason)`), carrying that reason; otherwise
///   `True` with the phase as reason. A `Warming` reason still counts as
///   "not yet satisfiable" — it explains *why* the Pending lease has no
///   cluster — so it is reported `False`.
///
/// `lastTransitionTime` follows core/v1 semantics: for each derived condition
/// we look up the matching `condition_type` in `prev`; if found AND its
/// `status` is unchanged we keep the previous timestamp, otherwise we stamp
/// `now`. So the time only moves when the condition actually flips (or is
/// brand new), never on a redundant reconcile.
pub fn derive_lease_conditions(
    status: &ClusterLeaseStatus,
    prev: &[ClusterLeaseCondition],
    unsatisfiable_reason: Option<crate::metrics::LeaseUnsatisfiableReason>,
    now: &str,
) -> Vec<ClusterLeaseCondition> {
    let message = status.message.clone().unwrap_or_default();
    let phase = status.phase.to_string();

    // Helper: build one condition, preserving lastTransitionTime when the
    // status is unchanged vs. `prev`.
    let build = |condition_type: &str, new_status: &str, reason: String, message: String| {
        let last_transition_time = prev
            .iter()
            .find(|c| c.condition_type == condition_type)
            .filter(|c| c.status == new_status)
            .and_then(|c| c.last_transition_time.clone())
            .or_else(|| Some(now.to_string()));
        ClusterLeaseCondition {
            condition_type: condition_type.to_string(),
            status: new_status.to_string(),
            reason,
            message,
            last_transition_time,
        }
    };

    let is_bound = status.phase == LeasePhase::Bound;
    let bool_status = |b: bool| if b { "True" } else { "False" };

    // Satisfiable is False (with the unsatisfiable reason) only on the
    // no-Ready-cluster path; otherwise it's True with the phase as reason.
    let (satisfiable_status, satisfiable_reason) = match unsatisfiable_reason {
        // PascalCase for the condition reason (K8s convention; consistent with
        // the PascalCase `Bound` reason). `as_str()` stays snake_case for the
        // metric label.
        Some(reason) => ("False", reason.condition_reason().to_string()),
        None => ("True", phase.clone()),
    };

    vec![
        build(
            "Bound",
            bool_status(is_bound),
            // Reason is always the phase: for Bound=True it's `Bound`, for
            // Bound=False it names what's blocking (Pending/Expired/…).
            phase,
            message.clone(),
        ),
        build(
            "Satisfiable",
            satisfiable_status,
            satisfiable_reason,
            message,
        ),
    ]
}

/// Whether this reconcile is entering a new unsatisfiable state.
///
/// A steady `Satisfiable=False` condition with the same typed reason is not a
/// new demand event. This keeps `kobe_lease_unsatisfiable_total` independent of
/// controller requeue frequency while still counting reason transitions.
///
/// Moving between two transient reasons (`Warming`, `AtCapacity`) is not a new
/// event either: a pool at its ceiling reports `Exhausted`, then `ScalingUp`
/// while a recycled slot is recreated, then `Exhausted` again, and each of
/// those flips would otherwise count the same waiting lease once more.
fn entered_unsatisfiable_condition(
    previous: &[ClusterLeaseCondition],
    reason: crate::metrics::LeaseUnsatisfiableReason,
) -> bool {
    use crate::metrics::LeaseUnsatisfiableReason as R;
    let transient = [R::Warming, R::AtCapacity].map(R::condition_reason);
    !previous.iter().any(|condition| {
        condition.condition_type == "Satisfiable"
            && condition.status == "False"
            && (condition.reason == reason.condition_reason()
                || (reason.is_transient() && transient.contains(&condition.reason.as_str())))
    })
}

/// Build a human-readable lease `status.message` and classify the
/// [`crate::metrics::LeaseUnsatisfiableReason`] from a pool's status, for the
/// "no Ready cluster" case. Shared so the controller branch and the
/// `create_lease` pre-flight (src/api/routes.rs) classify a pool identically.
///
/// The message echoes the pool fields an operator/client needs to decide
/// whether to keep waiting: phase, consecutiveFailures, lastFailureReason.
///
/// Quarantine is read from the counts, not the phase, matching the API
/// pre-flight: a pool below `minReady` with quarantined members and nothing
/// Ready reports `ScalingUp`, yet its queue cannot advance until teardown
/// evidence is repaired. Telling the tenant it is warming up would be wrong.
/// The message leaves the count out because the pre-flight appends it.
pub fn unsatisfiable_status(
    pool_ref: &str,
    pool_status: &Option<ClusterPoolStatus>,
) -> (String, crate::metrics::LeaseUnsatisfiableReason) {
    use crate::metrics::LeaseUnsatisfiableReason as R;

    let Some(status) = pool_status else {
        // No pool status (pool missing or never reconciled): treat as warming
        // rather than asserting exhaustion we can't prove.
        return (
            format!("no Ready cluster; pool {pool_ref} has no status yet (warming up)"),
            R::Warming,
        );
    };

    let phase = status.phase;
    let quarantine_blocked = status.quarantined > 0 && status.ready == 0;
    let reason = match phase {
        Some(ClusterPoolPhase::Failing) => R::PoolExhausted,
        // Same order as the API pre-flight: sustained failure first, then
        // quarantine, whatever phase the pool happens to report.
        _ if quarantine_blocked => R::CapacityBlocked,
        Some(ClusterPoolPhase::Backoff) => R::CapacityBlocked,
        // Every slot is leased: the queue waits for a lease to end.
        Some(ClusterPoolPhase::Exhausted) => R::AtCapacity,
        // Healthy/ScalingUp/Idle with no Ready cluster right now is a transient
        // warm-up; anything else (e.g. ScalingDown) is treated as degraded.
        Some(ClusterPoolPhase::Healthy)
        | Some(ClusterPoolPhase::ScalingUp)
        | Some(ClusterPoolPhase::Idle)
        | None => R::Warming,
        Some(ClusterPoolPhase::ScalingDown) => R::Degraded,
        Some(ClusterPoolPhase::Quarantined) => R::Degraded,
    };

    let phase_str = phase
        .map(|p| format!("{p:?}"))
        .unwrap_or_else(|| "Unknown".to_string());
    let cause = if phase == Some(ClusterPoolPhase::Failing) {
        ""
    } else if quarantine_blocked {
        " is blocked by quarantined members, held until their teardown evidence is repaired;"
    } else if phase == Some(ClusterPoolPhase::Exhausted) {
        " has every cluster leased; waiting for a lease to end;"
    } else {
        ""
    };
    let mut message = format!(
        "no Ready cluster; pool {pool_ref}{cause} phase={phase_str}, consecutiveFailures={}",
        status.consecutive_failures
    );
    if let Some(last) = status.last_failure_reason.as_deref() {
        message.push_str(&format!(", lastFailureReason={last}"));
    }
    if let Some(next) = status.next_attempt_at.as_deref() {
        message.push_str(&format!(", nextAttemptAt={next}"));
    }

    (message, reason)
}

async fn get_profile(client: &Client, name: &str, namespace: &str) -> Option<ClusterPool> {
    let profiles_api: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    match profiles_api.get(name).await {
        Ok(profile) => Some(profile),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(profile = name, "Profile not found");
            None
        }
        Err(e) => {
            error!(profile = name, "Failed to fetch profile: {e}");
            None
        }
    }
}

/// Retry a failed reconcile.
///
/// Every failure counts per lease; a success resets the count (see
/// [`reconcile_lease_tracked`]) and so does the lease's deletion (see
/// [`forget_deleted_lease`]). An optimistic-concurrency conflict retries after
/// [`CONFLICT_RETRY`] for the first [`FAST_CONFLICT_RETRIES`] failures: the
/// lease changed under the reconcile and the next read settles it. Conflicts
/// that keep coming, and every other error, back off exponentially (see
/// [`error_backoff`]).
fn error_policy<B: ClusterBackend>(
    lease: Arc<ClusterLease>,
    error: &LeaseError,
    ctx: Arc<LeaseContext<B>>,
) -> Action {
    let failures = ctx.failures.lock().map_or(1, |mut failures| {
        let count = failures.entry(lease.name_any()).or_insert(0);
        *count = count.saturating_add(1);
        *count
    });
    let conflict = matches!(error, LeaseError::Kube(kube_error) if optimistic_conflict(kube_error));
    if conflict && failures <= FAST_CONFLICT_RETRIES {
        debug!(lease = %lease.name_any(), failures, "Lease reconcile lost an optimistic race; retrying");
        return Action::requeue(CONFLICT_RETRY);
    }
    let failures = if conflict {
        failures - FAST_CONFLICT_RETRIES
    } else {
        failures
    };
    let delay = error_backoff(failures);
    error!(lease = %lease.name_any(), failures, retry_in = ?delay, "Lease reconciliation error: {error}");
    Action::requeue(delay)
}

/// Delay before retry number `failures` (1-based): [`ERROR_BACKOFF_BASE`]
/// doubled per earlier failure, capped at [`ERROR_BACKOFF_MAX`].
fn error_backoff(failures: u32) -> std::time::Duration {
    let doublings = failures.saturating_sub(1).min(16);
    ERROR_BACKOFF_BASE
        .saturating_mul(1 << doublings)
        .min(ERROR_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockBackend;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -----------------------------------------------------------------------
    // optimistic_conflict — which API failures mean "someone wrote first"
    // -----------------------------------------------------------------------

    fn api_error(code: u16, reason: &str, causes: Vec<&str>) -> kube::Error {
        use kube::core::response::{Status, StatusCause, StatusDetails, StatusSummary};
        kube::Error::Api(Box::new(Status {
            status: Some(StatusSummary::Failure),
            code,
            message: "boom".to_string(),
            reason: reason.to_string(),
            details: Some(StatusDetails {
                name: String::new(),
                group: String::new(),
                kind: String::new(),
                uid: String::new(),
                causes: causes
                    .into_iter()
                    .map(|field| StatusCause {
                        field: field.to_string(),
                        message: "invalid".to_string(),
                        reason: "FieldValueInvalid".to_string(),
                    })
                    .collect(),
                retry_after_seconds: 0,
            }),
            metadata: None,
        }))
    }

    /// A failed `Preconditions` check is unambiguous — 409 only ever means a
    /// concurrent modification.
    #[test]
    fn conflict_409_is_a_lost_race() {
        assert!(optimistic_conflict(&api_error(409, "Conflict", vec![])));
    }

    /// A failed JSON-Patch `test` op returns 422 with no field-level causes.
    /// This is the shape observed ~38×/day on int-pro (#153).
    #[test]
    fn invalid_422_without_causes_is_a_lost_race() {
        assert!(optimistic_conflict(&api_error(422, "Invalid", vec![])));
    }

    /// The one that matters: a 422 carrying field-level causes is a genuinely
    /// bad request, not a lost race. Retrying it can never succeed, so treating
    /// it as a conflict would silently requeue forever against a request the
    /// server will always reject — the failure shape of #150. It must stay
    /// loud.
    #[test]
    fn invalid_422_with_causes_is_a_real_error() {
        assert!(
            !optimistic_conflict(&api_error(422, "Invalid", vec!["spec.servers"])),
            "a validation failure must not be absorbed as a lost race"
        );
    }

    /// Unrelated failures are untouched — a 404 or a 500 is not a lost race.
    #[test]
    fn other_status_codes_are_not_lost_races() {
        assert!(!optimistic_conflict(&api_error(404, "NotFound", vec![])));
        assert!(!optimistic_conflict(&api_error(
            500,
            "InternalError",
            vec![]
        )));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a `LeaseContext<MockBackend>` wired to a local wiremock server.
    async fn test_lease_context() -> (Arc<LeaseContext<MockBackend>>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        let backend = MockBackend::new();
        let pools = Arc::new(RwLock::new(HashMap::new()));
        let authenticator = Arc::new(JwtAuthenticator::new("test".to_string()));

        let ctx = Arc::new(LeaseContext {
            client,
            backend,
            pools,
            queues: RwLock::new(HashMap::new()),
            active_reconciles: Mutex::new(HashSet::new()),
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
            instances: None,
            queue_wakes: None,
            failures: Mutex::new(HashMap::new()),
        });
        (ctx, server)
    }

    /// An instance that is already being torn down must not be handed to a new
    /// tenant, even while it still looks idle.
    ///
    /// Deletion is not instantaneous: once `deletionTimestamp` is set the
    /// object lingers until its finalizer runs, and during that window its
    /// status can still read `Ready` with no `leaseRef`. Reserving it binds a
    /// tenant to a cluster that is disappearing — the lease reaches `Bound`,
    /// consumes pool capacity, and then fails at connect time, because
    /// `resolve_lease_binding` separately refuses a deleting instance.
    ///
    /// The fixture is byte-for-byte the one `reserve_ready_instance` accepts in
    /// `bind_records_exact_binding_on_both_sides`, plus `deletionTimestamp`, so
    /// the timestamp is the only thing that can cause the rejection.
    #[tokio::test]
    async fn reserve_skips_instance_being_deleted() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("bind-del", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());
        let backend =
            BackendProvenance::from_config(&crate::crd::BackendConfig::default()).unwrap();
        let deleting_instance = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "pool-test-1",
                "namespace": "test-ns",
                "uid": "instance-uid",
                "resourceVersion": "20",
                "generation": 1,
                "labels": { "kobe.kunobi.ninja/pool": "test-profile" },
                // Teardown has started; the finalizer has not run yet.
                "deletionTimestamp": "2026-01-01T00:00:00Z",
                "finalizers": ["kobe.kunobi.ninja/cleanup"],
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "test-profile",
                    "uid": "test-profile-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
            // Still looks idle.
            "status": {
                "phase": "Ready",
                "provisioned": true,
                "leaseRef": null,
                "specHash": "0000000000000001",
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "test-profile-uid",
                    "backend": backend
                }
            }
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![deleting_instance.clone()]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(deleting_instance.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;
        // Deliberately mounted: if the candidate filter lets a deleting
        // instance through, the reservation PATCH succeeds and the assertion
        // below fails loudly instead of erroring on an unmatched request.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&deleting_instance))
            .mount(&server)
            .await;

        let result = reserve_ready_instance(&ctx.client, "test-ns", &lease, None, 0).await;
        assert!(
            matches!(result, Ok(None)),
            "an instance with a deletionTimestamp must not be reserved, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reserve_skips_ready_instance_with_stale_lease_ref() {
        // A Ready instance that still carries a leaseRef (e.g. a stale phase
        // write reverted it Leased->Ready without clearing leaseRef) must NOT be
        // reserved, or the same cluster is double-leased to a second tenant.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        let lease: ClusterLease = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": "lease-new",
                "namespace": "test-ns",
                "uid": "lease-uid",
                "resourceVersion": "10"
            },
            "spec": {
                "poolRef": "p",
                "ttl": "1h",
                "requester": { "type": "test:admin", "identity": "test" }
            },
            "status": { "phase": "Pending" }
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-new",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/p",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "metadata": { "name": "p", "namespace": "test-ns", "uid": "pool-uid" },
                "spec": {
                    "size": 1,
                    "backend": { "type": "k3s" },
                    "cluster": { "version": "v1.32.0" }
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterInstance",
                    "metadata": {
                        "name": "pool-p-0",
                        "namespace": "test-ns",
                        "labels": { "kobe.kunobi.ninja/pool": "p" }
                    },
                    "spec": { "poolRef": { "name": "p" } },
                    "status": { "phase": "Ready", "leaseRef": { "name": "lease-old" } }
                })]),
            ))
            .mount(&server)
            .await;

        let result = reserve_ready_instance(&client, "test-ns", &lease, None, 0).await;
        assert!(
            matches!(result, Ok(None)),
            "a Ready instance still carrying a leaseRef must not be reserved, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reserve_skips_ready_instance_with_stale_binding() {
        // A Ready instance can lose its display-only leaseRef while retaining
        // the authoritative binding. It is not free and must not become the
        // first candidate that prevents the scheduler trying later instances.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        let lease: ClusterLease = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": "lease-new",
                "namespace": "test-ns",
                "uid": "lease-uid",
                "resourceVersion": "10"
            },
            "spec": {
                "poolRef": "test-profile",
                "ttl": "1h",
                "requester": { "type": "test:admin", "identity": "test" }
            },
            "status": { "phase": "Pending" }
        }))
        .unwrap();

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterInstance",
                    "metadata": {
                        "name": "pool-test-1",
                        "namespace": "test-ns",
                        "labels": { "kobe.kunobi.ninja/pool": "test-profile" }
                    },
                    "spec": { "poolRef": { "name": "test-profile" } },
                    "status": {
                        "phase": "Ready",
                        "leaseRef": null,
                        "binding": exact_test_binding("lease-old", "lease-old-uid")
                    }
                })]),
            ))
            .mount(&server)
            .await;

        let result = reserve_ready_instance(&client, "test-ns", &lease, None, 0).await;
        assert!(
            matches!(result, Ok(None)),
            "a Ready instance still carrying a binding must not be reserved, got {result:?}"
        );
    }

    fn exact_test_binding(lease_name: &str, lease_uid: &str) -> LeaseBinding {
        LeaseBinding {
            binding_id: format!("binding-{lease_name}"),
            lease: ResourceRef {
                name: lease_name.into(),
                uid: Some(lease_uid.into()),
            },
            instance: BoundInstanceRef {
                name: "pool-test-1".into(),
                uid: "instance-uid".into(),
                observed_generation: 1,
            },
            pool: ResourceRef {
                name: "test-profile".into(),
                uid: Some("test-profile-uid".into()),
            },
            backend: BackendProvenance::from_config(&crate::crd::BackendConfig::default()).unwrap(),
            instance_spec_digest: "0000000000000001".into(),
            cleanup_mode: crate::crd::CleanupMode::Standard,
            creation_manifest_digest: None,
            creation_manifest: None,
            connect_token: None,
        }
    }

    fn exact_instance_for_binding(
        binding: Option<&LeaseBinding>,
        phase: &str,
    ) -> serde_json::Value {
        let lease_ref = binding.map(|binding| binding.lease.clone());
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "pool-test-1",
                "namespace": "test-ns",
                "uid": "instance-uid",
                "resourceVersion": "20",
                "generation": 1,
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "test-profile",
                    "uid": "test-profile-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
            "status": {
                "phase": phase,
                "provisioned": true,
                "bootstrapped": true,
                "leaseRef": lease_ref,
                "binding": binding,
                "specHash": "0000000000000001",
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "test-profile-uid",
                    "backend": BackendProvenance::from_config(&crate::crd::BackendConfig::default()).unwrap()
                }
            }
        })
    }

    fn exact_pending_lease_for_binding(binding: &LeaseBinding) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": binding.lease.name,
                "namespace": "test-ns",
                "uid": binding.lease.uid,
                "resourceVersion": "10",
                "generation": 1
            },
            "spec": {
                "poolRef": "test-profile",
                "ttl": "1h",
                "requester": { "type": "test:admin", "identity": "user@test.com" }
            },
            "status": {
                "phase": "Pending",
                "binding": binding
            }
        })
    }

    #[tokio::test]
    async fn finalize_binding_rereads_both_sides_and_retries_a_lost_race() {
        let (ctx, server) = test_lease_context().await;
        let binding = exact_test_binding("lease-finalize", "lease-finalize-uid");
        let stale = exact_pending_lease_for_binding(&binding);
        let mut fresh = stale.clone();
        fresh["metadata"]["resourceVersion"] = "11".into();
        let mut bound = fresh.clone();
        bound["metadata"]["resourceVersion"] = "12".into();
        bound["status"]["phase"] = "Bound".into();
        bound["status"]["clusterName"] = binding.instance.name.clone().into();
        let instance = exact_instance_for_binding(Some(&binding), "Leased");
        let lease_endpoint = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            binding.lease.name
        );
        let instance_endpoint = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/{}",
            binding.instance.name
        );

        Mock::given(method("GET"))
            .and(path(lease_endpoint.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&stale))
            .with_priority(1)
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(lease_endpoint.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&fresh))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(instance_endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(&instance))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{lease_endpoint}/status")))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": "Invalid",
                "message": "fence lost",
                "details": { "causes": [] },
                "code": 422
            })))
            .with_priority(1)
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{lease_endpoint}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&bound))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            finalize_binding(&ctx, "test-ns", &binding, chrono::Utc::now())
                .await
                .expect("fresh reciprocal pair must finalize")
        );
        let patches: Vec<serde_json::Value> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect();
        assert_eq!(patches.len(), 2);
        for (patch, resource_version) in patches.iter().zip(["10", "11"]) {
            let operations = patch.as_array().unwrap();
            assert!(operations.iter().any(|operation| {
                operation["op"] == "test"
                    && operation["path"] == "/metadata/resourceVersion"
                    && operation["value"] == resource_version
            }));
            assert!(operations.iter().any(|operation| {
                operation["op"] == "add"
                    && operation["path"] == "/status/phase"
                    && operation["value"] == "Bound"
            }));
            assert!(
                operations
                    .iter()
                    .all(|operation| operation["path"] != "/status"),
                "finalization must not replace unrelated status fields"
            );
        }
    }

    #[tokio::test]
    async fn two_competing_reservations_have_exactly_one_patch_winner() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let first = exact_test_binding("lease-a", "lease-a-uid");
        let second = exact_test_binding("lease-b", "lease-b-uid");
        let ready = exact_instance_for_binding(None, "Ready");

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready))
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": "Conflict",
                "code": 409
            })))
            .with_priority(2)
            .mount(&server)
            .await;

        let won = reserve_binding_instance_after_lease_fence(&client, "test-ns", &first)
            .await
            .unwrap();
        let lost = reserve_binding_instance_after_lease_fence(&client, "test-ns", &second)
            .await
            .unwrap();
        assert_eq!(won, ReservationOutcome::Reserved);
        assert_eq!(lost, ReservationOutcome::Retry);

        let requests = server.received_requests().await.unwrap();
        let patches: Vec<serde_json::Value> = requests
            .iter()
            .filter(|request| request.method == http::Method::PATCH)
            .filter_map(|request| serde_json::from_slice(&request.body).ok())
            .collect();
        assert_eq!(patches.len(), 2);
        for patch in patches {
            let ops = patch.as_array().expect("reservation uses JSON Patch");
            for path in [
                "/metadata/uid",
                "/metadata/resourceVersion",
                "/status/phase",
                "/status/leaseRef",
                "/status/binding",
            ] {
                assert!(
                    ops.iter().any(|op| op["path"] == path),
                    "missing {path}: {patch}"
                );
            }
        }
    }

    #[tokio::test]
    async fn reservation_conflict_adopts_the_exact_binding_without_clearing_intent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        let ready = exact_instance_for_binding(None, "Ready");
        let adopted = exact_instance_for_binding(Some(&binding), "Leased");
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(exact_pending_lease_for_binding(&binding)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready))
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(adopted))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{instance_path}/status")))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": "Conflict",
                "code": 409
            })))
            .mount(&server)
            .await;

        assert_eq!(
            reserve_binding_instance(&client, "test-ns", &binding)
                .await
                .unwrap(),
            ReservationOutcome::Reserved
        );
    }

    #[tokio::test]
    async fn exact_binding_already_in_teardown_is_retryable_not_foreign() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        let recycling = exact_instance_for_binding(Some(&binding), "Recycling");
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(exact_pending_lease_for_binding(&binding)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(recycling))
            .mount(&server)
            .await;

        assert_eq!(
            reserve_binding_instance(&client, "test-ns", &binding)
                .await
                .unwrap(),
            ReservationOutcome::Retry
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method != http::Method::PATCH)
        );
    }

    #[tokio::test]
    async fn adopted_exact_binding_repairs_stale_ready_projection_instead_of_clearing_intent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        let mut adopted = exact_instance_for_binding(Some(&binding), "Ready");
        adopted["status"]["leaseRef"] = serde_json::Value::Null;
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(exact_pending_lease_for_binding(&binding)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(adopted.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{instance_path}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(adopted))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reserve_binding_instance(&client, "test-ns", &binding)
                .await
                .unwrap(),
            ReservationOutcome::Reserved
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method == http::Method::PATCH)
            .expect("leaseRef repair patch");
        let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/status/binding"
                && operation["value"] == serde_json::to_value(&binding).unwrap()
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status/leaseRef"
                && operation["value"] == serde_json::to_value(&binding.lease).unwrap()
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status/phase"
                && operation["value"] == "Leased"
        }));
    }

    #[tokio::test]
    async fn resumed_composition_intent_must_match_outer_pool_authority() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let mut lease = authorized_sandbox_composition_handle(outer_name, "30");
        lease
            .metadata
            .finalizers
            .get_or_insert_default()
            .push(TEARDOWN_RECEIPT_RETENTION_FINALIZER.into());
        let mut binding = exact_test_binding(&lease.name_any(), "late-child-uid");
        binding.pool = ResourceRef {
            name: "child-pool".into(),
            uid: Some("child-pool-uid-b".into()),
        };
        lease.status.as_mut().unwrap().binding = Some(binding);
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(open_outer_sandbox(outer_name)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_pool("child-pool-uid-a", 3)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{}",
                crate::controllers::sandbox::allocation_fence_name(outer_name)
            )))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "leases",
                    "sandbox-allocation-late-outer",
                )),
            )
            .mount(&server)
            .await;

        assert!(
            reserve_ready_instance(&ctx.client, "test-ns", &lease, None, 0)
                .await
                .unwrap()
                .is_none()
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(!requests.iter().any(|request| {
            request.url.path().contains("/clusterinstances")
                || request.url.path().contains("/secrets")
                || request.method == http::Method::PATCH
        }));
    }

    #[tokio::test]
    async fn replayed_lease_intent_resumes_only_the_same_exact_instance() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        let leased = exact_instance_for_binding(Some(&binding), "Leased");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(leased))
            .expect(2)
            .mount(&server)
            .await;

        let mut lease = make_test_lease("lease-a", "Pending");
        Arc::make_mut(&mut lease).status.as_mut().unwrap().binding = Some(binding.clone());
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .expect(1)
            .mount(&server)
            .await;
        let resumed = reserve_ready_instance(&client, "test-ns", &lease, None, 0)
            .await
            .unwrap();
        assert_eq!(resumed, Some(binding));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            3,
            "replay may revalidate the exact lease and instance but must not list or reserve another one"
        );
    }

    /// Build a `ClusterLease` CRD object in the given phase.
    fn make_test_lease(name: &str, phase: &str) -> Arc<ClusterLease> {
        let cluster_name: serde_json::Value =
            if phase == "Bound" || phase == "Released" || phase == "Recycling" {
                serde_json::json!("pool-test-1")
            } else {
                serde_json::json!(null)
            };

        let expires_at: serde_json::Value = if phase == "Bound" {
            let future = chrono::Utc::now() + chrono::Duration::hours(1);
            serde_json::json!(future.to_rfc3339())
        } else {
            serde_json::json!(null)
        };

        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "uid": format!("{name}-uid")
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "user@test.com" },
                    "priority": 50
                },
                "status": {
                    "phase": phase,
                    "clusterName": cluster_name,
                    "expiresAt": expires_at,
                    "queuePosition": 0,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        )
    }

    fn delayed_sandbox_composition_handle(
        outer_name: &str,
        resource_version: &str,
        fenced: bool,
    ) -> ClusterLease {
        let outer_uid = "late-outer-uid";
        let child_name = crate::controllers::sandbox_child::internal_lease_name(outer_name);
        let mut metadata = serde_json::json!({
            "name": child_name,
            "namespace": "test-ns",
            "uid": "late-child-uid",
            "resourceVersion": resource_version,
            "generation": 1,
            "labels": {
                "app.kubernetes.io/managed-by": crate::sandbox::KOBE_MANAGED_BY,
                crate::sandbox::SANDBOX_LEASE_UID_LABEL: outer_uid,
            },
        });
        if fenced {
            metadata["ownerReferences"] = serde_json::json!([]);
            metadata["labels"][crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL] =
                "true".into();
            metadata["annotations"] = serde_json::json!({
                crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION: outer_name,
                crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION: outer_uid,
                crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION:
                    (chrono::Utc::now() + chrono::Duration::days(8)).to_rfc3339(),
            });
            metadata["finalizers"] = serde_json::json!([
                crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
            ]);
        } else {
            // Rolling-upgrade shape emitted by the pre-fence producer. Only
            // this exact sole legacy owner is migratable.
            metadata["ownerReferences"] = serde_json::json!([{
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "SandboxLease",
                "name": outer_name,
                "uid": outer_uid,
                "controller": true,
            }]);
        }
        serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": metadata,
            "spec": {
                "poolRef": "child-pool",
                "ttl": "2h",
                "requester": {
                    "type": "kobe:sandbox-composition",
                    "identity": "late-outer-uid"
                },
                "priority": 1000,
                "cleanupMode": "VerifiedDestroy"
            },
            "status": { "phase": "Pending" }
        }))
        .unwrap()
    }

    /// Exact metadata identity emitted by the base child-composition producer:
    /// managed-by plus the sole outer controller owner, but no outer UID label,
    /// retention annotations, tombstone label, or finalizer.
    fn base_legacy_sandbox_composition_handle(
        outer_name: &str,
        resource_version: &str,
    ) -> ClusterLease {
        let mut value = serde_json::to_value(delayed_sandbox_composition_handle(
            outer_name,
            resource_version,
            false,
        ))
        .unwrap();
        value["metadata"]["labels"]
            .as_object_mut()
            .unwrap()
            .remove(crate::sandbox::SANDBOX_LEASE_UID_LABEL);
        serde_json::from_value(value).unwrap()
    }

    #[tokio::test]
    async fn terminal_creating_404_remains_ambiguous_and_emits_no_write() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        let mut lease = (*make_test_lease("lease-a", "Released")).clone();
        lease.metadata.resource_version = Some("10".into());
        lease.spec.cleanup_mode = Some(crate::crd::CleanupMode::VerifiedDestroy);
        let status = lease.status.as_mut().unwrap();
        status.cluster_name = None;
        status.binding = Some(binding.clone());
        status.teardown_attempt_id = Some("teardown-1".into());
        status.connect_token_creation = Some(ConnectTokenCreation {
            attempt_id: "create-1".into(),
            phase: ConnectTokenCreationPhase::Creating,
            identity: None,
            verified_absent_at: None,
        });
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = close_terminal_connect_token_creation(
            &client,
            "test-ns",
            &lease,
            lease.status.as_ref().unwrap(),
            &binding,
        )
        .await
        .unwrap();
        assert!(result.is_none());
        assert!(!unbound_release_proof_is_complete(
            lease.status.as_ref().unwrap()
        ));
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method != http::Method::POST
                && request.method != http::Method::PATCH
                && request.method != http::Method::DELETE
        }));
    }

    #[tokio::test]
    async fn terminal_prepared_closes_creator_and_retains_exact_intent_atomically() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        let mut lease = (*make_test_lease("lease-a", "Released")).clone();
        lease.metadata.resource_version = Some("10".into());
        lease.spec.cleanup_mode = Some(crate::crd::CleanupMode::VerifiedDestroy);
        let status = lease.status.as_mut().unwrap();
        status.cluster_name = None;
        status.binding = Some(binding.clone());
        status.teardown_attempt_id = Some("teardown-1".into());
        status.connect_token_creation = Some(ConnectTokenCreation {
            attempt_id: "create-1".into(),
            phase: ConnectTokenCreationPhase::Prepared,
            identity: None,
            verified_absent_at: None,
        });
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            close_terminal_connect_token_creation(
                &client,
                "test-ns",
                &lease,
                lease.status.as_ref().unwrap(),
                &binding,
            )
            .await
            .unwrap()
            .is_none()
        );

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "Prepared close must issue only its CAS");
        let patch: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let operations = patch.as_array().unwrap();
        assert!(operations.iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status/binding"
                && operation["value"] == serde_json::to_value(&binding).unwrap()
        }));
        assert!(operations.iter().all(|operation| {
            !(operation["op"] == "remove" && operation["path"] == "/status/binding")
        }));
        assert!(operations.iter().any(|operation| {
            operation["path"] == "/status/connectTokenCreation"
                && operation["value"]["phase"] == "closed"
                && operation["value"]["verifiedAbsentAt"].is_string()
        }));
    }

    #[tokio::test]
    async fn lost_reservation_persists_closing_before_token_delete() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let identity = crate::crd::KubernetesResourceIdentity {
            api_version: "v1".into(),
            kind: "Secret".into(),
            namespace: Some("test-ns".into()),
            name: "lease-a-connect-token".into(),
            uid: "token-uid".into(),
        };
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        binding.connect_token = Some(identity.clone());
        let mut lease = (*make_test_lease("lease-a", "Pending")).clone();
        lease.metadata.resource_version = Some("10".into());
        lease.spec.cleanup_mode = Some(crate::crd::CleanupMode::VerifiedDestroy);
        let status = lease.status.as_mut().unwrap();
        status.binding = Some(binding.clone());
        status.connect_token_creation = Some(ConnectTokenCreation {
            attempt_id: "create-1".into(),
            phase: ConnectTokenCreationPhase::Ready,
            identity: Some(identity),
            verified_absent_at: None,
        });
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .expect(1)
            .mount(&server)
            .await;

        close_abandoned_pending_binding(&client, "test-ns", &lease, &binding)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|request| request.method != http::Method::DELETE)
        );
        let patch: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(patch.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status/connectTokenCreation"
                && operation["value"]["phase"] == "closing"
        }));
    }

    fn authority_unbound_lease() -> ClusterLease {
        let mut lease = (*make_test_lease("lease-a", "Released")).clone();
        lease.spec.cleanup_mode = Some(crate::crd::CleanupMode::VerifiedDestroy);
        let status = lease.status.as_mut().unwrap();
        status.cluster_name = None;
        status.teardown_attempt_id = Some("teardown-1".into());
        status.connect_token_creation = Some(ConnectTokenCreation {
            attempt_id: "create-1".into(),
            phase: ConnectTokenCreationPhase::Closed,
            identity: None,
            verified_absent_at: Some("2026-01-01T00:00:00Z".into()),
        });
        lease
    }

    #[test]
    fn never_bound_proof_rejects_a_late_binding_intent() {
        let mut lease = authority_unbound_lease();
        let status = lease.status.as_mut().unwrap();
        status.unbound_release_verified_at = Some("2026-01-01T00:00:00Z".into());
        status.conditions.push(ClusterLeaseCondition {
            condition_type: ALLOCATION_ABSENT_CONDITION.into(),
            status: "True".into(),
            reason: "NeverBound".into(),
            message: "release attempt teardown-1 proved no reciprocal allocation existed".into(),
            last_transition_time: Some("2026-01-01T00:00:00Z".into()),
        });
        assert!(unbound_release_proof_is_complete(status));

        status.binding = Some(exact_test_binding("lease-a", "lease-a-uid"));
        assert!(
            !unbound_release_proof_is_complete(status),
            "a binding intent appearing after proof must fail closed"
        );
    }

    #[test]
    fn never_bound_proof_retains_the_exact_pre_create_intent() {
        let mut lease = authority_unbound_lease();
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        {
            let status = lease.status.as_mut().unwrap();
            status.binding = Some(binding.clone());
            status.unbound_release_verified_at = Some("2026-01-01T00:00:00Z".into());
            status.conditions.push(ClusterLeaseCondition {
                condition_type: ALLOCATION_ABSENT_CONDITION.into(),
                status: "True".into(),
                reason: "NeverBound".into(),
                message: "release attempt teardown-1 proved no reciprocal allocation existed"
                    .into(),
                last_transition_time: Some("2026-01-01T00:00:00Z".into()),
            });
        }
        let status = lease.status.as_ref().unwrap();

        assert!(retained_unstarted_binding_matches_lease(&lease, status));
        assert!(unbound_release_proof_is_complete(status));
        assert!(unbound_release_proof_is_complete_for_lease(&lease, status));
        assert_eq!(status.binding.as_ref(), Some(&binding));

        let mut wrong_subject = lease.clone();
        wrong_subject
            .status
            .as_mut()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .lease
            .uid = Some("other-lease-uid".into());
        assert!(unbound_release_proof_is_complete(
            wrong_subject.status.as_ref().unwrap()
        ));
        assert!(!unbound_release_proof_is_complete_for_lease(
            &wrong_subject,
            wrong_subject.status.as_ref().unwrap()
        ));
    }

    #[tokio::test]
    async fn release_authority_refuses_never_bound_when_any_reciprocal_instance_exists() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let lease = authority_unbound_lease();
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![exact_instance_for_binding(
                    Some(&binding),
                    "Leased",
                )]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            authority_never_bound_observation(&client, "test-ns", &lease)
                .await
                .unwrap()
                .is_none(),
            "a reciprocal binding must keep NeverBound fail-closed"
        );
    }

    #[tokio::test]
    async fn release_authority_refuses_a_non_pre_create_binding_intent() {
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = authority_unbound_lease();
        lease.status.as_mut().unwrap().binding = Some(exact_test_binding("lease-a", "lease-a-uid"));

        assert!(
            authority_never_bound_observation(&client, "test-ns", &lease)
                .await
                .unwrap()
                .is_none(),
            "only an exact VerifiedDestroy pre-create intent can become NeverBound"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn retained_pre_create_intent_proves_exact_candidate_replacement_absent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = authority_unbound_lease();
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        lease.status.as_mut().unwrap().binding = Some(binding);
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut replacement = exact_instance_for_binding(None, "Ready");
        replacement["metadata"]["uid"] = "replacement-instance-uid".into();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![replacement])),
            )
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            authority_never_bound_observation(&client, "test-ns", &lease)
                .await
                .unwrap()
                .as_deref(),
            Some("2026-01-01T00:00:00Z"),
            "a same-name different-UID free instance is not the retained candidate"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == http::Method::GET)
        );
    }

    #[tokio::test]
    async fn delayed_creator_and_reserver_stop_at_the_terminal_lease_fence() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = authority_unbound_lease();
        lease.metadata.resource_version = Some("10".into());
        let mut binding = exact_test_binding("lease-a", "lease-a-uid");
        binding.cleanup_mode = crate::crd::CleanupMode::VerifiedDestroy;
        lease.status.as_mut().unwrap().binding = Some(binding.clone());
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            complete_connect_token_creation(&client, "test-ns", &lease, &binding)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reserve_binding_instance(&client, "test-ns", &binding)
                .await
                .unwrap(),
            ReservationOutcome::Retry
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "only the reserver performs a fresh lease GET"
        );
        assert!(requests.iter().all(|request| {
            request.method == http::Method::GET
                && !request.url.path().contains("/clusterinstances/")
                && !request.url.path().contains("/secrets/")
        }));
    }

    #[tokio::test]
    async fn release_authority_can_prove_pre_allocation_attempt_only_after_full_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = authority_unbound_lease();
        lease.status.as_mut().unwrap().connect_token_creation = None;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            authority_never_bound_observation(&client, "test-ns", &lease)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn release_authority_reuses_the_closed_creator_absence_timestamp() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let lease = authority_unbound_lease();
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            authority_never_bound_observation(&client, "test-ns", &lease)
                .await
                .unwrap()
                .as_deref(),
            Some("2026-01-01T00:00:00Z"),
            "NeverBound must remain causally tied to the creator's exact Closed proof"
        );
    }

    #[test]
    fn receipt_acknowledgement_cannot_replay_an_old_attempt_or_boolean() {
        let receipt = crate::crd::TeardownReceipt {
            schema_version: crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION,
            attempt_id: "attempt-1".into(),
            lease: ResourceRef {
                name: "lease-a".into(),
                uid: Some("lease-a-uid".into()),
            },
            instance: ResourceRef {
                name: "instance-a".into(),
                uid: Some("instance-a-uid".into()),
            },
            pool: ResourceRef {
                name: "pool-a".into(),
                uid: Some("pool-a-uid".into()),
            },
            backend_type: "k3s".into(),
            config_digest: "config".into(),
            instance_spec_digest: "instance-spec".into(),
            creation_manifest_digest: "manifest".into(),
            cleanup_mode: crate::crd::CleanupMode::VerifiedDestroy,
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:01:00Z".into()),
            checks: vec![crate::crd::TeardownCheck {
                subject: crate::crd::TeardownSubject::ServerStatefulSet,
                result: crate::crd::CheckResult::Verified,
                reason: None,
                verified: vec!["exact-sts".into()],
            }],
            retry_count: 0,
            outcome: crate::crd::TeardownOutcome::Verified,
        };
        let mut lease = (*make_test_lease("lease-a", "Recycling")).clone();
        let mut status = lease.status.clone().unwrap_or_default();
        status.teardown_receipt = Some(receipt.clone());

        lease.metadata.annotations = Some(std::collections::BTreeMap::from([(
            TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION.into(),
            "true".into(),
        )]));
        assert!(!teardown_receipt_acknowledged(&lease, &status));

        let token = receipt.acknowledgement_token().unwrap();
        lease
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION.into(), token);
        assert!(teardown_receipt_acknowledged(&lease, &status));

        status.teardown_receipt.as_mut().unwrap().attempt_id = "attempt-2".into();
        assert!(!teardown_receipt_acknowledged(&lease, &status));
    }

    fn closed_outer_sandbox(outer_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxLease",
            "metadata": {
                "name": outer_name,
                "namespace": "test-ns",
                "uid": "late-outer-uid",
                "resourceVersion": "outer-rv-20",
                "generation": 1,
                "finalizers": [crate::sandbox::SANDBOX_LEASE_FINALIZER]
            },
            "spec": {
                "poolRef": { "name": "sandbox-pool", "uid": "pool-uid", "generation": 1 },
                "ttl": "1h",
                "requester": {
                    "provider": "oidc", "type": "user",
                    "issuer": "https://issuer.invalid", "identity": "alice"
                }
            },
            "status": {
                "phase": "Releasing",
                "observedGeneration": 1,
                "releaseCause": "Requested"
            }
        })
    }

    fn open_outer_sandbox(outer_name: &str) -> serde_json::Value {
        let mut outer = closed_outer_sandbox(outer_name);
        outer["metadata"]["annotations"] = serde_json::json!({
            crate::api::sandbox::SANDBOX_ADMISSION_ANNOTATION:
                crate::api::sandbox::SANDBOX_ADMISSION_ADMITTED
        });
        outer["status"] = serde_json::json!({
            "phase": "Provisioning",
            "observedGeneration": 1
        });
        outer["spec"]["placementAuthority"] = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "namespace": "test-ns",
            "name": "child-pool",
            "uid": "child-pool-uid-a",
            "generation": 3
        });
        outer
    }

    fn child_cluster_pool(uid: &str, generation: i64) -> serde_json::Value {
        let mut pool = make_test_profile();
        pool["metadata"]["name"] = "child-pool".into();
        pool["metadata"]["uid"] = uid.into();
        pool["metadata"]["generation"] = generation.into();
        pool
    }

    fn authorized_sandbox_composition_handle(
        outer_name: &str,
        resource_version: &str,
    ) -> ClusterLease {
        let mut lease = delayed_sandbox_composition_handle(outer_name, resource_version, false);
        let identity = SandboxCompositionIdentity {
            outer_name: outer_name.into(),
            outer_uid: "late-outer-uid".into(),
        };
        let (labels, annotations, finalizers) =
            sandbox_composition_retention_metadata(&lease, &identity, false);
        lease.metadata.owner_references = Some(Vec::new());
        lease.metadata.labels = Some(labels);
        lease.metadata.annotations = Some(annotations);
        lease.metadata.finalizers = Some(finalizers);
        lease
    }

    #[tokio::test]
    async fn exact_outer_authority_and_live_pool_authorize_composition() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = authorized_sandbox_composition_handle(outer_name, "10");
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(open_outer_sandbox(outer_name)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_pool("child-pool-uid-a", 3)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{}",
                crate::controllers::sandbox::allocation_fence_name(outer_name)
            )))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "leases",
                    "sandbox-allocation-late-outer",
                )),
            )
            .mount(&server)
            .await;

        let SandboxCompositionGate::Authorized(authority) =
            sandbox_composition_allocation_gate(&ctx.client, "test-ns", &lease).await
        else {
            panic!("exact live authority must authorize the composition");
        };
        assert_eq!(authority.uid, "child-pool-uid-a");
        assert_eq!(authority.generation, 3);
    }

    /// The producer may read pool A and have its POST commit only after the
    /// same name points at pool B. The consumer closes that handle before any
    /// queue entry, binding intent, token, or instance observation.
    #[tokio::test]
    async fn same_name_pool_replacement_before_consumer_never_queues_or_binds() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = authorized_sandbox_composition_handle(outer_name, "10");
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(open_outer_sandbox(outer_name)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_pool("child-pool-uid-b", 1)),
            )
            .mount(&server)
            .await;

        let identity = SandboxCompositionIdentity {
            outer_name: outer_name.into(),
            outer_uid: "late-outer-uid".into(),
        };
        let (labels, annotations, finalizers) =
            sandbox_composition_retention_metadata(&lease, &identity, true);
        let mut rejected = lease.clone();
        rejected.metadata.owner_references = Some(Vec::new());
        rejected.metadata.labels = Some(labels);
        rejected.metadata.annotations = Some(annotations);
        rejected.metadata.finalizers = Some(finalizers);
        rejected.metadata.resource_version = Some("11".into());
        Mock::given(method("PATCH"))
            .and(path(child_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&rejected))
            .expect(1)
            .mount(&server)
            .await;
        let mut released = rejected;
        released.metadata.resource_version = Some("12".into());
        released.status.as_mut().unwrap().phase = LeasePhase::Released;
        Mock::given(method("PATCH"))
            .and(path(child_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(released))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx.clone()).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(1))
        );
        assert!(ctx.queues.read().await.values().all(Vec::is_empty));
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(!requests.iter().any(|request| {
            request.url.path().contains("/clusterinstances")
                || request.url.path().contains("/secrets")
        }));
        let status_patch = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_status_path
            })
            .expect("stale handle status patch");
        let operations: serde_json::Value = serde_json::from_slice(&status_patch.body).unwrap();
        assert!(!operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status/binding" || operation["value"]["phase"] == "Bound"
        }));
    }

    #[tokio::test]
    async fn legacy_pending_composition_without_authority_never_enters_queue() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = authorized_sandbox_composition_handle(outer_name, "20");
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let mut legacy_outer = open_outer_sandbox(outer_name);
        legacy_outer["spec"]
            .as_object_mut()
            .unwrap()
            .remove("placementAuthority");
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(legacy_outer))
            .mount(&server)
            .await;

        let identity = SandboxCompositionIdentity {
            outer_name: outer_name.into(),
            outer_uid: "late-outer-uid".into(),
        };
        let (labels, annotations, finalizers) =
            sandbox_composition_retention_metadata(&lease, &identity, true);
        let mut rejected = lease.clone();
        rejected.metadata.labels = Some(labels);
        rejected.metadata.annotations = Some(annotations);
        rejected.metadata.finalizers = Some(finalizers);
        rejected.metadata.resource_version = Some("21".into());
        Mock::given(method("PATCH"))
            .and(path(child_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&rejected))
            .expect(1)
            .mount(&server)
            .await;
        let mut released = rejected;
        released.metadata.resource_version = Some("22".into());
        released.status.as_mut().unwrap().phase = LeasePhase::Released;
        Mock::given(method("PATCH"))
            .and(path(child_status_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(released))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx.clone()).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(1))
        );
        assert!(ctx.queues.read().await.values().all(Vec::is_empty));
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(!requests.iter().any(|request| {
            request.url.path().contains("/clusterpools")
                || request.url.path().contains("/clusterinstances")
                || request.url.path().contains("/secrets")
        }));
    }

    /// A true base object has no UID label, so the exact sole ownerRef is the
    /// only safe migration source. Even with an open outer lease, the consumer
    /// must install the full owner-independent fence and end the pass before a
    /// pool lookup, queue write, status write, or instance reservation.
    #[tokio::test]
    async fn base_legacy_sandbox_composition_is_migrated_before_open_queue() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = base_legacy_sandbox_composition_handle(outer_name, "10");
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let outer_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
        );
        let fence_path = format!(
            "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{}",
            crate::controllers::sandbox::allocation_fence_name(outer_name)
        );
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(outer_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(open_outer_sandbox(outer_name)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_pool("child-pool-uid-a", 3)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(fence_path))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 404, "reason": "NotFound"
            })))
            .mount(&server)
            .await;
        let mut migrated = serde_json::to_value(&lease).unwrap();
        migrated["metadata"]["resourceVersion"] = "11".into();
        migrated["metadata"]["ownerReferences"] = serde_json::json!([]);
        Mock::given(method("PATCH"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(migrated))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::await_change()
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(!requests.iter().any(|request| {
            request.url.path().contains("/clusterinstances")
                || request.url.path() == child_status_path
        }));
        let patch = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_path
            })
            .expect("base-handle migration patch");
        let operations: Vec<serde_json::Value> = serde_json::from_slice(&patch.body).unwrap();
        for (path, value) in [
            ("/metadata/uid", serde_json::json!("late-child-uid")),
            ("/metadata/resourceVersion", serde_json::json!("10")),
        ] {
            assert!(operations.iter().any(|operation| {
                operation["op"] == "test"
                    && operation["path"] == path
                    && operation["value"] == value
            }));
        }
        assert!(operations.iter().any(|operation| {
            operation["path"] == "/metadata/ownerReferences"
                && operation["value"] == serde_json::json!([])
        }));
        let labels = &operations
            .iter()
            .find(|operation| operation["path"] == "/metadata/labels")
            .expect("UID/tombstone labels")["value"];
        assert_eq!(
            labels[crate::sandbox::SANDBOX_LEASE_UID_LABEL],
            "late-outer-uid"
        );
        assert_eq!(
            labels[crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL],
            "true"
        );
        let annotations = &operations
            .iter()
            .find(|operation| operation["path"] == "/metadata/annotations")
            .expect("outer identity and retention annotations")["value"];
        assert_eq!(
            annotations[crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION],
            outer_name
        );
        assert!(
            annotations
                .get(crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION)
                .and_then(serde_json::Value::as_str)
                .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
                .is_some_and(|deadline| deadline > chrono::Utc::now())
        );
        assert!(operations.iter().any(|operation| {
            operation["path"] == "/metadata/finalizers"
                && operation["value"].as_array().is_some_and(|finalizers| {
                    finalizers.iter().any(|finalizer| {
                        finalizer
                            == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
                    })
                })
        }));
    }

    /// A POST from the previous producer can commit after release published its
    /// fence. The consumer must migrate/fence that exact legacy object and end
    /// the pass before it ever lists or reserves capacity.
    #[tokio::test]
    async fn delayed_sandbox_composition_is_fenced_before_queue_or_reservation() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = delayed_sandbox_composition_handle(outer_name, "10", false);
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let outer_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
        );
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(outer_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(closed_outer_sandbox(outer_name)),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(child_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(delayed_sandbox_composition_handle(outer_name, "11", true)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut released =
            serde_json::to_value(delayed_sandbox_composition_handle(outer_name, "12", true))
                .unwrap();
        released["status"]["phase"] = "Released".into();
        Mock::given(method("PATCH"))
            .and(path(child_status_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(released))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(1))
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(!requests.iter().any(|request| {
            request.url.path().contains("/clusterinstances")
                || request.url.path().contains("/clusterpools/child-pool")
        }));
        let patch = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_path
            })
            .expect("retention fence patch");
        let patch: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert!(patch.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/metadata/ownerReferences"
                && operation["value"] == serde_json::json!([])
        }));
        assert!(patch.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/metadata/finalizers"
                && operation["value"].as_array().is_some_and(|finalizers| {
                    finalizers.iter().any(|finalizer| {
                        finalizer
                            == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
                    })
                })
        }));
    }

    /// Once fenced, the same delayed handle becomes Released under UID/RV and
    /// Pending-phase tests. It never enters the allocation queue.
    #[tokio::test]
    async fn fenced_delayed_sandbox_composition_is_terminalized_without_allocation() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let lease = delayed_sandbox_composition_handle(outer_name, "11", true);
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let outer_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
        );
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(outer_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(closed_outer_sandbox(outer_name)),
            )
            .mount(&server)
            .await;
        let mut released = serde_json::to_value(&lease).unwrap();
        released["status"]["phase"] = "Released".into();
        Mock::given(method("PATCH"))
            .and(path(child_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(released))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reconcile_lease(Arc::new(lease), ctx).await.unwrap(),
            Action::requeue(std::time::Duration::from_secs(1))
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            !requests
                .iter()
                .any(|request| request.url.path().contains("/clusterinstances"))
        );
        let patch = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_status_path
            })
            .expect("Released patch");
        let operations: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/status/phase"
                && operation["value"] == "Pending"
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status" && operation["value"]["phase"] == "Released"
        }));
    }

    /// Replica A can persist an intent and reserve an instance while replica B
    /// closes the outer lease. Finalization re-runs the consumer gate after its
    /// fresh GET, cannot publish `Bound`, and immediately moves the exact
    /// reciprocal reservation to Recycling so no child-pool slot is stranded.
    #[tokio::test]
    async fn finalize_binding_recycles_a_composition_closed_after_intent() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let mut lease = delayed_sandbox_composition_handle(outer_name, "12", false);
        lease.metadata.owner_references = Some(Vec::new());
        let binding = exact_test_binding(&lease.name_any(), "late-child-uid");
        lease.status.as_mut().unwrap().binding = Some(binding.clone());
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";
        let instance_status_path = format!("{instance_path}/status");
        let outer_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
        );
        Mock::given(method("GET"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(outer_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(closed_outer_sandbox(outer_name)),
            )
            .mount(&server)
            .await;
        let instance = exact_instance_for_binding(Some(&binding), "Leased");
        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&instance))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(instance_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&instance))
            .expect(1)
            .mount(&server)
            .await;
        let mut fenced = serde_json::to_value(&lease).unwrap();
        fenced["metadata"]["ownerReferences"] = serde_json::json!([]);
        fenced["metadata"]["labels"]
            [crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL] = "true".into();
        fenced["metadata"]["annotations"] = serde_json::json!({
            crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION: outer_name,
            crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION: "late-outer-uid",
            crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION:
                (chrono::Utc::now() + chrono::Duration::days(8)).to_rfc3339(),
        });
        fenced["metadata"]["finalizers"] = serde_json::json!([
            crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
        ]);
        Mock::given(method("PATCH"))
            .and(path(child_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&fenced))
            .expect(1)
            .mount(&server)
            .await;
        fenced["status"]["phase"] = "Released".into();
        Mock::given(method("PATCH"))
            .and(path(child_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(fenced))
            .expect(1)
            .mount(&server)
            .await;

        let bound = finalize_binding(&ctx, "test-ns", &binding, chrono::Utc::now())
            .await
            .expect("the exact stale reservation must be recycled");
        assert!(!bound, "a closed composition must not become Bound");
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method == http::Method::PATCH && request.url.path() == child_status_path
                })
                .count(),
            1,
            "a closed composition must never publish Bound"
        );
        let requests = server.received_requests().await.unwrap_or_default();
        let released = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_status_path
            })
            .expect("Released handle patch");
        let released: serde_json::Value = serde_json::from_slice(&released.body).unwrap();
        assert!(released.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status" && operation["value"]["phase"] == "Released"
        }));
        assert!(!released.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status" && operation["value"]["phase"] == "Bound"
        }));
        let recycle = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == instance_status_path
            })
            .expect("exact instance recycle patch");
        let operations: serde_json::Value = serde_json::from_slice(&recycle.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status/phase" && operation["value"] == "Recycling"
        }));
    }

    #[tokio::test]
    async fn finalize_binding_recycles_authority_mismatch_without_publishing_bound() {
        let (ctx, server) = test_lease_context().await;
        let outer_name = "late-outer";
        let mut lease = authorized_sandbox_composition_handle(outer_name, "40");
        let mut binding = exact_test_binding(&lease.name_any(), "late-child-uid");
        binding.pool = ResourceRef {
            name: "child-pool".into(),
            uid: Some("child-pool-uid-b".into()),
        };
        lease.status.as_mut().unwrap().binding = Some(binding.clone());
        let child_path = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
            lease.name_any()
        );
        let child_status_path = format!("{child_path}/status");
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";
        let instance_status_path = format!("{instance_path}/status");
        Mock::given(method("GET"))
            .and(path(child_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{outer_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(open_outer_sandbox(outer_name)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/child-pool",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(child_cluster_pool("child-pool-uid-a", 3)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{}",
                crate::controllers::sandbox::allocation_fence_name(outer_name)
            )))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "leases",
                    "sandbox-allocation-late-outer",
                )),
            )
            .mount(&server)
            .await;
        let instance = exact_instance_for_binding(Some(&binding), "Leased");
        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&instance))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(instance_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&instance))
            .expect(1)
            .mount(&server)
            .await;
        let mut quarantined = lease.clone();
        quarantined.status.as_mut().unwrap().phase = LeasePhase::Quarantined;
        Mock::given(method("PATCH"))
            .and(path(child_status_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(quarantined))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !finalize_binding(&ctx, "test-ns", &binding, chrono::Utc::now())
                .await
                .unwrap()
        );
        let requests = server.received_requests().await.unwrap_or_default();
        let lease_patch = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == child_status_path
            })
            .expect("quarantine status patch");
        let operations: serde_json::Value = serde_json::from_slice(&lease_patch.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status" && operation["value"]["phase"] == "Quarantined"
        }));
        assert!(!operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status" && operation["value"]["phase"] == "Bound"
        }));
        let recycle = requests
            .iter()
            .find(|request| {
                request.method == http::Method::PATCH && request.url.path() == instance_status_path
            })
            .expect("instance recycle patch");
        let operations: serde_json::Value = serde_json::from_slice(&recycle.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["path"] == "/status/phase" && operation["value"] == "Recycling"
        }));
    }

    #[tokio::test]
    async fn already_bound_legacy_composition_remains_recoverable_without_authority() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = authorized_sandbox_composition_handle("late-outer", "50");
        lease.status.as_mut().unwrap().phase = LeasePhase::Bound;
        let binding = exact_test_binding(&lease.name_any(), "late-child-uid");
        lease.status.as_mut().unwrap().binding = Some(binding.clone());
        let mut legacy_outer = open_outer_sandbox("late-outer");
        legacy_outer["spec"]
            .as_object_mut()
            .unwrap()
            .remove("placementAuthority");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/late-outer",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(legacy_outer))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            sandbox_composition_finalization_is_authorized(
                &ctx,
                "test-ns",
                &Api::namespaced(ctx.client.clone(), "test-ns"),
                &lease,
                &binding,
                true,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            1
        );
    }

    /// A lost status response must be retryable, and the recovered write must
    /// carry a durable NeverBound condition plus the exact attempt/timestamp
    /// token that the outer Sandbox later ACKs.
    #[tokio::test]
    async fn never_bound_proof_survives_a_lost_response_and_restart() {
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = delayed_sandbox_composition_handle("late-outer", "20", true);
        lease
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .remove(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION);
        lease.status.as_mut().unwrap().phase = LeasePhase::Released;
        lease.status.as_mut().unwrap().teardown_attempt_id = Some("attempt-1".into());
        let path_value = format!(
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}/status",
            lease.name_any()
        );
        Mock::given(method("PATCH"))
            .and(path(path_value.clone()))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 500,
                "reason": "InternalError"
            })))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(path_value.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lease))
            .expect(1)
            .with_priority(10)
            .mount(&server)
            .await;
        let leases: Api<ClusterLease> = Api::namespaced(client, "test-ns");
        let status = lease.status.as_ref().unwrap();
        let attempt = "attempt-1";
        let verified_at = "2026-01-01T00:00:00Z";

        assert!(
            record_unbound_release_proof(&leases, &lease, status, attempt, verified_at)
                .await
                .is_err()
        );
        record_unbound_release_proof(&leases, &lease, status, attempt, verified_at)
            .await
            .expect("retry after a lost response");

        let requests = server.received_requests().await.unwrap_or_default();
        let successful_retry: serde_json::Value =
            serde_json::from_slice(&requests.last().unwrap().body).unwrap();
        let operations = successful_retry.as_array().unwrap();
        let verified_at = operations
            .iter()
            .find(|operation| operation["path"] == "/status/unboundReleaseVerifiedAt")
            .and_then(|operation| operation["value"].as_str())
            .expect("durable proof timestamp")
            .to_string();
        let conditions = operations
            .iter()
            .find(|operation| operation["path"] == "/status/conditions")
            .map(|operation| operation["value"].clone())
            .expect("durable proof condition");
        let mut restarted = status.clone();
        restarted.unbound_release_verified_at = Some(verified_at);
        restarted.conditions = serde_json::from_value(conditions).unwrap();
        assert!(unbound_release_proof_is_complete(&restarted));
        assert_eq!(
            unbound_release_acknowledgement_token(&restarted),
            restarted
                .unbound_release_verified_at
                .as_ref()
                .map(|verified_at| format!("attempt-1:{verified_at}"))
        );
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "20"
        }));
    }

    #[test]
    fn stale_rejection_is_consumable_only_with_the_complete_retention_identity() {
        let exact = delayed_sandbox_composition_handle("late-outer", "20", true);
        assert!(stale_sandbox_composition_was_rejected(&exact));

        let mut missing_finalizer = exact.clone();
        missing_finalizer.metadata.finalizers = None;
        assert!(!stale_sandbox_composition_was_rejected(&missing_finalizer));

        let mut foreign_name = exact.clone();
        foreign_name.metadata.name = Some("kobe-sbx-someone-else".into());
        assert!(!stale_sandbox_composition_was_rejected(&foreign_name));

        let mut gc_dependent = exact;
        gc_dependent.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "SandboxLease".into(),
                name: "late-outer".into(),
                uid: "late-outer-uid".into(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        assert!(!stale_sandbox_composition_was_rejected(&gc_dependent));
    }

    /// Build a minimal `ClusterPool` JSON value for K8s API responses.
    fn make_test_profile() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "test-profile",
                "namespace": "test-ns",
                "uid": "test-profile-uid",
                "resourceVersion": "20"
            },
            "spec": {
                "size": 3,
                "ttl": "2h",
                "backend": { "type": "k3s" },
                "cluster": {
                    "version": "v1.31.3+k3s1"
                }
            }
        })
    }

    fn current_test_profile_spec_hash() -> String {
        let pool: ClusterPool = serde_json::from_value(make_test_profile()).unwrap();
        profile_spec_hash(&pool, &RenderContext::from_env(), &Default::default(), None)
    }

    fn bindable_instance_json(name: &str, spec_hash: &str) -> serde_json::Value {
        let backend =
            BackendProvenance::from_config(&crate::crd::BackendConfig::default()).unwrap();
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
                "resourceVersion": "20",
                "generation": 1,
                "labels": { "kobe.kunobi.ninja/pool": "test-profile" },
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "test-profile",
                    "uid": "test-profile-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
            "status": {
                "phase": "Ready",
                "provisioned": true,
                "leaseRef": null,
                "specHash": spec_hash,
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "test-profile-uid",
                    "backend": backend
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // error_policy
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn error_policy_backs_off_exponentially_per_lease() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("err-lease", "Pending");
        let error = || LeaseError::Lifecycle(anyhow::anyhow!("test error"));
        let delays: Vec<Action> = (0..3)
            .map(|_| error_policy(lease.clone(), &error(), ctx.clone()))
            .collect();
        assert_eq!(
            delays,
            vec![
                Action::requeue(std::time::Duration::from_secs(2)),
                Action::requeue(std::time::Duration::from_secs(4)),
                Action::requeue(std::time::Duration::from_secs(8)),
            ]
        );

        // Another lease starts its own count.
        let other = make_test_lease("other-lease", "Pending");
        assert_eq!(
            error_policy(other, &error(), ctx.clone()),
            Action::requeue(ERROR_BACKOFF_BASE)
        );
    }

    #[test]
    fn error_backoff_caps_at_the_maximum() {
        assert_eq!(error_backoff(1), ERROR_BACKOFF_BASE);
        assert_eq!(error_backoff(9), ERROR_BACKOFF_MAX);
        assert_eq!(error_backoff(u32::MAX), ERROR_BACKOFF_MAX);
    }

    #[tokio::test]
    async fn error_policy_retries_a_few_conflicts_fast_then_backs_off() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("conflict-lease", "Pending");
        let conflict = LeaseError::Kube(api_error(409, "Conflict", vec![]));
        for _ in 0..FAST_CONFLICT_RETRIES {
            assert_eq!(
                error_policy(lease.clone(), &conflict, ctx.clone()),
                Action::requeue(CONFLICT_RETRY)
            );
        }
        // Conflicts that keep coming point at a lagging store; they must not
        // retry every second until the watch recovers.
        assert_eq!(
            error_policy(lease.clone(), &conflict, ctx.clone()),
            Action::requeue(ERROR_BACKOFF_BASE)
        );
        assert_eq!(
            error_policy(lease, &conflict, ctx),
            Action::requeue(ERROR_BACKOFF_BASE * 2)
        );
    }

    // -----------------------------------------------------------------------
    // remove_from_queue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_remove_from_queue() {
        let queues = RwLock::new(HashMap::new());
        {
            let mut q = queues.write().await;
            q.insert(
                "test-profile".to_string(),
                vec![
                    PendingLease {
                        lease_name: "lease-a".to_string(),
                        priority: 100,
                        created_at: chrono::Utc::now(),
                    },
                    PendingLease {
                        lease_name: "lease-b".to_string(),
                        priority: 50,
                        created_at: chrono::Utc::now(),
                    },
                ],
            );
        }

        remove_from_queue(&queues, "test-profile", "lease-a").await;

        let q = queues.read().await;
        let queue = q.get("test-profile").unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].lease_name, "lease-b");
    }

    /// A lease that disappears while `Pending` must leave the in-memory
    /// priority queue with it.
    ///
    /// Every other eviction site needs a live lease to reconcile, so a
    /// hard `DELETE` (kubectl, owner GC, or the loser of a create race)
    /// used to strand its entry forever. That is not a leak so much as a
    /// deadlock: the queue sorts oldest-first within a priority, so the
    /// ghost sits at the head, every later lease for the pool computes
    /// `is_head == false`, and nothing in that pool can bind again until
    /// the operator restarts — `rebuild_queues` runs only at startup and
    /// only inserts.
    #[tokio::test]
    async fn disappeared_pending_lease_is_evicted_from_the_queue() {
        let (ctx, server) = test_lease_context().await;

        // The ghost, plus a real lease queued behind it.
        {
            let mut q = ctx.queues.write().await;
            q.insert(
                "test-profile".to_string(),
                vec![
                    PendingLease {
                        lease_name: "ghost-1".to_string(),
                        priority: 50,
                        created_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                    },
                    PendingLease {
                        lease_name: "real-1".to_string(),
                        priority: 50,
                        created_at: chrono::Utc::now(),
                    },
                ],
            );
        }

        // A cached object carrying a resourceVersion, so the reconciler
        // re-reads it from the apiserver — which is where it learns the
        // lease is gone.
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "ghost-1",
                    "namespace": "test-ns",
                    "resourceVersion": "42"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "user@test.com" },
                    "priority": 50
                },
                "status": { "phase": "Pending" }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/ghost-1",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("clusterleases", "ghost-1")),
            )
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::await_change());

        let queues = ctx.queues.read().await;
        let queue = queues
            .get("test-profile")
            .expect("pool queue still present");
        assert!(
            !queue.iter().any(|p| p.lease_name == "ghost-1"),
            "deleted lease must not remain queued — it would block the pool head forever"
        );
        assert_eq!(
            queue.first().map(|p| p.lease_name.as_str()),
            Some("real-1"),
            "the lease behind the ghost must become head and be able to bind"
        );
    }

    /// The reaper sweep is what actually un-wedges a pool after a lease
    /// is deleted outside a reconcile.
    ///
    /// `reconcile_lease`'s 404 branch cannot do it: kube-runtime drives
    /// the controller from `applied_objects()` (Deleted events dropped),
    /// and requeues resolve through the reflector store, so a
    /// `kubectl delete` of a queued lease produces no reconcile at all.
    /// Only a sweep against a live LIST sees the ghost.
    #[test]
    fn prune_evicts_queue_entries_with_no_live_pending_lease() {
        let mut queues: HashMap<String, Vec<PendingLease>> = HashMap::new();
        let at = |mins: i64| chrono::Utc::now() - chrono::Duration::minutes(mins);
        queues.insert(
            "pool-a".to_string(),
            vec![
                // Deleted out from under us — oldest, so it holds the head.
                PendingLease {
                    lease_name: "ghost".into(),
                    priority: 50,
                    created_at: at(10),
                },
                PendingLease {
                    lease_name: "real".into(),
                    priority: 50,
                    created_at: at(1),
                },
            ],
        );
        // A second pool proves the sweep is not scoped to one queue —
        // the reconcile path only ever knew about a lease's own pool.
        queues.insert(
            "pool-b".to_string(),
            vec![PendingLease {
                lease_name: "stale-elsewhere".into(),
                priority: 50,
                created_at: at(5),
            }],
        );

        let live: std::collections::HashSet<String> = ["real".to_string()].into_iter().collect();
        let mut evicted = prune_queues_against_live(&mut queues, &live);
        evicted.sort();

        assert_eq!(
            evicted,
            vec!["ghost".to_string(), "stale-elsewhere".to_string()]
        );
        assert_eq!(
            queues["pool-a"]
                .iter()
                .map(|p| p.lease_name.as_str())
                .collect::<Vec<_>>(),
            vec!["real"],
            "the surviving lease must become head and be able to bind"
        );
        assert!(queues["pool-b"].is_empty());
    }

    /// A pool whose queue is entirely live must be left alone — the
    /// sweep must not churn the common case.
    #[test]
    fn prune_leaves_a_fully_live_queue_untouched() {
        let mut queues: HashMap<String, Vec<PendingLease>> = HashMap::new();
        queues.insert(
            "pool-a".to_string(),
            vec![
                PendingLease {
                    lease_name: "a".into(),
                    priority: 50,
                    created_at: chrono::Utc::now(),
                },
                PendingLease {
                    lease_name: "b".into(),
                    priority: 10,
                    created_at: chrono::Utc::now(),
                },
            ],
        );
        let live: std::collections::HashSet<String> =
            ["a".to_string(), "b".to_string()].into_iter().collect();

        let evicted = prune_queues_against_live(&mut queues, &live);

        assert!(evicted.is_empty());
        assert_eq!(queues["pool-a"].len(), 2);
    }

    #[tokio::test]
    async fn test_remove_from_queue_nonexistent_profile() {
        let queues = RwLock::new(HashMap::new());
        // Should not panic when profile does not exist.
        remove_from_queue(&queues, "no-such-profile", "lease-x").await;
        assert!(queues.read().await.is_empty());
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Pending — no ready clusters
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_pending_lease_no_ready_clusters() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("pending-1", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/pending-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.as_ref()))
            .mount(&server)
            .await;

        // Mock the status PATCH that the reconciler issues to update queue position.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/pending-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "pending-1", "namespace": "test-ns", "uid": "pending-1-uid", "resourceVersion": "11" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Pending", "queuePosition": 1 }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (return 404 — no profile, so no queue timeout logic).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "clusterpools",
                    "test-profile",
                )),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        // No ready cluster: the instance watch wakes it when one appears.
        assert_eq!(action, Action::requeue(PENDING_BACKSTOP));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Pending — queue timeout expiry (#233)
    //
    // Both pool shapes are exercised against the SAME helper so a
    // regression that special-cases one of them (e.g. re-adding the old
    // `scaling.is_some()` guard) fails both tests identically instead of
    // leaving the untested shape silently broken again.
    // -----------------------------------------------------------------------

    /// Drives a Pending lease, created `age` ago, through one reconcile
    /// against `pool_spec_extra` merged into a minimal `ClusterPool` spec.
    /// Returns the requeue `Action` and the pre/post `LEASE_QUEUE_WAIT_SECONDS{expired}`
    /// sample counts so callers can assert the metric moved.
    ///
    /// `pool_name` must be unique per caller (not just per test file): the
    /// metric is a real global `LazyLock` registry shared by every test
    /// binary-wide, and `cargo test` runs tests concurrently, so two cases
    /// sharing a pool name would race on the same before/after sample count.
    async fn run_queue_timeout_case(
        pool_name: &str,
        age: chrono::Duration,
        pool_spec_extra: serde_json::Value,
    ) -> (Action, u64, u64) {
        let (ctx, server) = test_lease_context().await;
        let lease_name = format!("{pool_name}-lease");
        let created_at = (chrono::Utc::now() - age).to_rfc3339();
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": lease_name,
                    "namespace": "test-ns",
                    "uid": format!("{lease_name}-uid"),
                    "resourceVersion": "10",
                    "creationTimestamp": created_at,
                },
                "spec": {
                    "poolRef": pool_name,
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": { "phase": "Pending", "queuePosition": 1 }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{lease_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.as_ref()))
            .mount(&server)
            .await;

        let mut pool_spec = serde_json::json!({
            "size": 3,
            "ttl": "2h",
            "backend": { "type": "k3s" },
            "cluster": { "version": "v1.31.3+k3s1" }
        });
        for (key, value) in pool_spec_extra.as_object().unwrap() {
            pool_spec[key] = value.clone();
        }
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/{pool_name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "metadata": { "name": pool_name, "namespace": "test-ns", "uid": format!("{pool_name}-uid"), "resourceVersion": "20" },
                "spec": pool_spec
            })))
            .mount(&server)
            .await;

        // One route serves both status writes reconcile_lease issues for an
        // expiring Pending lease: the queue-position write, then (once the
        // timeout check trips) expire_lease_fenced's phase→Expired write.
        // Routing on the patch body — rather than mount order — keeps this
        // independent of wiremock's match-priority rules for two mocks on
        // the same method+path.
        let lease_name_for_patch = lease_name.clone();
        let pool_name_owned = pool_name.to_string();
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{lease_name}/status"
            )))
            .respond_with(move |request: &wiremock::Request| {
                let ops: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("status patch JSON");
                let expiring = ops.as_array().unwrap().iter().any(|op| {
                    op["path"] == "/status" && op["value"]["phase"] == "Expired"
                });
                let status = if expiring {
                    serde_json::json!({ "phase": "Expired" })
                } else {
                    serde_json::json!({ "phase": "Pending", "queuePosition": 1 })
                };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterLease",
                    "metadata": { "name": lease_name_for_patch, "namespace": "test-ns",
                                  "uid": format!("{lease_name_for_patch}-uid"), "resourceVersion": "11" },
                    "spec": { "poolRef": pool_name_owned, "ttl": "1h",
                               "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                    "status": status
                }))
            })
            .mount(&server)
            .await;

        let before = crate::metrics::LEASE_QUEUE_WAIT_SECONDS
            .with_label_values(&[pool_name, "expired"])
            .get_sample_count();

        let action = reconcile_lease(lease, ctx).await.unwrap();

        let after = crate::metrics::LEASE_QUEUE_WAIT_SECONDS
            .with_label_values(&[pool_name, "expired"])
            .get_sample_count();

        (action, before, after)
    }

    /// #233: a fixed-size pool (no `scaling` block) previously had no queue
    /// timeout at all — a lease past `spec.queue_timeout` must still expire.
    #[tokio::test]
    async fn test_reconcile_pending_lease_expires_on_fixed_size_pool_queue_timeout() {
        let (action, before, after) = run_queue_timeout_case(
            "queue-timeout-fixed-pool",
            chrono::Duration::minutes(2),
            serde_json::json!({ "queueTimeout": "1m" }),
        )
        .await;

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(
            after,
            before + 1,
            "expired queue-wait metric should record for a fixed-size pool"
        );
    }

    /// Same expiry path for an autoscaled pool, to prove the fix did not
    /// regress the pre-existing `scaling.queue_timeout` behavior.
    #[tokio::test]
    async fn test_reconcile_pending_lease_expires_on_scaling_pool_queue_timeout() {
        let (action, before, after) = run_queue_timeout_case(
            "queue-timeout-scaling-pool",
            chrono::Duration::minutes(2),
            serde_json::json!({
                "scaling": {
                    "minReady": 1,
                    "maxClusters": 8,
                    "scaleDownAfter": "5m",
                    "queueTimeout": "1m",
                    "creatingTimeout": "10m"
                }
            }),
        )
        .await;

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(
            after,
            before + 1,
            "expired queue-wait metric should record for a scaling pool"
        );
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Pending — binds to a ready cluster
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reservation_writes_uid_fenced_pair_for_ready_cluster() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("bind-1", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());
        let backend =
            BackendProvenance::from_config(&crate::crd::BackendConfig::default()).unwrap();
        let ready_instance = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "pool-test-1",
                "namespace": "test-ns",
                "uid": "instance-uid",
                "resourceVersion": "20",
                "generation": 1,
                "labels": { "kobe.kunobi.ninja/pool": "test-profile" },
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "test-profile",
                    "uid": "test-profile-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
            "status": {
                "phase": "Ready",
                "provisioned": true,
                "leaseRef": null,
                "specHash": "0000000000000001",
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "test-profile-uid",
                    "backend": backend
                }
            }
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![ready_instance.clone()]),
            ))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready_instance.clone()))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": { "name": "pool-test-1", "namespace": "test-ns", "uid": "instance-uid", "resourceVersion": "21", "generation": 1 },
                "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
                "status": { "phase": "Leased", "provisioned": true }
            })))
            .mount(&server)
            .await;

        let intent_response = std::sync::Arc::new(std::sync::Mutex::new(None));
        let intent_response_for_patch = intent_response.clone();
        let lease_for_response = (*lease).clone();
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-1/status",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("lease intent JSON Patch");
                let binding = operations
                    .as_array()
                    .and_then(|operations| {
                        operations.iter().find(|operation| {
                            operation["op"] == "add" && operation["path"] == "/status/binding"
                        })
                    })
                    .map(|operation| operation["value"].clone())
                    .expect("intent patch carries binding");
                let mut response = serde_json::to_value(&lease_for_response).unwrap();
                response["metadata"]["resourceVersion"] = "11".into();
                response["status"]["binding"] = binding;
                *intent_response_for_patch.lock().unwrap() = Some(response.clone());
                ResponseTemplate::new(200).set_body_json(response)
            })
            .expect(1)
            .mount(&server)
            .await;
        let intent_response_for_get = intent_response.clone();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-1",
            ))
            .respond_with(move |_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(
                    intent_response_for_get
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("intent PATCH precedes lease fence GET"),
                )
            })
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;

        let binding = reserve_ready_instance(&ctx.client, "test-ns", &lease, None, 0)
            .await
            .unwrap()
            .expect("ready instance should be reserved");
        assert_eq!(binding.lease.uid.as_deref(), Some("bind-1-uid"));
        assert_eq!(binding.instance.uid, "instance-uid");
        assert_eq!(binding.instance.observed_generation, 1);
        assert_eq!(binding.pool.uid.as_deref(), Some("test-profile-uid"));

        let requests = server.received_requests().await.unwrap();
        let patches: Vec<serde_json::Value> = requests
            .iter()
            .filter(|request| request.method == http::Method::PATCH)
            .filter_map(|request| serde_json::from_slice(&request.body).ok())
            .collect();
        assert!(
            patches
                .iter()
                .any(|patch| patch.as_array().is_some_and(|ops| {
                    ops.iter().any(|op| op["path"] == "/metadata/uid")
                        && ops
                            .iter()
                            .any(|op| op["path"] == "/metadata/resourceVersion")
                        && ops.iter().any(|op| op["path"] == "/status/binding")
                }))
        );
    }

    /// #234: a new lease must take the current-template member even when a
    /// stale Ready member sorts first by name.
    #[tokio::test]
    async fn reserve_ready_instance_binds_the_current_template_member_ahead_of_a_stale_one() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("bind-current", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());
        let current_hash = current_test_profile_spec_hash();
        let stale = bindable_instance_json("aaa-stale", "ffffffffffffffff");
        let current = bindable_instance_json("zzz-current", &current_hash);

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![stale.clone(), current.clone()]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/zzz-current",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(current.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/zzz-current/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": "zzz-current",
                    "namespace": "test-ns",
                    "uid": "zzz-current-uid",
                    "resourceVersion": "21",
                    "generation": 1
                },
                "spec": { "poolRef": { "name": "test-profile", "uid": "test-profile-uid" } },
                "status": { "phase": "Leased", "provisioned": true }
            })))
            .mount(&server)
            .await;

        let intent_response = std::sync::Arc::new(std::sync::Mutex::new(None));
        let intent_response_for_patch = intent_response.clone();
        let lease_for_response = (*lease).clone();
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-current/status",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("lease intent JSON Patch");
                let binding = operations
                    .as_array()
                    .and_then(|operations| {
                        operations.iter().find(|operation| {
                            operation["op"] == "add" && operation["path"] == "/status/binding"
                        })
                    })
                    .map(|operation| operation["value"].clone())
                    .expect("intent patch carries binding");
                let mut response = serde_json::to_value(&lease_for_response).unwrap();
                response["metadata"]["resourceVersion"] = "11".into();
                response["status"]["binding"] = binding;
                *intent_response_for_patch.lock().unwrap() = Some(response.clone());
                ResponseTemplate::new(200).set_body_json(response)
            })
            .expect(1)
            .mount(&server)
            .await;
        let intent_response_for_get = intent_response.clone();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-current",
            ))
            .respond_with(move |_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(
                    intent_response_for_get
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("intent PATCH precedes lease fence GET"),
                )
            })
            .expect(1)
            .mount(&server)
            .await;

        let binding = reserve_ready_instance(&ctx.client, "test-ns", &lease, None, 0)
            .await
            .unwrap()
            .expect("current-template instance should be reserved");
        assert_eq!(
            binding.instance.name, "zzz-current",
            "stale aaa-stale sorts first by name and must still lose to the current member"
        );
        assert_eq!(binding.instance.uid, "zzz-current-uid");
    }

    #[tokio::test]
    async fn test_reconcile_returns_quickly_when_same_lease_is_already_in_progress() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("duplicate-1", "Pending");

        ctx.active_reconciles
            .lock()
            .expect("active reconciles lock")
            .insert("duplicate-1".to_string());

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn test_reconcile_stale_pending_event_uses_fresh_bound_state() {
        let (ctx, server) = test_lease_context().await;
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "stale-1",
                    "namespace": "test-ns",
                    "resourceVersion": "1"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Pending",
                    "queuePosition": 1,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/stale-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "stale-1",
                    "namespace": "test-ns",
                    "resourceVersion": "2"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "boundAt": chrono::Utc::now().to_rfc3339(),
                    "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "queuePosition": 0,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn ambiguous_legacy_name_only_binding_stays_unavailable() {
        let (ctx, server) = test_lease_context().await;
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "repair-1",
                    "namespace": "test-ns",
                    "uid": "repair-1-uid",
                    "resourceVersion": "1"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Pending",
                    "clusterName": "pool-test-1",
                    "boundAt": chrono::Utc::now().to_rfc3339(),
                    "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "queuePosition": 1,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/repair-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "repair-1",
                    "namespace": "test-ns",
                    "uid": "repair-1-uid",
                    "resourceVersion": "1"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Pending",
                    "clusterName": "pool-test-1",
                    "boundAt": chrono::Utc::now().to_rfc3339(),
                    "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "queuePosition": 1,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/repair-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "repair-1", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "queuePosition": 0,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Bound — not expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_bound_lease_not_expired() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("bound-1", "Bound");
        // The helper already sets expires_at to now + 1h.

        let action = reconcile_lease(lease, ctx).await.unwrap();
        // Not expired → requeue at 30s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Bound — expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_bound_lease_expired() {
        let (ctx, server) = test_lease_context().await;

        // Build a Bound lease with expires_at in the past.
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "expired-1", "namespace": "test-ns", "uid": "expired-1-uid", "resourceVersion": "10" },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "expiresAt": past.to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/expired-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        // Mock PATCH for status update to Expired.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/expired-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "expired-1", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Expired" }
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Released — transitions to Recycling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_released_lease() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("released-1", "Released");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/released-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        // Mock PATCH for status update to Recycling.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/released-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "released-1", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Recycling", "clusterName": "pool-test-1" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": { "name": "pool-test-1", "namespace": "test-ns" },
                "spec": { "poolRef": { "name": "test-profile" } },
                "status": { "phase": "Recycling", "provisioned": true, "leaseRef": null }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (for diagnostics check — return profile with no diagnostics).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/released-1-connect-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "released-1-connect-token",
                    "namespace": "test-ns",
                    "uid": "secret-uid",
                    "resourceVersion": "5",
                    "ownerReferences": [{
                        "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                        "kind": "ClusterLease",
                        "name": "released-1",
                        "uid": "released-1-uid"
                    }]
                },
                "data": { "token": "dG9rZW4=" }
            })))
            .mount(&server)
            .await;

        // The exact owner-fenced connect-token Secret is explicitly deleted.
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/released-1-connect-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "released-1-connect-token", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
        let calls = ctx.backend.call_count();
        assert_eq!(calls.delete, 0);
    }

    /// Build an Expired lease that names nothing: no binding, no clusterName.
    ///
    /// This is the shape that accumulated on int-pro (#150) — a lease whose TTL
    /// ran out while it was still sitting in the queue, so it never held
    /// capacity.
    fn make_never_bound_expired_lease(name: &str) -> Arc<ClusterLease> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "uid": format!("{name}-uid"),
                    "resourceVersion": "10"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "user@test.com" },
                    "priority": 50
                },
                "status": {
                    "phase": "Expired",
                    "queuePosition": 2,
                    "extensionsCount": 0,
                    "maxExtensions": 2,
                    "message": BINDING_UNVERIFIED_MESSAGE
                }
            }))
            .unwrap(),
        )
    }

    /// A lease that expired while still queued must be retired, not retried
    /// forever.
    ///
    /// It never held capacity: no binding was recorded and no clusterName was
    /// ever written, so there is no instance to recycle and none to quarantine.
    /// Before #150 this returned `requeue(30s)` unconditionally, so every such
    /// lease re-reconciled every 30 seconds for as long as the cluster lived —
    /// 75 of them on int-pro, for two days, emitting ~216k WARN lines/day and
    /// drowning the genuine `binding_missing` signal this same message carries
    /// for live leases.
    ///
    /// Asserting `await_change()` rather than any requeue duration is the point:
    /// the object is gone, so there is nothing left to come back to.
    #[tokio::test]
    async fn expired_lease_that_never_bound_is_retired_not_retried() {
        let (ctx, server) = test_lease_context().await;
        let lease = make_never_bound_expired_lease("never-bound-1");

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/never-bound-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        // The connect-token Secret lookup happens before binding resolution.
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/never-bound-1-connect-token",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;

        // The lease CRD itself is deleted — this is the assertion that fails
        // against the pre-#150 code, which only ever patched status.
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/never-bound-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .expect(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(
            action,
            Action::await_change(),
            "a retired lease must not be requeued — the object no longer exists"
        );
        assert_eq!(ctx.backend.call_count().delete, 0);
    }

    /// Retirement must be reachable ONLY when the lease names nothing.
    ///
    /// A terminal lease carrying `clusterName` but no binding is the legacy
    /// pre-UID-fence shape: a controller may have crashed after writing just the
    /// name, so an instance may still exist under it and this lease is the only
    /// pointer to it. Deleting it would discard the sole record of capacity that
    /// might still be running — the same reasoning that stops
    /// `backfill_legacy_binding` promoting a bare name to authority.
    ///
    /// This is the guard on #150's fix: it must not widen into "no binding
    /// resolved ⇒ delete".
    #[tokio::test]
    async fn terminal_lease_naming_a_cluster_is_never_retired() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_never_bound_expired_lease("legacy-named-1");
        {
            let lease = Arc::make_mut(&mut lease);
            let status = lease.status.as_mut().expect("fixture has status");
            status.cluster_name = Some("pool-test-1".to_string());
            // Not yet stamped, so the mark path does its one write.
            status.message = None;
        }

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/legacy-named-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/legacy-named-1-connect-token",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/legacy-named-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        // No DELETE is mounted: if the fix ever widens to cover this case, the
        // unmatched request fails the test rather than silently passing.
        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(
            action,
            Action::requeue(std::time::Duration::from_secs(30)),
            "a lease naming a cluster must keep waiting for a human, not be deleted"
        );
        assert_eq!(ctx.backend.call_count().delete, 0);
    }

    /// Recycling must survive the generation bump that deletion itself causes.
    ///
    /// The apiserver increments `metadata.generation` when it stamps
    /// `deletionTimestamp` on a finalizer-bearing object, so an instance whose
    /// delete is already in flight reads one generation ahead of the binding
    /// that named it. Requiring equality there judged the exact instance "not
    /// safe to recycle" on every pass, so the lease never observed recycling
    /// completion — the other half of the pool-exhaustion deadlock. Drift on a
    /// *live* instance is still refused.
    #[tokio::test]
    async fn deleting_instance_is_still_recyclable_despite_the_deletion_generation_bump() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");

        let mut deleting = exact_instance_for_binding(Some(&binding), "Recycling");
        deleting["metadata"]["deletionTimestamp"] = serde_json::json!("2026-01-01T00:00:00Z");
        deleting["metadata"]["finalizers"] =
            serde_json::json!(["kobe.kunobi.ninja/instance-cleanup"]);
        deleting["metadata"]["generation"] = serde_json::json!(2);

        let mut live_drift = exact_instance_for_binding(Some(&binding), "Recycling");
        live_drift["metadata"]["generation"] = serde_json::json!(2);

        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";
        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(deleting))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(live_drift))
            .mount(&server)
            .await;

        assert!(
            mark_instance_recycling(&client, "test-ns", &binding)
                .await
                .unwrap(),
            "a deleting instance must still count as the exact recycle subject"
        );
        assert!(
            !mark_instance_recycling(&client, "test-ns", &binding)
                .await
                .unwrap(),
            "generation drift on a live instance stays fenced"
        );
    }

    /// A reciprocal binding survives a stale profile phase projection. Once
    /// release wins, that adopted instance must enter receipt-backed recycling
    /// rather than being treated as free or stranded in Ready.
    #[tokio::test]
    async fn exact_adopted_binding_recycles_even_if_phase_was_reverted_to_ready() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let binding = exact_test_binding("lease-a", "lease-a-uid");
        let ready = exact_instance_for_binding(Some(&binding), "Ready");
        let instance_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1";

        Mock::given(method("GET"))
            .and(path(instance_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{instance_path}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ready))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            mark_instance_recycling(&client, "test-ns", &binding)
                .await
                .unwrap()
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method == http::Method::PATCH)
            .expect("recycling patch");
        let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status/phase"
                && operation["value"] == "Recycling"
        }));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Recycling — cluster gone, lease deleted
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn legacy_recycling_lease_without_binding_is_not_deleted() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("recycling-1", "Recycling");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/recycling-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/recycling-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        // Pool state has NO entry for the cluster (it's gone).
        // (pools is already empty by default.)

        // Mock DELETE for the lease CRD.
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/recycling-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "recycling-1", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Recycling" }
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(RECYCLING_BACKSTOP));
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Recycling — cluster NOT gone, requeue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn legacy_recycling_lease_does_not_mutate_same_named_instance() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("recycling-2", "Recycling");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/recycling-2",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/recycling-2/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": { "name": "pool-test-1", "namespace": "test-ns" },
                "spec": { "poolRef": { "name": "test-profile" } },
                "status": { "phase": "Recycling", "provisioned": true, "leaseRef": null }
            })))
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        // Cluster still present: the instance watch reports its delete.
        assert_eq!(action, Action::requeue(RECYCLING_BACKSTOP));
    }

    // -----------------------------------------------------------------------
    // extend_lease_ttl: success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_lease_ttl_success() {
        let (ctx, server) = test_lease_context().await;

        // A resolvable policy is required to extend (fail-closed max-TTL ceiling).
        // max_ttl 4h comfortably covers bound_at + ~2h after the extension below.
        let policy: crate::crd::access_policy::AccessPolicy =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "AccessPolicy",
                "metadata": { "name": "test" },
                "spec": {
                    "auth": { "oidc": {
                        "issuer": "https://issuer.example.com",
                        "audience": ["test"],
                        "algorithms": ["RS256"]
                    }},
                    "rules": [{ "pools": ["*"], "maxTtl": "4h",
                                "maxConcurrentLeases": 5, "maxExtensions": 2 }]
                }
            }))
            .unwrap();
        ctx.authenticator
            .update_policies(vec![policy], std::collections::HashMap::new())
            .await;

        let future_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let bound_at = chrono::Utc::now() - chrono::Duration::minutes(30);

        // Mock GET for the lease.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/extend-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "extend-1", "namespace": "test-ns", "uid": "extend-1-uid", "resourceVersion": "10" },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "boundAt": bound_at.to_rfc3339(),
                    "expiresAt": future_expiry.to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        // Mock PATCH for extending the TTL.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/extend-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "extend-1", "namespace": "test-ns", "uid": "extend-1-uid", "resourceVersion": "10" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": {
                    "phase": "Bound",
                    "extensionsCount": 1
                }
            })))
            .mount(&server)
            .await;

        let result = extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "extend-1",
            "30m",
            "extend-1-uid",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_ok());
        // The returned string should be a valid RFC3339 timestamp.
        let new_expiry_str = result.unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(&new_expiry_str).is_ok());
    }

    /// Extension is a mutation, so it must carry the same UID fence every other
    /// cross-object write in #79 carries.
    ///
    /// Two holes without it:
    /// 1. **Name reuse.** The lease is read by name and patched by name. If it
    ///    is deleted and a same-named lease is recreated by another requester in
    ///    between, the merge patch silently extends the *new* owner's lease.
    /// 2. **Lost update.** `extensionsCount` is a read-modify-write; two
    ///    concurrent extends both read N and write N+1, so the pair costs one
    ///    extension and `maxExtensions` can be exceeded.
    ///
    /// Both close by patching under `test` ops on uid, resourceVersion, and the
    /// observed `extensionsCount`.
    #[tokio::test]
    async fn extend_is_uid_and_count_fenced() {
        let (ctx, server) = test_lease_context().await;
        let policy: crate::crd::access_policy::AccessPolicy =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "AccessPolicy",
                "metadata": { "name": "test" },
                "spec": {
                    "auth": { "oidc": {
                        "issuer": "https://issuer.example.com",
                        "audience": ["test"],
                        "algorithms": ["RS256"]
                    }},
                    "rules": [{ "pools": ["*"], "maxTtl": "4h",
                                "maxConcurrentLeases": 5, "maxExtensions": 2 }]
                }
            }))
            .unwrap();
        ctx.authenticator
            .update_policies(vec![policy], std::collections::HashMap::new())
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/extend-fence",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "extend-fence",
                    "namespace": "test-ns",
                    "uid": "extend-fence-uid",
                    "resourceVersion": "77"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "boundAt": (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339(),
                    "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/extend-fence/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "extend-fence", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                          "requester": {"type": "test", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Bound", "extensionsCount": 1 }
            })))
            .mount(&server)
            .await;

        extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "extend-fence",
            "30m",
            "extend-fence-uid",
            &ctx.authenticator,
        )
        .await
        .expect("extending the exact observed lease should succeed");

        let patch = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|req| req.method == http::Method::PATCH)
            .expect("extend must issue a status PATCH");
        assert_eq!(
            patch
                .headers
                .get("content-type")
                .map(|value| value.to_str().unwrap()),
            Some("application/json-patch+json"),
            "a merge patch cannot express a precondition; extend must use JSON Patch"
        );
        let ops: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        let tests: Vec<(&str, &serde_json::Value)> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|op| op["op"] == "test")
            .map(|op| (op["path"].as_str().unwrap(), &op["value"]))
            .collect();
        assert!(
            tests.contains(&("/metadata/uid", &serde_json::json!("extend-fence-uid"))),
            "extend must pin the exact lease UID, else a same-named replacement is extended: {tests:?}"
        );
        assert!(
            tests.contains(&("/metadata/resourceVersion", &serde_json::json!("77"))),
            "extend must pin the observed resourceVersion: {tests:?}"
        );
        assert!(
            tests.contains(&("/status/extensionsCount", &serde_json::json!(0))),
            "extend must pin the observed extensionsCount so concurrent extends cannot lose an increment: {tests:?}"
        );
    }

    /// A lease whose UID changed under us (name reuse) must not be extended.
    ///
    /// Every other gate is deliberately satisfied — resolvable policy, `Bound`
    /// phase, extensions remaining, and a PATCH mock that would return 200 — so
    /// the UID fence is the only thing that can produce the denial. Without
    /// that setup the test passes for the wrong reason (an unresolvable policy
    /// also yields `Lifecycle`) and stops detecting a dropped fence.
    #[tokio::test]
    async fn extend_denies_uid_mismatch() {
        let (ctx, server) = test_lease_context().await;
        let policy: crate::crd::access_policy::AccessPolicy =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "AccessPolicy",
                "metadata": { "name": "test" },
                "spec": {
                    "auth": { "oidc": {
                        "issuer": "https://issuer.example.com",
                        "audience": ["test"],
                        "algorithms": ["RS256"]
                    }},
                    "rules": [{ "pools": ["*"], "maxTtl": "4h",
                                "maxConcurrentLeases": 5, "maxExtensions": 2 }]
                }
            }))
            .unwrap();
        ctx.authenticator
            .update_policies(vec![policy], std::collections::HashMap::new())
            .await;
        // Would succeed if the fence were removed.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/reused/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "reused", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                          "requester": {"type": "test", "identity": "someone-else"},
                          "priority": 50 },
                "status": { "phase": "Bound", "extensionsCount": 1 }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/reused",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "reused",
                    "namespace": "test-ns",
                    // A different tenant recreated this name after we observed it.
                    "uid": "replacement-uid",
                    "resourceVersion": "1"
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test", "identity": "someone-else" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "boundAt": chrono::Utc::now().to_rfc3339(),
                    "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let err = extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "reused",
            "30m",
            "original-uid",
            &ctx.authenticator,
        )
        .await
        .expect_err("a replaced lease must not be extendable");
        assert!(
            matches!(err, LeaseError::Lifecycle(_)),
            "expected a lifecycle denial, got {err:?}"
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|req| req.method == http::Method::PATCH),
            "a UID mismatch must deny before any mutation"
        );
    }

    // -----------------------------------------------------------------------
    // extend_lease_ttl: fail-closed when the requester policy is unresolvable
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_lease_ttl_denied_without_policy() {
        // A Bound lease whose requester policy can no longer be resolved (e.g. the
        // AuthPolicy was renamed/removed) must not be extendable — there is no
        // max-TTL ceiling to enforce, so we deny rather than extend unbounded.
        let (ctx, server) = test_lease_context().await;
        // No policies configured on the authenticator.

        let future_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let bound_at = chrono::Utc::now() - chrono::Duration::minutes(30);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/extend-2",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "extend-2", "namespace": "test-ns", "uid": "extend-2-uid", "resourceVersion": "10" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                          "requester": {"type": "stale-provider:admin", "identity": "u"},
                          "priority": 50 },
                "status": {
                    "phase": "Bound", "clusterName": "pool-test-1",
                    "boundAt": bound_at.to_rfc3339(), "expiresAt": future_expiry.to_rfc3339(),
                    "extensionsCount": 0, "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let result = extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "extend-2",
            "30m",
            "extend-2-uid",
            &ctx.authenticator,
        )
        .await;
        assert!(
            result.is_err(),
            "extend must be denied when no policy resolves"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no policy resolves"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // extend_lease_ttl: wrong phase
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_lease_ttl_wrong_phase() {
        let (ctx, server) = test_lease_context().await;

        // Mock GET returning a lease in Pending phase.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/pending-ext",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "pending-ext", "namespace": "test-ns", "uid": "pending-ext-uid", "resourceVersion": "10" },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Pending",
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let result = extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "pending-ext",
            "30m",
            "pending-ext-uid",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not in Bound phase"),
            "Expected 'not in Bound phase' in error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // extend_lease_ttl: max extensions reached
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_lease_ttl_max_extensions_reached() {
        let (ctx, server) = test_lease_context().await;

        let future_expiry = chrono::Utc::now() + chrono::Duration::hours(1);

        // Mock GET returning a Bound lease with extensions_count == max_extensions.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/maxext-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "maxext-1", "namespace": "test-ns", "uid": "maxext-1-uid", "resourceVersion": "10" },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "expiresAt": future_expiry.to_rfc3339(),
                    "extensionsCount": 2,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let result = extend_lease_ttl(
            &ctx.client,
            "test-ns",
            "maxext-1",
            "30m",
            "maxext-1-uid",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Maximum extensions"),
            "Expected 'Maximum extensions' in error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // unsatisfiable_status: pool-health → message + reason classification (#189)
    // -----------------------------------------------------------------------

    fn pool_status(
        phase: Option<ClusterPoolPhase>,
        consecutive_failures: u32,
        last_failure_reason: Option<&str>,
    ) -> ClusterPoolStatus {
        ClusterPoolStatus {
            phase,
            consecutive_failures,
            last_failure_reason: last_failure_reason.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn unsatisfiable_status_classifies_failing_pool_as_exhausted() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let status = Some(pool_status(
            Some(ClusterPoolPhase::Failing),
            3,
            Some("server StatefulSet not reaching Ready"),
        ));
        let (msg, reason) = unsatisfiable_status("p", &status);
        assert_eq!(reason, R::PoolExhausted);
        assert!(msg.contains("phase=Failing"), "got: {msg}");
        assert!(msg.contains("consecutiveFailures=3"), "got: {msg}");
        assert!(
            msg.contains("lastFailureReason=server StatefulSet not reaching Ready"),
            "got: {msg}"
        );
    }

    #[test]
    fn unsatisfiable_status_classifies_backoff_as_capacity_blocked() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let status = Some(pool_status(Some(ClusterPoolPhase::Backoff), 1, None));
        let (_, reason) = unsatisfiable_status("p", &status);
        assert_eq!(reason, R::CapacityBlocked);
    }

    #[test]
    fn unsatisfiable_status_treats_healthy_and_missing_as_warming() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let healthy = Some(pool_status(Some(ClusterPoolPhase::Healthy), 0, None));
        assert_eq!(unsatisfiable_status("p", &healthy).1, R::Warming);
        // No status at all → warming (we won't assert exhaustion we can't prove).
        let (msg, reason) = unsatisfiable_status("p", &None);
        assert_eq!(reason, R::Warming);
        assert!(msg.contains("warming up"), "got: {msg}");
    }

    /// #338 made a pool with quarantined members and nothing Ready report
    /// `ScalingUp`. The tenant must not read that as warming up.
    #[test]
    fn unsatisfiable_status_blames_quarantine_whatever_the_phase() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        for phase in [
            Some(ClusterPoolPhase::ScalingUp),
            Some(ClusterPoolPhase::Healthy),
            Some(ClusterPoolPhase::Quarantined),
            Some(ClusterPoolPhase::Backoff),
            None,
        ] {
            let mut status = pool_status(phase, 0, None);
            status.quarantined = 2;
            let (msg, reason) = unsatisfiable_status("p", &Some(status));
            assert_eq!(reason, R::CapacityBlocked, "phase {phase:?}");
            assert!(msg.contains("blocked by quarantined members"), "got: {msg}");
            assert!(!msg.contains("warming"), "got: {msg}");
        }

        // Ready members still bind, so quarantine alone is not the story.
        let mut serving = pool_status(Some(ClusterPoolPhase::Quarantined), 0, None);
        serving.quarantined = 1;
        serving.ready = 1;
        assert_eq!(unsatisfiable_status("p", &Some(serving)).1, R::Degraded);

        // Sustained failure still wins, as in the API pre-flight.
        let mut failing = pool_status(Some(ClusterPoolPhase::Failing), 3, None);
        failing.quarantined = 1;
        assert_eq!(
            unsatisfiable_status("p", &Some(failing)).1,
            R::PoolExhausted
        );
    }

    #[test]
    fn unsatisfiable_status_explains_an_exhausted_pool() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let status = Some(pool_status(Some(ClusterPoolPhase::Exhausted), 0, None));
        let (msg, reason) = unsatisfiable_status("p", &status);
        assert_eq!(
            reason,
            R::AtCapacity,
            "normal exhaustion is not capacity_blocked"
        );
        assert!(msg.contains("every cluster leased"), "got: {msg}");
        assert!(msg.contains("phase=Exhausted"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Pending — no Ready cluster writes a status.message and
    // bumps kobe_lease_unsatisfiable_total (#189).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_pending_no_ready_writes_message_for_failing_pool() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = make_test_lease("unsat-1", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/unsat-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease.as_ref()))
            .mount(&server)
            .await;

        // queue-position + message PATCHes both target this /status path.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/unsat-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "unsat-1", "namespace": "test-ns", "uid": "unsat-1-uid", "resourceVersion": "11" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Pending", "queuePosition": 1 }
            })))
            .mount(&server)
            .await;

        // A Failing pool — the controller reads this to build the message.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "metadata": { "name": "test-profile", "namespace": "test-ns" },
                "spec": { "size": 3, "ttl": "2h", "cluster": { "version": "v1.31.3+k3s1" } },
                "status": {
                    "phase": "Failing",
                    "consecutiveFailures": 4,
                    "lastFailureReason": "server StatefulSet not reaching Ready"
                }
            })))
            .mount(&server)
            .await;

        // No Ready instances.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        let before = crate::metrics::LEASE_UNSATISFIABLE_TOTAL
            .with_label_values(&["test-profile", "pool_exhausted"])
            .get();

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(PENDING_BACKSTOP));

        // The metric for the Failing-pool reason incremented.
        let after = crate::metrics::LEASE_UNSATISFIABLE_TOTAL
            .with_label_values(&["test-profile", "pool_exhausted"])
            .get();
        assert_eq!(after, before + 1, "unsatisfiable metric should increment");

        // A status PATCH carrying a non-empty `message` was issued.
        let requests = server.received_requests().await.unwrap();
        let wrote_message = requests.iter().any(|r| {
            r.method == http::Method::PATCH
                && r.url.path().ends_with("/clusterleases/unsat-1/status")
                && serde_json::from_slice::<serde_json::Value>(&r.body)
                    .ok()
                    .and_then(|b| {
                        b.as_array()?
                            .iter()
                            .find(|op| op["path"] == "/status/message")?
                            .get("value")
                            .and_then(|m| m.as_str())
                            .map(|m| m.contains("phase=Failing") && !m.is_empty())
                    })
                    .unwrap_or(false)
        });
        assert!(
            wrote_message,
            "expected a status PATCH writing a non-empty message containing the pool phase"
        );

        // The same PATCH must carry the structured conditions companion (#189):
        // Bound=False (phase Pending) and Satisfiable=False (pool_exhausted).
        let wrote_conditions = requests.iter().any(|r| {
            r.method == http::Method::PATCH
                && r.url.path().ends_with("/clusterleases/unsat-1/status")
                && serde_json::from_slice::<serde_json::Value>(&r.body)
                    .ok()
                    .and_then(|b| {
                        let conds = b
                            .as_array()?
                            .iter()
                            .find(|op| op["path"] == "/status/conditions")?
                            .get("value")?
                            .as_array()?
                            .clone();
                        let bound = conds
                            .iter()
                            .find(|c| c.get("type") == Some(&serde_json::json!("Bound")))?;
                        let sat = conds
                            .iter()
                            .find(|c| c.get("type") == Some(&serde_json::json!("Satisfiable")))?;
                        Some(
                            bound.get("status") == Some(&serde_json::json!("False"))
                                && bound.get("reason") == Some(&serde_json::json!("Pending"))
                                && sat.get("status") == Some(&serde_json::json!("False"))
                                && sat.get("reason") == Some(&serde_json::json!("PoolExhausted")),
                        )
                    })
                    .unwrap_or(false)
        });
        assert!(
            wrote_conditions,
            "expected a status PATCH writing Bound=False/Pending and Satisfiable=False/PoolExhausted conditions"
        );
    }

    // -----------------------------------------------------------------------
    // derive_lease_conditions (#189): pure derivation + lastTransitionTime
    // -----------------------------------------------------------------------

    fn lease_cond<'a>(conds: &'a [ClusterLeaseCondition], ty: &str) -> &'a ClusterLeaseCondition {
        conds
            .iter()
            .find(|c| c.condition_type == ty)
            .unwrap_or_else(|| panic!("missing condition {ty}"))
    }

    #[test]
    fn derive_lease_conditions_bound_phase_is_bound_true_satisfiable_true() {
        let now = "2026-01-01T00:00:00Z";
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            message: Some("running".into()),
            ..Default::default()
        };
        let conds = derive_lease_conditions(&st, &[], None, now);

        let bound = lease_cond(&conds, "Bound");
        assert_eq!(bound.status, "True");
        assert_eq!(bound.reason, "Bound");
        assert_eq!(bound.message, "running");
        assert_eq!(bound.last_transition_time.as_deref(), Some(now));

        let sat = lease_cond(&conds, "Satisfiable");
        assert_eq!(sat.status, "True");
        assert_eq!(sat.reason, "Bound");
    }

    #[test]
    fn derive_lease_conditions_pending_unsatisfiable_is_bound_false_satisfiable_false() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let now = "2026-01-01T00:00:00Z";
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Pending,
            message: Some("no Ready cluster; pool p phase=Failing".into()),
            ..Default::default()
        };
        // PoolExhausted: the no-Ready-cluster path classifies the pool.
        let conds = derive_lease_conditions(&st, &[], Some(R::PoolExhausted), now);

        let bound = lease_cond(&conds, "Bound");
        assert_eq!(bound.status, "False");
        assert_eq!(bound.reason, "Pending");

        let sat = lease_cond(&conds, "Satisfiable");
        assert_eq!(sat.status, "False");
        assert_eq!(sat.reason, "PoolExhausted");
        assert!(sat.message.contains("phase=Failing"));
    }

    #[test]
    fn derive_lease_conditions_warming_is_satisfiable_false() {
        // A healthy-but-warming pool still has no cluster yet, so the lease is
        // not (currently) satisfiable — Satisfiable=False with reason `Warming`
        // explains *why* the Pending lease has no cluster.
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let now = "2026-01-01T00:00:00Z";
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Pending,
            ..Default::default()
        };
        let conds = derive_lease_conditions(&st, &[], Some(R::Warming), now);
        let sat = lease_cond(&conds, "Satisfiable");
        assert_eq!(sat.status, "False");
        assert_eq!(sat.reason, "Warming");
    }

    #[test]
    fn unsatisfiable_metric_counts_edges_and_reason_changes_only() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let previous = vec![ClusterLeaseCondition {
            condition_type: "Satisfiable".into(),
            status: "False".into(),
            reason: "PoolExhausted".into(),
            message: String::new(),
            last_transition_time: None,
        }];

        assert!(!entered_unsatisfiable_condition(
            &previous,
            R::PoolExhausted
        ));
        assert!(entered_unsatisfiable_condition(
            &previous,
            R::CapacityBlocked
        ));
        assert!(entered_unsatisfiable_condition(&[], R::PoolExhausted));
    }

    /// A full pool flips Exhausted -> ScalingUp -> Exhausted while a recycled
    /// slot is recreated. The same waiting lease must be counted once.
    #[test]
    fn unsatisfiable_metric_ignores_flips_between_transient_reasons() {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        let previously = |reason: &str| {
            vec![ClusterLeaseCondition {
                condition_type: "Satisfiable".into(),
                status: "False".into(),
                reason: reason.into(),
                message: String::new(),
                last_transition_time: None,
            }]
        };
        assert!(entered_unsatisfiable_condition(&[], R::AtCapacity));
        assert!(!entered_unsatisfiable_condition(
            &previously("Warming"),
            R::AtCapacity
        ));
        assert!(!entered_unsatisfiable_condition(
            &previously("AtCapacity"),
            R::Warming
        ));
        // Leaving a transient state for a real problem still counts, and so
        // does recovering into a transient one from a real problem.
        assert!(entered_unsatisfiable_condition(
            &previously("AtCapacity"),
            R::PoolExhausted
        ));
        assert!(entered_unsatisfiable_condition(
            &previously("CapacityBlocked"),
            R::AtCapacity
        ));
    }

    #[test]
    fn derive_lease_conditions_preserves_transition_time_when_status_unchanged() {
        let prev_time = "2025-12-31T00:00:00Z";
        let now = "2026-01-01T00:00:00Z";
        // Previously Bound=True.
        let prev = vec![ClusterLeaseCondition {
            condition_type: "Bound".to_string(),
            status: "True".to_string(),
            reason: "Bound".to_string(),
            message: "old".to_string(),
            last_transition_time: Some(prev_time.to_string()),
        }];
        // Still Bound=True — status unchanged, keep the prior timestamp.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            ..Default::default()
        };
        let conds = derive_lease_conditions(&st, &prev, None, now);
        assert_eq!(
            lease_cond(&conds, "Bound").last_transition_time.as_deref(),
            Some(prev_time),
            "transition time preserved when Bound status does not flip"
        );
    }

    #[test]
    fn derive_lease_conditions_updates_transition_time_when_status_flips() {
        let prev_time = "2025-12-31T00:00:00Z";
        let now = "2026-01-01T00:00:00Z";
        // Previously Bound=True (lease was bound).
        let prev = vec![ClusterLeaseCondition {
            condition_type: "Bound".to_string(),
            status: "True".to_string(),
            reason: "Bound".to_string(),
            message: String::new(),
            last_transition_time: Some(prev_time.to_string()),
        }];
        // Now Expired -> Bound=False. Status flipped -> stamp now.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Expired,
            ..Default::default()
        };
        let conds = derive_lease_conditions(&st, &prev, None, now);
        let bound = lease_cond(&conds, "Bound");
        assert_eq!(bound.status, "False");
        assert_eq!(bound.reason, "Expired");
        assert_eq!(
            bound.last_transition_time.as_deref(),
            Some(now),
            "transition time updated when Bound status flips"
        );
    }
    // -----------------------------------------------------------------------
    // Event-driven wakes: bind window, instance/secret mappers, queue eviction
    // -----------------------------------------------------------------------

    fn instance_fixture(name: &str, pool: &str, phase: &str) -> ClusterInstance {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
                "labels": { "kobe.kunobi.ninja/pool": pool }
            },
            "spec": {},
            "status": { "phase": phase }
        }))
        .unwrap()
    }

    fn pending_lease_fixture(name: &str, priority: u32, created: &str) -> Arc<ClusterLease> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "uid": format!("{name}-uid"),
                    "creationTimestamp": created
                },
                "spec": {
                    "poolRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "user@test.com" },
                    "priority": priority
                },
                "status": { "phase": "Pending" }
            }))
            .unwrap(),
        )
    }

    fn pending(name: &str) -> PendingLease {
        PendingLease {
            lease_name: name.into(),
            priority: 50,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn bind_window_is_one_per_free_instance_and_never_empty() {
        assert_eq!(bind_window(0), 1, "the head always gets to try");
        assert_eq!(bind_window(1), 1);
        assert_eq!(bind_window(3), 3);
    }

    #[test]
    fn free_instances_counts_only_unreserved_ready_instances_of_the_pool() {
        let mut reserved = instance_fixture("reserved", "test-profile", "Ready");
        reserved.status.as_mut().unwrap().lease_ref = Some(ResourceRef {
            name: "someone".into(),
            uid: Some("someone-uid".into()),
        });
        let mut deleting = instance_fixture("deleting", "test-profile", "Ready");
        deleting.metadata.deletion_timestamp =
            serde_json::from_value(serde_json::json!("2026-01-01T00:00:00Z")).unwrap();
        let instances: Vec<Arc<ClusterInstance>> = vec![
            instance_fixture("free-1", "test-profile", "Ready"),
            instance_fixture("free-2", "test-profile", "Ready"),
            instance_fixture("creating", "test-profile", "Creating"),
            instance_fixture("other-pool", "other", "Ready"),
            reserved,
            deleting,
        ]
        .into_iter()
        .map(Arc::new)
        .collect();
        assert_eq!(free_instances_in_pool(&instances, "test-profile"), 2);
    }

    #[test]
    fn the_head_tries_every_instance_and_other_slots_only_their_own() {
        let free = || vec!["a", "b", "c"];
        assert_eq!(candidates_for_slot(free(), 0), ["a", "b", "c"]);
        assert_eq!(candidates_for_slot(free(), 1), ["b"]);
        assert_eq!(candidates_for_slot(free(), 2), ["c"]);
        assert!(
            candidates_for_slot(free(), 3).is_empty(),
            "a slot past the free list must not wrap onto the head's instance"
        );
    }

    fn ready_member(
        name: &str,
        spec_hash: Option<&str>,
        state_since: Option<&str>,
    ) -> ClusterInstance {
        let mut instance = instance_fixture(name, "test-profile", "Ready");
        let status = instance.status.get_or_insert_with(Default::default);
        status.spec_hash = spec_hash.map(str::to_string);
        status.state_since = state_since.map(str::to_string);
        instance
    }

    fn ordered_names(members: Vec<ClusterInstance>, current: &str) -> Vec<String> {
        order_bind_candidates(members, current)
            .into_iter()
            .map(|instance| instance.name_any())
            .collect()
    }

    #[test]
    fn order_bind_candidates_puts_current_spec_ahead_of_stale_even_when_stale_sorts_first_by_name()
    {
        assert_eq!(
            ordered_names(
                vec![
                    ready_member("aaa-stale", Some("old"), None),
                    ready_member("zzz-current", Some("now"), None),
                ],
                "now",
            ),
            ["zzz-current", "aaa-stale"]
        );
    }

    #[test]
    fn order_bind_candidates_picks_the_oldest_member_within_each_spec_group() {
        assert_eq!(
            ordered_names(
                vec![
                    ready_member("current-new", Some("now"), Some("2026-01-02T00:00:00Z")),
                    ready_member("current-old", Some("now"), Some("2026-01-01T00:00:00Z")),
                    ready_member("stale-new", Some("old"), Some("2026-01-02T00:00:00Z")),
                    ready_member("stale-old", Some("old"), Some("2026-01-01T00:00:00Z")),
                ],
                "now",
            ),
            ["current-old", "current-new", "stale-old", "stale-new"]
        );
    }

    #[test]
    fn order_bind_candidates_does_not_treat_an_unstamped_member_as_current() {
        assert_eq!(
            ordered_names(
                vec![
                    ready_member("unstamped", None, Some("2026-01-01T00:00:00Z")),
                    ready_member("current", Some("now"), Some("2026-01-02T00:00:00Z")),
                ],
                "now",
            ),
            ["current", "unstamped"]
        );
    }

    #[test]
    fn a_wake_for_a_deleted_object_is_not_a_reconcile_error() {
        let gone: kube::runtime::controller::Error<LeaseError, kube::runtime::watcher::Error> =
            kube::runtime::controller::Error::ObjectNotFound(Box::new(
                ObjectRef::<ClusterLease>::new("gone")
                    .within("test-ns")
                    .erase(),
            ));
        assert!(woke_deleted_object(&gone));
        let failed: kube::runtime::controller::Error<LeaseError, kube::runtime::watcher::Error> =
            kube::runtime::controller::Error::ReconcilerFailed(
                LeaseError::Lifecycle(anyhow::anyhow!("boom")),
                Box::new(ObjectRef::<ClusterLease>::new("x").erase()),
            );
        assert!(!woke_deleted_object(&failed));

        let errors = || {
            crate::metrics::RECONCILIATIONS_TOTAL
                .with_label_values(&["lease", "error"])
                .get()
        };
        let before = errors();
        observe_lease_result(Err(gone));
        assert_eq!(errors(), before, "a deleted lease's wake is not an error");
    }

    #[tokio::test]
    async fn deleting_a_lease_forgets_its_failures_and_queue_entry() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("doomed", "Pending");
        ctx.queues
            .write()
            .await
            .insert("test-profile".into(), vec![pending("doomed")]);
        let error = LeaseError::Lifecycle(anyhow::anyhow!("boom"));
        error_policy(lease.clone(), &error, ctx.clone());
        error_policy(lease.clone(), &error, ctx.clone());

        forget_deleted_lease(&ctx, &lease).await;

        assert!(ctx.failures.lock().unwrap().is_empty());
        assert!(ctx.queues.read().await["test-profile"].is_empty());
        assert_eq!(
            error_policy(lease, &error, ctx),
            Action::requeue(ERROR_BACKOFF_BASE),
            "a lease reusing the name starts its backoff over"
        );
    }

    #[test]
    fn a_free_instance_wakes_the_front_of_its_pool_queue_in_priority_order() {
        let leases = vec![
            pending_lease_fixture("old-low", 10, "2026-01-01T00:00:00Z"),
            pending_lease_fixture("new-high", 90, "2026-01-01T00:05:00Z"),
            pending_lease_fixture("old-high", 90, "2026-01-01T00:01:00Z"),
        ];
        let free = instance_fixture("free", "test-profile", "Ready");
        assert_eq!(
            pending_leases_to_wake(&free, &leases, 2),
            ["old-high", "new-high"]
        );
        assert_eq!(
            pending_leases_to_wake(&free, &leases, 1),
            ["old-high"],
            "a window of one wakes only the head"
        );
    }

    #[test]
    fn an_instance_that_is_not_free_wakes_no_pending_lease() {
        let leases = vec![pending_lease_fixture("waiting", 50, "2026-01-01T00:00:00Z")];
        let creating = instance_fixture("creating", "test-profile", "Creating");
        assert!(pending_leases_to_wake(&creating, &leases, 1).is_empty());
        let other_pool = instance_fixture("elsewhere", "other", "Ready");
        assert!(pending_leases_to_wake(&other_pool, &leases, 1).is_empty());
    }

    #[test]
    fn instance_index_reports_a_lease_the_instance_stopped_naming() {
        let binding = exact_test_binding("held", "held-uid");
        let mut reserved = instance_fixture("pool-test-1", "test-profile", "Leased");
        reserved.status.as_mut().unwrap().binding = Some(binding.clone());
        reserved.status.as_mut().unwrap().lease_ref = Some(binding.lease.clone());
        let released = instance_fixture("pool-test-1", "test-profile", "Ready");

        let mut index = InstanceLeaseIndex::default();
        assert_eq!(
            index.applied(&reserved).into_iter().collect::<Vec<_>>(),
            ["held"]
        );
        assert_eq!(
            index.applied(&released).into_iter().collect::<Vec<_>>(),
            ["held"],
            "dropping the reservation must still wake the lease it named"
        );
        assert!(index.applied(&released).is_empty());
    }

    #[test]
    fn instance_index_reports_the_lease_of_a_deleted_instance() {
        let binding = exact_test_binding("recycling", "recycling-uid");
        let mut instance = instance_fixture("pool-test-1", "test-profile", "Recycling");
        instance.status.as_mut().unwrap().binding = Some(binding);
        let mut index = InstanceLeaseIndex::default();
        index.applied(&instance);
        assert_eq!(
            index.deleted(&instance).into_iter().collect::<Vec<_>>(),
            ["recycling"]
        );
        assert!(index.named.is_empty(), "a deleted instance is forgotten");
    }

    #[test]
    fn connect_secret_maps_back_to_its_lease() {
        let name = crate::api::connect::connect_secret_name("lease-abc");
        assert_eq!(lease_for_connect_secret(&name), Some("lease-abc"));
        assert_eq!(lease_for_connect_secret("pool-test-1-kubeconfig"), None);
        assert_eq!(lease_for_connect_secret("-connect-token"), None);
    }

    #[test]
    fn queue_window_takes_the_front_in_order() {
        let queue = vec![pending("a"), pending("b"), pending("c")];
        assert_eq!(queue_window(&queue, 2), ["a", "b"]);
        assert_eq!(queue_window(&queue, 5), ["a", "b", "c"]);
    }

    /// Removing the head used to leave the next lease waiting for its timer.
    #[tokio::test]
    async fn dequeue_of_the_head_wakes_the_new_head() {
        let (ctx, _server) = test_lease_context().await;
        let (wakes, mut woken) = tokio::sync::mpsc::unbounded_channel();
        let ctx = Arc::new(LeaseContext {
            queue_wakes: Some(wakes),
            ..Arc::into_inner(ctx).expect("sole owner")
        });
        ctx.queues.write().await.insert(
            "test-profile".into(),
            vec![pending("head"), pending("next"), pending("last")],
        );

        ctx.dequeue("test-profile", "head").await;

        assert_eq!(woken.try_recv().unwrap().name, "next");
        assert!(woken.try_recv().is_err(), "only the bind window is woken");
        let queue = ctx.queues.read().await["test-profile"].clone();
        assert_eq!(queue_window(&queue, 5), ["next", "last"]);
    }

    #[tokio::test]
    async fn dequeue_behind_the_window_wakes_nobody() {
        let (ctx, _server) = test_lease_context().await;
        let (wakes, mut woken) = tokio::sync::mpsc::unbounded_channel();
        let ctx = Arc::new(LeaseContext {
            queue_wakes: Some(wakes),
            ..Arc::into_inner(ctx).expect("sole owner")
        });
        ctx.queues.write().await.insert(
            "test-profile".into(),
            vec![pending("head"), pending("next")],
        );

        ctx.dequeue("test-profile", "next").await;
        ctx.dequeue("test-profile", "not-queued").await;

        assert!(woken.try_recv().is_err());
    }

    #[tokio::test]
    async fn remove_from_queue_reports_the_position_it_removed() {
        let queues = RwLock::new(HashMap::from([(
            "test-profile".to_string(),
            vec![pending("a"), pending("b")],
        )]));
        assert_eq!(
            remove_from_queue(&queues, "test-profile", "b").await,
            Some(1)
        );
        assert_eq!(remove_from_queue(&queues, "test-profile", "b").await, None);
        assert_eq!(remove_from_queue(&queues, "missing", "a").await, None);
    }

    /// A Pending lease outside the bind window waits on a backstop timer; the
    /// instance watch and queue wakes are what move it.
    #[tokio::test]
    async fn pending_lease_behind_the_head_waits_on_the_backstop() {
        let (ctx, server) = test_lease_context().await;
        ctx.queues
            .write()
            .await
            .insert("test-profile".into(), vec![pending("ahead")]);
        let mut lease = make_test_lease("behind", "Pending");
        Arc::make_mut(&mut lease).metadata.resource_version = Some("10".into());

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/behind",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/behind/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;
        // Any reservation attempt would list instances; a lease outside the
        // window must not.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .expect(0)
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(PENDING_BACKSTOP));
    }

    // -----------------------------------------------------------------------
    // Terminal Standard leases whose unbound reservation intent names a gone
    // instance
    // -----------------------------------------------------------------------

    /// The int-pro leak shape: Expired, reservation intent recorded while
    /// Pending, never Bound (no clusterName), Standard cleanup.
    fn orphaned_intent_lease(name: &str) -> (Arc<ClusterLease>, LeaseBinding) {
        let binding = exact_test_binding(name, &format!("{name}-uid"));
        let mut lease = make_never_bound_expired_lease(name);
        Arc::make_mut(&mut lease).status.as_mut().unwrap().binding = Some(binding.clone());
        (lease, binding)
    }

    async fn mount_terminal_lease_reads(server: &MockServer, lease: &ClusterLease) {
        let name = lease.name_any();
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/namespaces/test-ns/secrets/{name}-connect-token"
            )))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(server)
            .await;
    }

    async fn mount_lease_delete(server: &MockServer, lease: &ClusterLease, expected: u64) {
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
                lease.name_any()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .expect(expected)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn expired_unbound_intent_whose_instance_is_gone_is_retired() {
        let (ctx, server) = test_lease_context().await;
        let (lease, _) = orphaned_intent_lease("orphan-404");
        mount_terminal_lease_reads(&server, &lease).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 1).await;

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(ctx.backend.call_count().delete, 0);
    }

    #[tokio::test]
    async fn expired_unbound_intent_whose_name_was_reused_is_retired() {
        let (ctx, server) = test_lease_context().await;
        let (lease, _) = orphaned_intent_lease("orphan-replaced");
        mount_terminal_lease_reads(&server, &lease).await;
        let mut replacement = exact_instance_for_binding(None, "Ready");
        replacement["metadata"]["uid"] = serde_json::json!("replacement-uid");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement))
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 1).await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    /// While the exact instance carries the reservation, the lease stays as
    /// its handle: the instance controller recycles it from there.
    #[tokio::test]
    async fn expired_unbound_intent_whose_exact_instance_holds_it_is_kept() {
        let (ctx, server) = test_lease_context().await;
        let (lease, binding) = orphaned_intent_lease("orphan-live");
        mount_terminal_lease_reads(&server, &lease).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(exact_instance_for_binding(Some(&binding), "Leased")),
            )
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 0).await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    /// The #340 known gap: the instance released the orphan reservation and
    /// went back to Ready with the same UID. Resolution fails with
    /// `ReciprocalBindingMismatch`, and before this the lease requeued every
    /// 30s forever although it held nothing.
    #[tokio::test]
    async fn expired_unbound_intent_whose_instance_released_it_is_retired() {
        let (ctx, server) = test_lease_context().await;
        let (lease, _) = orphaned_intent_lease("orphan-released");
        mount_terminal_lease_reads(&server, &lease).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(exact_instance_for_binding(None, "Ready")),
            )
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 1).await;

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(ctx.backend.call_count().delete, 0);
    }

    /// Same instance, now reserved by a different lease: this one holds
    /// nothing, and retiring it must not touch the other reservation.
    #[tokio::test]
    async fn expired_unbound_intent_whose_instance_serves_another_lease_is_retired() {
        let (ctx, server) = test_lease_context().await;
        let (lease, _) = orphaned_intent_lease("orphan-superseded");
        mount_terminal_lease_reads(&server, &lease).await;
        let other = exact_test_binding("someone-else", "someone-else-uid");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(exact_instance_for_binding(Some(&other), "Leased")),
            )
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-1/status",
            ))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 1).await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    // -----------------------------------------------------------------------
    // Quarantine override
    // -----------------------------------------------------------------------

    fn quarantined_lease(name: &str, annotation: Option<&str>) -> Arc<ClusterLease> {
        let mut lease = make_test_lease(name, "Quarantined");
        let binding = exact_test_binding(name, &format!("{name}-uid"));
        let lease_mut = Arc::make_mut(&mut lease);
        lease_mut.metadata.resource_version = Some("50".into());
        lease_mut.metadata.finalizers = Some(vec![TEARDOWN_RECEIPT_RETENTION_FINALIZER.into()]);
        if let Some(value) = annotation {
            lease_mut.metadata.annotations = Some(std::collections::BTreeMap::from([(
                crate::quarantine::RELEASE_QUARANTINE_ANNOTATION.to_string(),
                value.to_string(),
            )]));
        }
        lease_mut.status.as_mut().unwrap().binding = Some(binding);
        lease
    }

    async fn mount_finalizer_patch(server: &MockServer, lease: &ClusterLease, expected: u64) {
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
                lease.name_any()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .expect(expected)
            .mount(server)
            .await;
    }

    /// Default stays fail-closed: a quarantined lease waits for evidence.
    #[tokio::test]
    async fn quarantined_lease_without_override_is_held() {
        let (ctx, server) = test_lease_context().await;
        let lease = quarantined_lease("held", None);
        mount_terminal_lease_reads(&server, &lease).await;
        mount_finalizer_patch(&server, &lease, 0).await;
        mount_lease_delete(&server, &lease, 0).await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn quarantine_override_for_another_uid_keeps_the_lease() {
        let (ctx, server) = test_lease_context().await;
        let lease = quarantined_lease("copied", Some("some-other-uid"));
        mount_terminal_lease_reads(&server, &lease).await;
        mount_finalizer_patch(&server, &lease, 0).await;
        mount_lease_delete(&server, &lease, 0).await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
    }

    /// The override revokes access, drops the retention finalizer, and
    /// deletes the exact lease, counting the release.
    #[tokio::test]
    async fn quarantine_override_releases_the_exact_lease() {
        let (ctx, server) = test_lease_context().await;
        let lease = quarantined_lease("released", Some("released-uid"));
        mount_terminal_lease_reads(&server, &lease).await;
        mount_finalizer_patch(&server, &lease, 1).await;
        mount_lease_delete(&server, &lease, 1).await;
        let before = crate::metrics::QUARANTINE_RELEASES_TOTAL
            .with_label_values(&["test-profile", "lease"])
            .get();

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert!(
            crate::metrics::QUARANTINE_RELEASES_TOTAL
                .with_label_values(&["test-profile", "lease"])
                .get()
                > before
        );
    }

    /// A Sandbox composition's receipt belongs to its SandboxLease; the
    /// override does not delete it out from under that owner.
    #[tokio::test]
    async fn quarantine_override_refuses_a_sandbox_composition_lease() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = quarantined_lease("composed", Some("composed-uid"));
        let lease_mut = Arc::make_mut(&mut lease);
        lease_mut.spec.requester.requester_type = "kobe:sandbox-composition".into();
        lease_mut.spec.requester.identity = "outer-sandbox".into();
        lease_mut.spec.cleanup_mode = Some(CleanupMode::VerifiedDestroy);
        mount_terminal_lease_reads(&server, &lease).await;
        mount_finalizer_patch(&server, &lease, 0).await;
        mount_lease_delete(&server, &lease, 0).await;
        // The refusal is announced once, not on every 300s requeue.
        Mock::given(method("POST"))
            .and(path("/apis/events.k8s.io/v1/namespaces/test-ns/events"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let action = reconcile_lease(lease.clone(), ctx.clone()).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(300)));
    }

    /// With the split teardown authority, admission can refuse the finalizer
    /// write. That is not a release: nothing is counted or announced, and the
    /// lease is not deleted.
    #[tokio::test]
    async fn quarantine_override_does_not_record_a_refused_finalizer_write() {
        let (ctx, server) = test_lease_context().await;
        let lease = quarantined_lease("refused-write", Some("refused-write-uid"));
        mount_terminal_lease_reads(&server, &lease).await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/{}",
                lease.name_any()
            )))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "Forbidden", "code": 403,
                "message": "receipt retention cannot be removed before exact acknowledgement"
            })))
            .mount(&server)
            .await;
        mount_lease_delete(&server, &lease, 0).await;
        Mock::given(method("POST"))
            .and(path("/apis/events.k8s.io/v1/namespaces/test-ns/events"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(0)
            .mount(&server)
            .await;

        assert!(reconcile_lease(lease, ctx).await.is_err());
    }

    /// A lease this path already deleted, held open by another finalizer, is
    /// not counted a second time.
    #[tokio::test]
    async fn quarantine_override_counts_an_already_deleting_lease_once() {
        let (ctx, server) = test_lease_context().await;
        let mut lease = quarantined_lease("deleting", Some("deleting-uid"));
        let lease_mut = Arc::make_mut(&mut lease);
        lease_mut.metadata.finalizers = Some(vec!["example.com/other".into()]);
        lease_mut.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        mount_terminal_lease_reads(&server, &lease).await;
        mount_finalizer_patch(&server, &lease, 0).await;
        mount_lease_delete(&server, &lease, 0).await;
        Mock::given(method("POST"))
            .and(path("/apis/events.k8s.io/v1/namespaces/test-ns/events"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(0)
            .mount(&server)
            .await;

        let action = reconcile_lease(lease, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[test]
    fn an_instance_holds_a_lease_through_either_reservation_field() {
        let binding = exact_test_binding("mine", "mine-uid");
        let parse = |value: serde_json::Value| -> ClusterInstance {
            serde_json::from_value(value).unwrap()
        };
        let held = parse(exact_instance_for_binding(Some(&binding), "Leased"));
        assert!(instance_names_lease(&held, "mine-uid"));

        let mut ref_only = held.clone();
        ref_only.status.as_mut().unwrap().binding = None;
        assert!(instance_names_lease(&ref_only, "mine-uid"));

        let mut binding_only = held.clone();
        binding_only.status.as_mut().unwrap().lease_ref = None;
        assert!(instance_names_lease(&binding_only, "mine-uid"));

        let released = parse(exact_instance_for_binding(None, "Ready"));
        assert!(!instance_names_lease(&released, "mine-uid"));
        assert!(!instance_names_lease(&held, "other-uid"));
    }

    #[test]
    fn only_standard_never_bound_intents_are_retirement_candidates() {
        let (lease, binding) = orphaned_intent_lease("candidate");
        let status = lease.status.clone().unwrap();
        assert_eq!(
            orphaned_standard_intent(&lease, &status, false),
            Some(&binding)
        );
        assert_eq!(
            orphaned_standard_intent(&lease, &status, true),
            None,
            "verified cleanup keeps its receipt protocol"
        );

        let mut verified = (*lease).clone();
        verified.spec.cleanup_mode = Some(CleanupMode::VerifiedDestroy);
        let mut verified_status = status.clone();
        verified_status.binding.as_mut().unwrap().cleanup_mode = CleanupMode::VerifiedDestroy;
        assert_eq!(
            orphaned_standard_intent(&verified, &verified_status, false),
            None
        );

        let mut was_bound = status.clone();
        was_bound.cluster_name = Some("pool-test-1".into());
        assert_eq!(orphaned_standard_intent(&lease, &was_bound, false), None);

        let mut no_binding = status.clone();
        no_binding.binding = None;
        assert_eq!(orphaned_standard_intent(&lease, &no_binding, false), None);

        let mut recycling = status;
        recycling.phase = LeasePhase::Recycling;
        assert_eq!(orphaned_standard_intent(&lease, &recycling, false), None);
    }
}
