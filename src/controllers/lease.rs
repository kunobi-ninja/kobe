use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, Preconditions};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::auth::JwtAuthenticator;
use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{
    BackendProvenance, BoundInstanceRef, ClusterInstance, ClusterInstancePhase, ClusterLease,
    ClusterLeaseCondition, ClusterLeaseStatus, ClusterPool, ClusterPoolPhase, ClusterPoolStatus,
    LeaseBinding, LeasePhase, ResourceRef, TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION,
    UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION,
};
use crate::diagnostics;
use crate::lease_binding::BindingResolutionError;
use crate::pool::{PoolState, parse_duration};

#[derive(Debug)]
struct SandboxCompositionIdentity {
    outer_name: String,
    outer_uid: String,
}

#[derive(Debug)]
enum SandboxCompositionGate {
    NotComposition,
    Authorized,
    NeedsMigration(SandboxCompositionIdentity),
    Closed(SandboxCompositionIdentity),
    Invalid,
    Retry,
}

/// Produce the owner-independent metadata fence for one exact composition.
///
/// Unknown labels, annotations, and finalizers are preserved. The known
/// identity fields are overwritten only after the caller has validated every
/// pre-existing value against `identity`.
fn sandbox_composition_retention_metadata(
    lease: &ClusterLease,
    identity: &SandboxCompositionIdentity,
    stale_rejected: bool,
) -> (
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
    Vec<String>,
) {
    let now = chrono::Utc::now();
    let mut labels = lease.metadata.labels.clone().unwrap_or_default();
    labels.insert(
        crate::sandbox::SANDBOX_LEASE_UID_LABEL.into(),
        identity.outer_uid.clone(),
    );
    labels.insert(
        crate::controllers::sandbox_child::CHILD_HANDLE_TOMBSTONE_LABEL.into(),
        "true".into(),
    );
    let mut annotations = lease.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(
        crate::controllers::sandbox_child::CHILD_HANDLE_OUTER_NAME_ANNOTATION.into(),
        identity.outer_name.clone(),
    );
    if stale_rejected {
        annotations.insert(
            crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION.into(),
            identity.outer_uid.clone(),
        );
    }
    let deadline_is_live = annotations
        .get(crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|deadline| deadline.with_timezone(&chrono::Utc) > now);
    if !deadline_is_live {
        annotations.insert(
            crate::controllers::sandbox_child::CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION.into(),
            crate::controllers::sandbox_child::child_handle_retention_deadline(now).to_rfc3339(),
        );
    }
    let mut finalizers = lease.metadata.finalizers.clone().unwrap_or_default();
    if !finalizers.iter().any(|finalizer| {
        finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
    }) {
        finalizers.push(crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER.into());
    }
    (labels, annotations, finalizers)
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
        || lease.spec.requester.identity != "kobe-operator"
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
    let outer_is_open = outer.uid().as_deref() == Some(outer_uid.as_str())
        && crate::controllers::sandbox::sandbox_lease_authorizes_allocation(&outer);
    if !outer_is_open {
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
                SandboxCompositionGate::Authorized
            } else {
                SandboxCompositionGate::NeedsMigration(identity)
            }
        }
        Ok(_) => SandboxCompositionGate::Closed(identity),
        Err(_) => SandboxCompositionGate::Retry,
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

    let ctx = Arc::new(LeaseContext {
        client: client.clone(),
        backend,
        pools,
        queues: RwLock::new(HashMap::new()),
        active_reconciles: Mutex::new(HashSet::new()),
        namespace: namespace.to_string(),
        authenticator,
        factory,
    });

    rebuild_queues(&ctx).await;

    let reaper_ctx = ctx.clone();
    let reaper_ns = namespace.to_string();
    let reaper_shutdown = shutdown.clone();
    tokio::spawn(async move {
        run_reaper(reaper_ctx, &reaper_ns, reaper_shutdown).await;
    });

    info!("Starting lease controller");

    let controller = Controller::new(leases, Config::default())
        .run(reconcile_lease, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["lease", "ok"])
                        .inc();
                    debug!(lease = %obj.name, "Lease reconciled");
                }
                Err(e) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["lease", "error"])
                        .inc();
                    error!("Lease reconciliation error: {e:?}");
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Lease controller shutting down");
        },
    }
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
                // It is NOT the fix for deletes in general: kube-runtime
                // drives the controller from `applied_objects()`, which
                // drops Deleted events, and requeues resolve through the
                // reflector store — so a `kubectl delete` of a queued
                // lease produces no reconcile here at all. The reaper's
                // sweep (`prune_queues_against_live`) is what actually
                // guarantees the entry goes away; this just gets there
                // sooner when the race does happen.
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
                return Ok(Action::await_change());
            }
            Err(err) => return Err(LeaseError::Kube(err)),
        }
    } else {
        lease
    };

    let status = lease.status.clone().unwrap_or_default();

    // This consumer-side gate must run before legacy backfill, queue writes or
    // binding intent. A POST can commit after its creator was cancelled, and
    // two operator replicas may reconcile the same object concurrently.
    if status.phase == LeasePhase::Pending {
        match sandbox_composition_allocation_gate(&ctx.client, &ns, &lease).await {
            SandboxCompositionGate::NotComposition | SandboxCompositionGate::Authorized => {}
            SandboxCompositionGate::NeedsMigration(identity) => {
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
                return migrate_sandbox_composition_retention_fence(&leases_api, &lease, &identity)
                    .await;
            }
            SandboxCompositionGate::Closed(identity) => {
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
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
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
                return quarantine_invalid_sandbox_composition(&leases_api, &lease).await;
            }
            SandboxCompositionGate::Retry => {
                return Ok(Action::requeue(std::time::Duration::from_secs(15)));
            }
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
                let bound = finalize_binding(&ctx, &ns, &binding, created_at_for(&lease)).await?;
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
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

            let (is_head, position) = {
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
                let head = queue.first().map(|h| h.lease_name == name).unwrap_or(false);
                (head, pos)
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
                    return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                }
                Err(error) => return Err(error.into()),
            };

            if let Some(profile) = get_profile(&ctx.client, &lease.spec.pool_ref, &ns).await
                && let Some(scaling) = &profile.spec.scaling
                && let Some(timeout) = parse_duration(&scaling.queue_timeout)
            {
                let age = chrono::Utc::now() - created_at;
                if age > timeout {
                    warn!(lease = %name, "Lease exceeded queue timeout, expiring");
                    crate::metrics::LEASE_QUEUE_WAIT_SECONDS
                        .with_label_values(&[lease.spec.pool_ref.as_str(), "expired"])
                        .observe(age.num_milliseconds() as f64 / 1000.0);
                    remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
                    let patch = expired_status_patch(&status.conditions);
                    leases_api
                        .patch_status(
                            &name,
                            &PatchParams::apply("kobe-operator"),
                            &Patch::Merge(&patch),
                        )
                        .await?;
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
            }

            if !is_head {
                debug!(lease = %name, position, "Not queue head, waiting for higher-priority leases");
                return Ok(Action::requeue(std::time::Duration::from_secs(5)));
            }

            let reserved_binding = reserve_ready_instance(&ctx.client, &ns, &queued_lease).await?;

            if let Some(binding) = reserved_binding {
                // The instance reservation is durable. If this final status
                // write fails or the process stops, the next reconcile sees
                // the same lease-side intent and finishes the same pair. It
                // must not roll back on an uncertain response.
                let bound = finalize_binding(&ctx, &ns, &binding, created_at).await?;
                remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
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

                // Only count genuinely-unsatisfiable demand. A healthy-but-warming
                // pool (reason=Warming) is a normal cold-start, not an exhaustion
                // event — counting it on every ~5s requeue tick would swamp the
                // alert signal with normal warm-ups (#189 review).
                if reason != crate::metrics::LeaseUnsatisfiableReason::Warming {
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
                // doesn't churn the timestamp on every ~5s requeue tick.
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
                if let Err(e) = leases_api
                    .patch_status(
                        &name,
                        &PatchParams::apply("kobe-operator"),
                        &Patch::Merge(
                            &serde_json::json!({ "status": { "message": message, "conditions": conditions } }),
                        ),
                    )
                    .await
                {
                    warn!(lease = %name, "Failed to write unsatisfiable status message (continuing): {e}");
                }

                Ok(Action::requeue(std::time::Duration::from_secs(5)))
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
                            let patch = expired_status_patch(&status.conditions);
                            leases_api
                                .patch_status(
                                    &name,
                                    &PatchParams::apply("kobe-operator"),
                                    &Patch::Merge(&patch),
                                )
                                .await?;
                            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                        }
                    }
                    Err(e) => {
                        error!(
                            lease = %name,
                            expires_at = %expires_at_str,
                            "Failed to parse expires_at, force-expiring lease: {e}"
                        );
                        let patch = expired_status_patch(&status.conditions);
                        leases_api
                            .patch_status(
                                &name,
                                &PatchParams::apply("kobe-operator"),
                                &Patch::Merge(&patch),
                            )
                            .await?;
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

            remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;

            let Some(lease_uid) = lease.metadata.uid.as_deref() else {
                mark_binding_unverified(&leases_api, &lease, "lease_uid_missing").await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            };

            // Explicitly delete the lease's connect-token Secret now, rather
            // than waiting for owner-ref GC when the lease CRD is deleted at the
            // end of Recycling (#178). Closes the window where a released lease's
            // token still validates if the CRD delete is interrupted; access is
            // also bounded per-request by the proxy phase/expiry re-check (#116).
            // Best-effort: a failure must not abort recycling.
            if let Err(e) =
                crate::api::connect::delete_lease_connect_token(&ctx.client, &ns, &name, lease_uid)
                    .await
            {
                warn!(lease = %name, "best-effort connect-token delete failed (continuing): {e:#}");
            }

            // A composition-only lease that reached a terminal phase before
            // binding never owned a cluster. That absence is useful proof to
            // the outer SandboxLease, but deleting this handle immediately
            // would erase it before the outer controller can checkpoint it.
            // Persist an explicit NeverBound proof and retain the exact handle
            // until the outer lease ACKs this exact timestamp.
            if lease.spec.cleanup_mode == Some(crate::crd::CleanupMode::VerifiedDestroy)
                && lease.spec.requester.requester_type == "kobe:sandbox-composition"
                && lease.spec.requester.identity == "kobe-operator"
                && status.binding.is_none()
                && status.cluster_name.is_none()
                && status.teardown_receipt.is_none()
            {
                if !unbound_release_proof_is_complete(&status) {
                    record_unbound_release_proof(&leases_api, &lease, &status).await?;
                    return Ok(Action::await_change());
                }
                let proof = status
                    .unbound_release_verified_at
                    .as_deref()
                    .expect("complete proof has a timestamp");
                if stale_sandbox_composition_was_rejected(&lease) {
                    info!(lease = %name, "Retiring rejected stale NeverBound handle behind retention finalizer");
                    return Ok(if delete_lease_crd(&leases_api, &lease).await {
                        Action::await_change()
                    } else {
                        Action::requeue(std::time::Duration::from_secs(15))
                    });
                }
                if lease
                    .annotations()
                    .get(UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION)
                    .is_some_and(|ack| ack == proof)
                {
                    // The outer controller installs/verifies the retention
                    // fence before deleting. Older ACK writers did not, so
                    // deleting here could erase the only proof during a
                    // rolling upgrade.
                    debug!(lease = %name, "retaining ACKed NeverBound proof for outer retirement");
                    return Ok(Action::requeue(std::time::Duration::from_secs(300)));
                }
                debug!(lease = %name, "retaining terminal NeverBound proof until its composing Sandbox ACKs");
                return Ok(Action::requeue(std::time::Duration::from_secs(300)));
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
                    if status.cluster_name.is_none()
                        && !sandbox_composition_requires_outer_retirement(&lease)
                        && !teardown_receipt_unconsumed(&lease, &status) =>
                {
                    info!(
                        lease = %name,
                        phase = %phase,
                        "Retiring terminal lease: no binding was ever recorded"
                    );
                    crate::metrics::LEASES_RETIRED_UNBOUND_TOTAL
                        .with_label_values(&[
                            lease.spec.pool_ref.as_str(),
                            phase.to_string().as_str(),
                        ])
                        .inc();
                    return Ok(if delete_lease_crd(&leases_api, &lease).await {
                        Action::await_change()
                    } else {
                        Action::requeue(std::time::Duration::from_secs(15))
                    });
                }
                Err(err) => {
                    mark_binding_unverified(&leases_api, &lease, err.reason_code()).await?;
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
                mark_binding_unverified(&leases_api, &lease, "instance_recycle_fence_failed")
                    .await?;
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            }

            let mut recycling_status = status.clone();
            recycling_status.phase = LeasePhase::Recycling;
            if diag_url.is_some() {
                recycling_status.diagnostics_url = diag_url;
            }
            let conditions = derive_lease_conditions(
                &recycling_status,
                &status.conditions,
                None,
                &chrono::Utc::now().to_rfc3339(),
            );
            recycling_status.conditions = conditions;
            let lease_rv = lease
                .resource_version()
                .ok_or_else(|| anyhow::anyhow!("lease missing resourceVersion"))?;
            let patch = json_patch(serde_json::json!([
                { "op": "test", "path": "/metadata/uid", "value": lease_uid },
                { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
                { "op": "test", "path": "/status/binding", "value": resolved.binding },
                { "op": "add", "path": "/status", "value": recycling_status }
            ]));
            leases_api
                .patch_status(&name, &PatchParams::default(), &Patch::<()>::Json(patch))
                .await?;
            debug!(cluster = %cluster_name, "Marked exact ClusterInstance recycling");

            Ok(Action::requeue(std::time::Duration::from_secs(10)))
        }

        // Terminal until the same exact subject produces a verified receipt.
        // Access is already revoked and the binding/finalizers are deliberately
        // retained as cleanup handles, so there is nothing to reconcile here.
        // The transitions INTO this phase, and the retry that can leave it,
        // belong to the verified-teardown controller work.
        LeasePhase::Quarantined => Ok(Action::requeue(std::time::Duration::from_secs(300))),

        LeasePhase::Recycling => {
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
                Ok(Action::requeue(std::time::Duration::from_secs(15)))
            }
        }
    }
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
    let lease = leases_api.get(&binding.lease.name).await?;
    if lease.metadata.uid.as_deref() != binding.lease.uid.as_deref() {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "lease UID changed while finalizing binding"
        )));
    }
    let status = lease.status.clone().unwrap_or_default();
    if status.phase == LeasePhase::Bound && status.binding.as_ref() == Some(binding) {
        return Ok(true);
    }
    if status.phase != LeasePhase::Pending || status.binding.as_ref() != Some(binding) {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "lease binding intent changed before finalization"
        )));
    }
    match sandbox_composition_allocation_gate(&ctx.client, namespace, &lease).await {
        SandboxCompositionGate::NotComposition => {
            if lease.metadata.deletion_timestamp.is_some() {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "lease was deleted while finalizing binding"
                )));
            }
        }
        SandboxCompositionGate::Authorized => {}
        SandboxCompositionGate::NeedsMigration(identity) => {
            let _ =
                migrate_sandbox_composition_retention_fence(&leases_api, &lease, &identity).await?;
            return Ok(false);
        }
        SandboxCompositionGate::Closed(identity) => {
            let _ = close_stale_sandbox_composition(
                &ctx.client,
                namespace,
                &leases_api,
                &lease,
                &identity,
            )
            .await?;
            return Ok(false);
        }
        SandboxCompositionGate::Invalid => {
            if !mark_instance_recycling(&ctx.client, namespace, binding).await? {
                return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                    "invalid Sandbox reservation could not be fenced for recycling"
                )));
            }
            let _ = quarantine_invalid_sandbox_composition(&leases_api, &lease).await?;
            return Ok(false);
        }
        SandboxCompositionGate::Retry => {
            return Err(LeaseError::Lifecycle(anyhow::anyhow!(
                "Sandbox composition authorization unavailable while finalizing binding"
            )));
        }
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
        unbound_release_verified_at: None,
    };
    new_status.conditions =
        derive_lease_conditions(&new_status, &status.conditions, None, &now.to_rfc3339());

    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "add", "path": "/status", "value": new_status }
    ]));
    leases_api
        .patch_status(
            &binding.lease.name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await?;

    let bind_duration = (chrono::Utc::now() - created_at).num_milliseconds() as f64 / 1000.0;
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
    Ok(true)
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
    status.teardown_receipt.as_ref().is_some_and(|receipt| {
        !stale_sandbox_composition_was_rejected(lease)
            && lease
                .annotations()
                .get(TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION)
                != Some(&receipt.attempt_id)
    })
}

fn sandbox_composition_requires_outer_retirement(lease: &ClusterLease) -> bool {
    lease.spec.requester.requester_type == "kobe:sandbox-composition"
        && lease.spec.requester.identity == "kobe-operator"
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
        && lease.spec.requester.identity == "kobe-operator"
        && lease.spec.cleanup_mode == Some(crate::crd::CleanupMode::VerifiedDestroy)
        && annotations
            .get(crate::controllers::sandbox_child::CHILD_HANDLE_STALE_REJECTED_ANNOTATION)
            == Some(outer_uid)
        && retention_deadline_is_valid
        && lease.finalizers().iter().any(|finalizer| {
            finalizer == crate::controllers::sandbox_child::CHILD_HANDLE_RETENTION_FINALIZER
        })
}

const ALLOCATION_ABSENT_CONDITION: &str = "AllocationAbsent";

fn unbound_release_proof_is_complete(status: &ClusterLeaseStatus) -> bool {
    let timestamp = status
        .unbound_release_verified_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
    timestamp.is_some()
        && status.conditions.iter().any(|condition| {
            condition.condition_type == ALLOCATION_ABSENT_CONDITION
                && condition.status == "True"
                && condition.reason == "NeverBound"
        })
}

async fn record_unbound_release_proof(
    leases: &Api<ClusterLease>,
    lease: &ClusterLease,
    status: &ClusterLeaseStatus,
) -> Result<(), LeaseError> {
    let Some(uid) = lease.uid().filter(|uid| !uid.is_empty()) else {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!("lease UID missing")));
    };
    let Some(resource_version) = lease.resource_version() else {
        return Err(LeaseError::Lifecycle(anyhow::anyhow!(
            "lease resourceVersion missing"
        )));
    };
    let verified_at = status
        .unbound_release_verified_at
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let previous = status
        .conditions
        .iter()
        .find(|condition| condition.condition_type == ALLOCATION_ABSENT_CONDITION);
    let transition = previous
        .filter(|condition| condition.status == "True" && condition.reason == "NeverBound")
        .and_then(|condition| condition.last_transition_time.clone())
        .unwrap_or_else(|| verified_at.clone());
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
        message: "Terminal lease never acquired a ClusterInstance binding".into(),
        last_transition_time: Some(transition),
    });
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "add", "path": "/status/unboundReleaseVerifiedAt", "value": verified_at },
        { "op": "add", "path": "/status/conditions", "value": conditions }
    ]));
    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if optimistic_conflict(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
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
    if reserve_binding_instance(client, namespace, &binding).await? {
        Ok(Some(binding))
    } else {
        clear_lease_binding_intent(client, namespace, lease_uid, &binding).await?;
        Ok(None)
    }
}

async fn reserve_ready_instance(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<Option<LeaseBinding>, LeaseError> {
    if let Some(binding) = lease
        .status
        .as_ref()
        .and_then(|status| status.binding.clone())
    {
        return if reserve_binding_instance(client, namespace, &binding).await? {
            Ok(Some(binding))
        } else {
            clear_lease_binding_intent(client, namespace, lease_uid_for(lease)?, &binding).await?;
            Ok(None)
        };
    }

    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/pool={}", lease.spec.pool_ref));
    let instances = instances_api.list(&lp).await?;
    let mut ready: Vec<ClusterInstance> = instances
        .into_iter()
        .filter(|instance| {
            // An instance under deletion is not free capacity, however idle its
            // status looks. Between `deletionTimestamp` being set and the
            // finalizer completing, phase can still read Ready with no
            // leaseRef; binding there would hand a tenant a cluster that is
            // going away, and `resolve_lease_binding` would then refuse the
            // connection (`InstanceDeleting`) on a lease that already reached
            // Bound and consumed pool capacity.
            if instance.metadata.deletion_timestamp.is_some() {
                return false;
            }
            instance
                .status
                .as_ref()
                // A genuinely-free instance is Ready AND carries no leaseRef. The
                // extra leaseRef check prevents a double-lease: if a stale write
                // (e.g. the profile controller syncing an out-of-date in-memory
                // phase) reverts an already-Leased instance to Ready while leaving
                // its leaseRef set, selecting it here would bind the same cluster
                // to a second tenant. Requiring leaseRef == None excludes that
                // case while still admitting all genuinely-idle instances.
                .map(|s| s.phase == ClusterInstancePhase::Ready && s.lease_ref.is_none())
                .unwrap_or(false)
        })
        .collect();
    ready.sort_by_key(|instance| instance.name_any());

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

    for instance in ready {
        let binding = match binding_from_observation(lease, &instance, &pool) {
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

        let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
        let intent_patch = json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": lease_uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv },
            { "op": "test", "path": "/status/phase", "value": "Pending" },
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

        if reserve_binding_instance(client, namespace, &binding).await? {
            return Ok(Some(binding));
        }

        // The intended instance was won by another lease. Remove only this
        // exact still-Pending intent; resourceVersion + full binding tests mean
        // a concurrent finalization or replacement cannot be erased.
        clear_lease_binding_intent(client, namespace, lease_uid, &binding).await?;
        return Ok(None);
    }

    Ok(None)
}

fn lease_uid_for(lease: &ClusterLease) -> Result<&str, LeaseError> {
    lease
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| LeaseError::Lifecycle(anyhow::anyhow!("lease missing UID")))
}

/// Reserve the exact instance named by an already-persisted lease intent.
/// Returns `false` on an optimistic conflict/occupied instance and leaves
/// uncertain transport failures for the next reconcile to recover.
async fn reserve_binding_instance(
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
    if !instance_matches_binding_subject(&instance, binding) {
        return Ok(false);
    }
    let status = instance.status.clone().unwrap_or_default();
    let lease_ref_exact = status.lease_ref.as_ref().is_some_and(|reference| {
        reference.name == binding.lease.name && reference.uid == binding.lease.uid
    });
    if status.phase == ClusterInstancePhase::Leased
        && status.binding.as_ref() == Some(binding)
        && lease_ref_exact
    {
        return Ok(true);
    }

    let is_free = status.phase == ClusterInstancePhase::Ready
        && status.binding.is_none()
        && status.lease_ref.is_none();
    let is_provable_legacy_pair = status.phase == ClusterInstancePhase::Leased
        && status.binding.is_none()
        && status.lease_ref.as_ref().is_some_and(|reference| {
            reference.name == binding.lease.name && reference.uid.is_none()
        });
    if !is_free && !is_provable_legacy_pair {
        return Ok(false);
    }

    let uid = instance
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("instance missing UID"))?;
    let rv = instance
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("instance missing resourceVersion"))?;
    let expected_phase = if is_free { "Ready" } else { "Leased" };
    let expected_lease_ref = if is_free {
        serde_json::Value::Null
    } else {
        serde_json::json!({ "name": binding.lease.name })
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
        Ok(_) => Ok(true),
        Err(err) if optimistic_conflict(&err) => Ok(false),
        Err(err) => Err(err.into()),
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
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": "Pending" },
        { "op": "test", "path": "/status/binding", "value": binding },
        { "op": "remove", "path": "/status/binding" }
    ]));
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
    if status.phase != ClusterInstancePhase::Leased {
        return Ok(false);
    }
    let rv = instance
        .resource_version()
        .ok_or_else(|| anyhow::anyhow!("instance missing resourceVersion"))?;
    let patch = json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": binding.instance.uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": "Leased" },
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

            let evicted = {
                let mut queues = ctx.queues.write().await;
                prune_queues_against_live(&mut queues, &live_pending)
            };
            if !evicted.is_empty() {
                warn!(
                    leases = ?evicted,
                    "Reaper: evicted queue entries with no live Pending lease (would otherwise head-block the pool)"
                );
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
                            let patch = expired_status_patch(&status.conditions);
                            if let Err(e) = leases_api
                                .patch_status(
                                    &name,
                                    &PatchParams::apply("kobe-operator"),
                                    &Patch::Merge(&patch),
                                )
                                .await
                            {
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
                        let patch = expired_status_patch(&status.conditions);
                        if let Err(e) = leases_api
                            .patch_status(
                                &name,
                                &PatchParams::apply("kobe-operator"),
                                &Patch::Merge(&patch),
                            )
                            .await
                        {
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

async fn remove_from_queue(
    queues: &RwLock<HashMap<String, Vec<PendingLease>>>,
    profile: &str,
    lease_name: &str,
) {
    let mut queues = queues.write().await;
    if let Some(queue) = queues.get_mut(profile) {
        queue.retain(|p| p.lease_name != lease_name);
    }
}

/// Drop queue entries whose lease is no longer `Pending` on the
/// apiserver, returning the names evicted.
///
/// This is the authoritative cleanup, and it exists because the
/// reconcile path cannot be. kube-runtime's `Controller` is driven by
/// `applied_objects()`, which drops Deleted events, and every scheduled
/// requeue resolves through the reflector store first — so once a
/// deleted lease leaves the store, **no reconcile ever runs for it**.
/// The 404 branch in `reconcile_lease` therefore only catches the narrow
/// race where a delete lands mid-reconcile; a plain `kubectl delete` of
/// a queued lease never reaches it.
///
/// That matters because a stranded entry is not a leak but a deadlock:
/// the queue is sorted oldest-first within a priority, so the ghost sits
/// at the head and every later lease for that pool sees `is_head ==
/// false` and never binds.
///
/// Sweeping from a LIST is safe against the obvious race — a lease
/// created after the LIST could be pruned here, but the queue insert in
/// `reconcile_lease` is idempotent and runs on a 5s requeue, so it
/// re-inserts itself on the next pass. A transient drop self-heals; a
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

/// Build the `{ "status": { ... } }` merge patch that transitions a lease to
/// `Expired`, carrying the derived conditions (`Bound=False`, `Satisfiable`)
/// alongside the phase. `prev` is the lease's on-disk conditions, used to
/// preserve `lastTransitionTime` when a condition's status is unchanged.
fn expired_status_patch(prev: &[ClusterLeaseCondition]) -> serde_json::Value {
    let expired = ClusterLeaseStatus {
        phase: LeasePhase::Expired,
        ..Default::default()
    };
    let conditions =
        derive_lease_conditions(&expired, prev, None, &chrono::Utc::now().to_rfc3339());
    serde_json::json!({ "status": { "phase": "Expired", "conditions": conditions } })
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

/// Build a human-readable lease `status.message` and classify the
/// [`crate::metrics::LeaseUnsatisfiableReason`] from a pool's status, for the
/// "no Ready cluster" case. Shared so the controller branch and the
/// `create_lease` pre-flight (src/api/routes.rs) classify a pool identically.
///
/// The message echoes the pool fields an operator/client needs to decide
/// whether to keep waiting: phase, consecutiveFailures, lastFailureReason.
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
    let reason = match phase {
        Some(ClusterPoolPhase::Failing) => R::PoolExhausted,
        Some(ClusterPoolPhase::Backoff) => R::CapacityBlocked,
        // Healthy/ScalingUp/Idle with no Ready cluster right now is a transient
        // warm-up; anything else (e.g. ScalingDown) is treated as degraded.
        Some(ClusterPoolPhase::Healthy)
        | Some(ClusterPoolPhase::ScalingUp)
        | Some(ClusterPoolPhase::Idle)
        | None => R::Warming,
        Some(ClusterPoolPhase::ScalingDown) => R::Degraded,
    };

    let phase_str = phase
        .map(|p| format!("{p:?}"))
        .unwrap_or_else(|| "Unknown".to_string());
    let mut message = format!(
        "no Ready cluster; pool {pool_ref} phase={phase_str}, consecutiveFailures={}",
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

fn error_policy<B: ClusterBackend>(
    _lease: Arc<ClusterLease>,
    error: &LeaseError,
    _ctx: Arc<LeaseContext<B>>,
) -> Action {
    error!("Lease reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(30))
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

        let result = reserve_ready_instance(&ctx.client, "test-ns", &lease).await;
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

        let result = reserve_ready_instance(&client, "test-ns", &lease).await;
        assert!(
            matches!(result, Ok(None)),
            "a Ready instance still carrying a leaseRef must not be reserved, got {result:?}"
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

        let won = reserve_binding_instance(&client, "test-ns", &first)
            .await
            .unwrap();
        let lost = reserve_binding_instance(&client, "test-ns", &second)
            .await
            .unwrap();
        assert!(won);
        assert!(!lost);

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
            .expect(1)
            .mount(&server)
            .await;

        let mut lease = make_test_lease("lease-a", "Pending");
        Arc::make_mut(&mut lease).status.as_mut().unwrap().binding = Some(binding.clone());
        let resumed = reserve_ready_instance(&client, "test-ns", &lease)
            .await
            .unwrap();
        assert_eq!(resumed, Some(binding));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "replay must not list or reserve another instance"
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
                    "identity": "kobe-operator"
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
        outer
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
                || request.url.path().contains("/clusterpools/child-pool")
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

    /// A lost status response must be retryable, and the recovered write must
    /// carry a durable NeverBound condition plus the exact timestamp that the
    /// outer Sandbox later ACKs.
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

        assert!(
            record_unbound_release_proof(&leases, &lease, status)
                .await
                .is_err()
        );
        record_unbound_release_proof(&leases, &lease, status)
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

    // -----------------------------------------------------------------------
    // error_policy
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_error_policy_returns_requeue() {
        let (ctx, _server) = test_lease_context().await;
        let lease = make_test_lease("err-lease", "Pending");
        let error = LeaseError::Lifecycle(anyhow::anyhow!("test error"));
        let action = error_policy(lease, &error, ctx);
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
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
                "metadata": { "name": "pending-1", "namespace": "test-ns" },
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
        // No ready cluster → requeue at 5s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
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

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&*lease))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;

        let binding = reserve_ready_instance(&ctx.client, "test-ns", &lease)
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
                "metadata": { "name": "expired-1", "namespace": "test-ns" },
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(15)));
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
        // Cluster still present → requeue at 15s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(15)));
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
                "metadata": { "name": "unsat-1", "namespace": "test-ns" },
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));

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
                        b.get("status")
                            .and_then(|s| s.get("message"))
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
                        let conds = b.get("status")?.get("conditions")?.as_array()?.clone();
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
}
