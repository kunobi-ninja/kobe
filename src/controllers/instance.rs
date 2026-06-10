use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSpec, PodTemplateSpec, SecretVolumeSource, Volume, VolumeMount,
};
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::core::ObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::{
    BackendFactory, BootstrapJobPlan, ClusterBackend, resolve_bootstrap_addons,
    resolve_bootstrap_jobs,
};
use crate::crd::{
    Addon, BackendConfig, BackendType, BootstrapRef, CIDRClaim, CIDRClaimPhase, CIDRClaimSpec,
    ClusterConfig, ClusterInstance, ClusterInstanceCondition, ClusterInstanceNetwork,
    ClusterInstancePhase, ClusterInstanceStatus, ClusterLease, ClusterPool, HealthCheckConfig,
    LeasePhase, ReadinessGate, SnapshotConfig,
};
use crate::velero::VeleroCoordinator;

/// Finalizer placed on every `ClusterInstance` so the operator gets a
/// chance to tear down backend-owned resources (StatefulSet, Deployment,
/// Service, Secrets, ConfigMaps) before the CR is removed from etcd.
///
/// Without this, a direct `kubectl delete clusterinstance ...` or any
/// abnormal-path deletion (Creating/Unhealthy/Failed) drops the CR
/// immediately and `K3sBackend::delete()` / `K0sBackend::delete()`
/// never runs — leaking the entire backend resource set (see #95).
const INSTANCE_FINALIZER: &str = "kobe.kunobi.ninja/instance-cleanup";

// ─────────────────────────────────────────────────────────────────────
// Metrics helpers
// ─────────────────────────────────────────────────────────────────────

/// Seconds elapsed since the `ClusterInstance` was created.
/// Used as the duration value for `kobe_instance_create_duration_seconds`
/// at terminal phase transitions. Returns `0.0` when
/// `creation_timestamp` is missing (shouldn't happen — any instance
/// reaching a terminal phase was Created at some point).
fn instance_age_seconds(instance: &ClusterInstance) -> f64 {
    instance
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| {
            let created_ms = t.0.as_millisecond();
            let now_ms = chrono::Utc::now().timestamp_millis();
            ((now_ms - created_ms).max(0) as f64) / 1000.0
        })
        .unwrap_or(0.0)
}

/// Stable string label for a backend type. Closed enum, no
/// allocations — keeps Prometheus label cardinality fixed.
fn backend_label(backend: &BackendType) -> &'static str {
    match backend {
        BackendType::K3s => "k3s",
        BackendType::K0s => "k0s",
        BackendType::Capi => "capi",
        BackendType::Vkobe => "vkobe",
        BackendType::Vcluster => "vcluster",
    }
}

/// Profile label, with `"standalone"` for instances not managed by a
/// pool. Used as the `profile` label on per-instance metrics so the
/// label set is stable across pool-managed and standalone instances.
fn profile_label(instance: &ClusterInstance) -> &str {
    instance
        .spec
        .pool_ref
        .as_ref()
        .map(|r| r.name.as_str())
        .unwrap_or("standalone")
}

/// Record an instance create-attempt outcome: histogram observation +
/// counter increment. Called when phase transitions to a terminal
/// state (`Ready`, `Failed`) for the first time.
fn observe_instance_create(
    instance: &ClusterInstance,
    backend: &BackendType,
    outcome: crate::metrics::InstanceCreateOutcome,
) {
    let elapsed = instance_age_seconds(instance);
    let profile = profile_label(instance);
    let backend_str = backend_label(backend);
    crate::metrics::INSTANCE_CREATE_DURATION
        .with_label_values(&[profile, backend_str, outcome.as_str()])
        .observe(elapsed);
    crate::metrics::INSTANCE_CREATES_TOTAL
        .with_label_values(&[profile, backend_str, outcome.as_str()])
        .inc();
}

/// Increment the recycle counter with a typed reason. The Recycling
/// transition itself is performed by the caller; this only records
/// the metric.
fn observe_recycle(instance: &ClusterInstance, reason: crate::metrics::RecycleReason) {
    crate::metrics::INSTANCE_RECYCLES_TOTAL
        .with_label_values(&[profile_label(instance), reason.as_str()])
        .inc();
}

pub struct InstanceContext<B: ClusterBackend> {
    pub client: Client,
    pub backend: B,
    pub namespace: String,
    pub factory: Option<BackendFactory>,
    pub velero: Option<VeleroCoordinator>,
}

#[derive(Debug, Clone)]
struct ResolvedInstanceConfig {
    owner_name: String,
    backend: BackendConfig,
    cluster: ClusterConfig,
    addons: Vec<Addon>,
    bootstraps: Vec<BootstrapRef>,
    health_check: Option<HealthCheckConfig>,
    readiness_gates: Vec<ReadinessGate>,
    snapshot: Option<SnapshotConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] anyhow::Error),
}

pub async fn run_instance_controller<B: ClusterBackend + Clone + 'static>(
    client: Client,
    namespace: &str,
    backend: B,
    factory: Option<BackendFactory>,
    velero: Option<VeleroCoordinator>,
    shutdown: CancellationToken,
) {
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let ctx = Arc::new(InstanceContext {
        client: client.clone(),
        backend,
        namespace: namespace.to_string(),
        factory,
        velero,
    });

    info!("Starting instance controller");

    let controller = Controller::new(instances, Config::default())
        .run(reconcile_instance, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["instance", "ok"])
                        .inc();
                    debug!(instance = %obj.name, "Instance reconciled");
                }
                Err(e) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["instance", "error"])
                        .inc();
                    error!("Instance reconciliation error: {e:?}");
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Instance controller shutting down");
        },
    }
}

#[tracing::instrument(skip_all, fields(instance = %instance.name_any()))]
async fn reconcile_instance<B: ClusterBackend + Clone + 'static>(
    instance: Arc<ClusterInstance>,
    ctx: Arc<InstanceContext<B>>,
) -> Result<Action, InstanceError> {
    let name = instance.name_any();
    let ns = instance
        .namespace()
        .unwrap_or_else(|| ctx.namespace.clone());
    let status = instance.status.clone().unwrap_or_default();
    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
    // Resolve config tolerantly during deletion: a cascading ClusterPool
    // delete sets a deletionTimestamp on the child AND removes the pool, so a
    // strict resolve would Err before the finalizer path runs and deadlock the
    // delete. `resolve_instance_config` falls back to `status.created_with`
    // when the pool is gone and we're deleting (see #95-adjacent note there).
    let is_deleting = instance.metadata.deletion_timestamp.is_some();
    let config = resolve_instance_config(&ctx.client, &instance, &ns, is_deleting).await?;
    let profile_name = instance.spec.pool_ref.as_ref().map(|r| r.name.clone());
    let owner = profile_name.as_deref().unwrap_or(name.as_str());

    // ── Finalizer handling ──────────────────────────────────────────────
    //
    // Block etcd removal of the `ClusterInstance` until `backend.delete()`
    // has run. Two cases:
    //
    // 1. `deletion_timestamp` is set: Kubernetes is trying to GC the CR
    //    but our finalizer is blocking it. Run the backend teardown +
    //    host-side orphan cleanup, then remove the finalizer so the API
    //    server can complete the delete. This is what catches the
    //    abnormal-path leak in #95: `kubectl delete clusterinstance`
    //    while in Creating/Unhealthy/Failed (or any non-Ready) phase
    //    used to drop the CR immediately and leak the entire backend
    //    resource set.
    //
    // 2. No `deletion_timestamp` and finalizer not yet present: stamp
    //    it on so future deletions are intercepted. Done idempotently
    //    via JSON Merge Patch — re-running on an instance that already
    //    has it is a no-op patch.
    let has_finalizer = instance
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|x| x == INSTANCE_FINALIZER));

    if instance.metadata.deletion_timestamp.is_some() {
        if has_finalizer {
            info!(
                instance = %name,
                owner = %owner,
                phase = ?status.phase,
                "ClusterInstance deletion requested; running backend cleanup before releasing finalizer"
            );
            match delete_instance_backend(&ctx, &config, &instance, &name, &ns).await {
                Ok(()) => {
                    cleanup_orphan_projected_resources(&ctx.client, &name, &ns).await;
                    remove_finalizer(&instances_api, &instance, INSTANCE_FINALIZER).await?;
                    return Ok(Action::await_change());
                }
                Err(e) => {
                    warn!(
                        instance = %name,
                        error = %format!("{e:#}"),
                        "Backend cleanup failed during finalizer-driven delete; will retry"
                    );
                    return Ok(Action::requeue(std::time::Duration::from_secs(15)));
                }
            }
        }
        // Deletion in progress and we already released our finalizer —
        // wait for the API server to complete the delete. No requeue
        // needed; the watch stream will stop emitting once the object
        // is gone.
        return Ok(Action::await_change());
    }

    if !has_finalizer {
        add_finalizer(&instances_api, &instance, INSTANCE_FINALIZER).await?;
        // Re-reconcile immediately so the rest of the state machine
        // sees the updated metadata. The watch event from the patch
        // will arrive on its own, but a tight requeue avoids a
        // pointless idle gap on first reconcile.
        return Ok(Action::requeue(std::time::Duration::from_secs(0)));
    }

    match status.phase {
        ClusterInstancePhase::Creating if !status.provisioned => {
            // ── Phase 0: allocate network CIDRs if not yet recorded ─────
            //
            // Two-phase split intentional: persist the allocation BEFORE
            // any backend resource is created. If the operator crashes
            // between allocation and provisioning, the persisted slot is
            // still ours — re-reconciling reads it and skips re-allocation.
            // If we instead allocated + provisioned in one pass and the
            // status patch failed mid-flight, we'd risk leaking backend
            // resources whose slot the next reconcile would re-allocate
            // (collision with the very resources we just created).
            //
            // Backends that own their own network plane (k3s, k0s) need
            // CIDRs that don't collide with the host cluster (10.43/10.42
            // are k3s/rke2/kubeadm defaults — leasing pools used to silently
            // route in-pod kubernetes.default.svc to the HOST apiserver
            // because of iptables overlap). Backends that reuse the host
            // network (vkobe) ignore the field. Allocation runs uniformly
            // for all backends; vkobe just doesn't read it.
            //
            // The IP space itself is governed by `CIDRPool` resources
            // and per-instance allocation goes through a `CIDRClaim`
            // owned by this `ClusterInstance`. We create the claim once
            // (idempotent), wait for the IPAM controller to bind it,
            // copy the result to `status.network`, and let provisioning
            // proceed. See `controllers::ipam` for the allocation logic
            // and `crd::cidr` for the CRD shapes.
            let network = match &status.network {
                Some(n) => n.clone(),
                None => match ensure_claim_bound(&ctx.client, &ns, &instance).await? {
                    ClaimResolution::Bound(net) => {
                        info!(
                            instance = %name,
                            service_cidr = %net.service_cidr,
                            cluster_cidr = %net.cluster_cidr,
                            "CIDRClaim bound; copying CIDRs to ClusterInstance.status.network"
                        );
                        patch_instance_status(
                            &instances_api,
                            &instance,
                            ClusterInstanceStatus {
                                phase: ClusterInstancePhase::Creating,
                                provisioned: false,
                                bootstrapped: false,
                                lease_ref: status.lease_ref.clone(),
                                active_bootstrap: None,
                                idle_since: status.idle_since.clone(),
                                state_since: Some(chrono::Utc::now().to_rfc3339()),
                                health_failures: status.health_failures,
                                spec_hash: status.spec_hash.clone(),
                                network: Some(net.clone()),
                                // `created_with: None` lets `skip_serializing_if`
                                // omit the field from the JSON Merge Patch, so
                                // the on-disk provenance written at create time
                                // is preserved (we never want to overwrite it
                                // from an instance-controller patch).
                                created_with: None,
                                message: Some("network allocated; awaiting provisioning".into()),
                                // Overwritten centrally in patch_instance_status.
                                conditions: Vec::new(),
                            },
                        )
                        .await?;
                        // Requeue to let the next pass actually provision
                        // — keeps the "persist allocation, then create
                        // resources" boundary explicit even if it costs
                        // one extra reconcile.
                        return Ok(Action::requeue(std::time::Duration::from_secs(1)));
                    }
                    ClaimResolution::Pending => {
                        debug!(
                            instance = %name,
                            "CIDRClaim is Pending; waiting for IPAM controller"
                        );
                        return Ok(Action::requeue(std::time::Duration::from_secs(2)));
                    }
                    ClaimResolution::Conflict(msg) => {
                        warn!(
                            instance = %name,
                            reason = %msg,
                            "CIDRClaim is in Conflict; provisioning blocked"
                        );
                        return Ok(Action::requeue(std::time::Duration::from_secs(60)));
                    }
                },
            };

            // Thread the allocated network into the resolved cluster
            // config so the backend reads it from a single place.
            let mut config = config;
            config.cluster.allocated_network = Some(network);

            info!(instance = %name, owner = %owner, "Provisioning backend resources");
            // Build the OwnerReference once so backends can stamp it on
            // every namespaced child resource — defense-in-depth GC for
            // the explicit `delete()` cleanup path. See `ClusterBackend::create`
            // for the contract.
            let owner_ref = instance.controller_owner_ref(&());
            match provision_instance(&ctx, &config, &name, &ns, owner_ref.as_ref()).await {
                Ok(()) => {
                    patch_instance_status(
                        &instances_api,
                        &instance,
                        ClusterInstanceStatus {
                            phase: ClusterInstancePhase::Creating,
                            provisioned: true,
                            bootstrapped: false,
                            lease_ref: status.lease_ref,
                            active_bootstrap: None,
                            idle_since: status.idle_since,
                            state_since: Some(chrono::Utc::now().to_rfc3339()),
                            health_failures: status.health_failures,
                            spec_hash: status.spec_hash.clone(),
                            message: Some("waiting for control plane to become ready".into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                    Ok(Action::requeue(std::time::Duration::from_secs(5)))
                }
                Err(e) => {
                    let failure = format!("{e:#}");
                    warn!(instance = %name, error = %failure, "Provisioning failed");
                    observe_instance_create(
                        &instance,
                        &config.backend.backend_type,
                        crate::metrics::InstanceCreateOutcome::Failed,
                    );
                    patch_instance_status(
                        &instances_api,
                        &instance,
                        ClusterInstanceStatus {
                            phase: ClusterInstancePhase::Failed,
                            provisioned: false,
                            bootstrapped: false,
                            lease_ref: status.lease_ref,
                            active_bootstrap: None,
                            idle_since: None,
                            state_since: Some(chrono::Utc::now().to_rfc3339()),
                            health_failures: status.health_failures,
                            spec_hash: status.spec_hash.clone(),
                            message: Some(format!("provisioning failed: {failure}")),
                            ..Default::default()
                        },
                    )
                    .await?;
                    Ok(Action::requeue(std::time::Duration::from_secs(30)))
                }
            }
        }
        ClusterInstancePhase::Creating if status.provisioned => {
            let ready = evaluate_instance_readiness(&ctx, &config, &name, &ns).await?;
            if ready {
                match reconcile_instance_bootstraps(&ctx, &config, &instance, &name, &ns).await {
                    Ok(Some(active_bootstrap)) => {
                        let message = Some(format!("running bootstrap '{active_bootstrap}'"));
                        patch_instance_status(
                            &instances_api,
                            &instance,
                            ClusterInstanceStatus {
                                phase: ClusterInstancePhase::Creating,
                                provisioned: true,
                                bootstrapped: false,
                                lease_ref: status.lease_ref,
                                active_bootstrap: Some(active_bootstrap),
                                idle_since: None,
                                state_since: status.state_since,
                                health_failures: 0,
                                spec_hash: status.spec_hash.clone(),
                                message,
                                ..Default::default()
                            },
                        )
                        .await?;
                        Ok(Action::requeue(std::time::Duration::from_secs(5)))
                    }
                    Ok(None) => {
                        observe_instance_create(
                            &instance,
                            &config.backend.backend_type,
                            crate::metrics::InstanceCreateOutcome::Ready,
                        );
                        patch_instance_status(
                            &instances_api,
                            &instance,
                            ClusterInstanceStatus {
                                phase: ClusterInstancePhase::Ready,
                                provisioned: true,
                                bootstrapped: true,
                                lease_ref: status.lease_ref,
                                active_bootstrap: None,
                                idle_since: Some(chrono::Utc::now().to_rfc3339()),
                                state_since: Some(chrono::Utc::now().to_rfc3339()),
                                health_failures: 0,
                                spec_hash: status.spec_hash.clone(),
                                message: Some("ready".into()),
                                ..Default::default()
                            },
                        )
                        .await?;
                        Ok(Action::requeue(std::time::Duration::from_secs(30)))
                    }
                    Err(e) => {
                        let failure = format!("{e:#}");
                        warn!(instance = %name, error = %failure, "Bootstrap failed");
                        observe_instance_create(
                            &instance,
                            &config.backend.backend_type,
                            crate::metrics::InstanceCreateOutcome::Failed,
                        );
                        // Bootstrap-specific counter so an alert can
                        // distinguish "bootstrap failure" from generic
                        // "create failure" without having to
                        // disambiguate via duration buckets.
                        let bootstrap_label =
                            status.active_bootstrap.as_deref().unwrap_or("unknown");
                        crate::metrics::BOOTSTRAP_FAILURES_TOTAL
                            .with_label_values(&[
                                profile_label(&instance),
                                bootstrap_label,
                                // Reason classification deferred — needs Job
                                // status inspection to differentiate
                                // ExitNonZero vs Timeout vs BackoffLimit. For
                                // now we tag everything as backoff_limit
                                // because that's what the wrapping Job
                                // ultimately reports.
                                crate::metrics::BootstrapFailureReason::BackoffLimit.as_str(),
                            ])
                            .inc();
                        let message = Some(format!(
                            "bootstrap '{}' failed: {failure}",
                            status.active_bootstrap.as_deref().unwrap_or("unknown")
                        ));
                        patch_instance_status(
                            &instances_api,
                            &instance,
                            ClusterInstanceStatus {
                                phase: ClusterInstancePhase::Failed,
                                provisioned: true,
                                bootstrapped: false,
                                lease_ref: status.lease_ref,
                                active_bootstrap: status.active_bootstrap,
                                idle_since: None,
                                state_since: Some(chrono::Utc::now().to_rfc3339()),
                                health_failures: status.health_failures,
                                spec_hash: status.spec_hash.clone(),
                                message,
                                ..Default::default()
                            },
                        )
                        .await?;
                        Ok(Action::requeue(std::time::Duration::from_secs(30)))
                    }
                }
            } else {
                Ok(Action::requeue(std::time::Duration::from_secs(5)))
            }
        }
        ClusterInstancePhase::Ready => {
            let next =
                evaluate_ready_instance(&ctx, &config, &instance, &name, &ns, &status).await?;
            Ok(next)
        }
        ClusterInstancePhase::Leased => {
            let next = evaluate_leased_instance(&ctx, &instance, &name, &ns, &status).await?;
            Ok(next)
        }
        ClusterInstancePhase::Recycling => {
            info!(instance = %name, owner = %owner, "Deleting backend resources");
            match delete_instance_backend(&ctx, &config, &instance, &name, &ns).await {
                Ok(()) => {
                    // Best-effort cleanup of host-side resources that the
                    // backend's own delete() doesn't own. See
                    // cleanup_orphan_projected_resources() for the rationale —
                    // this prevents the orphan-leak pattern that took down
                    // an internal cluster (~700 leaked probe pods + ~170 leaked
                    // projected workload pods over 8 days of cycling).
                    cleanup_orphan_projected_resources(&ctx.client, &name, &ns).await;

                    instances_api.delete(&name, &Default::default()).await?;
                    Ok(Action::await_change())
                }
                Err(e) => {
                    warn!(instance = %name, error = %format!("{e:#}"), "Delete failed");
                    Ok(Action::requeue(std::time::Duration::from_secs(15)))
                }
            }
        }
        ClusterInstancePhase::Failed | ClusterInstancePhase::Unhealthy
            if instance.spec.pool_ref.is_none() =>
        {
            // Standalone instances (no pool_ref) are invisible to the pool
            // manager, so a terminal one would requeue forever and leak its
            // backend resources — for k3s/k0s, the per-cluster Postgres database
            // created before the failure plus any half-created k8s objects. After
            // a short grace window (so an operator can inspect it), move it to
            // Recycling, which runs delete_instance_backend + datastore cleanup.
            let grace = chrono::Duration::minutes(5);
            if !standalone_terminal_should_recycle(
                status.state_since.as_deref(),
                chrono::Utc::now(),
                grace,
            ) {
                return Ok(Action::requeue(std::time::Duration::from_secs(30)));
            }
            warn!(
                instance = %name,
                phase = ?status.phase,
                "Standalone instance is terminal past the grace window; recycling to release backend resources"
            );
            let message = Some(format!(
                "recycling terminal standalone instance (was {})",
                phase_reason(&status.phase)
            ));
            patch_instance_status(
                &instances_api,
                &instance,
                ClusterInstanceStatus {
                    phase: ClusterInstancePhase::Recycling,
                    provisioned: status.provisioned,
                    bootstrapped: status.bootstrapped,
                    lease_ref: status.lease_ref.clone(),
                    active_bootstrap: None,
                    idle_since: None,
                    state_since: Some(chrono::Utc::now().to_rfc3339()),
                    health_failures: status.health_failures,
                    spec_hash: status.spec_hash.clone(),
                    message,
                    ..Default::default()
                },
            )
            .await?;
            Ok(Action::await_change())
        }
        _ => Ok(Action::requeue(std::time::Duration::from_secs(30))),
    }
}

/// Whether a terminal (Failed/Unhealthy) *standalone* instance has been in that
/// state long enough to recycle — releasing its backend resources — rather than
/// keep it for inspection. A missing or unparseable `state_since` returns `true`
/// (recycle) so a malformed timestamp can never strand a leaking instance.
fn standalone_terminal_should_recycle(
    state_since: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    grace: chrono::Duration,
) -> bool {
    match state_since.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
        Some(since) => now.signed_duration_since(since.with_timezone(&chrono::Utc)) >= grace,
        None => true,
    }
}

/// Whether a leased instance has held its reservation long enough (`state_since`
/// older than `grace`) to be considered for orphaned-reservation release. A
/// missing or unparseable `state_since` returns `false` — conservative, so a
/// normal in-flight bind is never disturbed.
fn reservation_grace_elapsed(
    state_since: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    grace: chrono::Duration,
) -> bool {
    state_since
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|since| now.signed_duration_since(since.with_timezone(&chrono::Utc)) >= grace)
        .unwrap_or(false)
}

/// Evaluate a `Leased` instance.
///
/// Leased instances are **intentionally not health-probed**: once a cluster is
/// handed to a tenant it is the tenant's for the lease TTL, and proactively
/// recycling it out from under an active lease (or flapping its phase on a
/// transient probe failure) would be far more disruptive than a tenant
/// observing a degraded cluster they can release. So this only reacts to the
/// lease's lifecycle — recycling when the lease is Released/Expired/Recycling or
/// gone, and reclaiming an orphaned reservation (see below) — never to backend
/// health. Health gating happens while the instance is `Ready` (pre-lease).
async fn evaluate_leased_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    instance: &ClusterInstance,
    name: &str,
    namespace: &str,
    status: &ClusterInstanceStatus,
) -> Result<Action, InstanceError> {
    let Some(lease_ref) = &status.lease_ref else {
        warn!(instance = %name, "Leased instance is missing lease_ref, recycling");
        observe_recycle(instance, crate::metrics::RecycleReason::LeaseReleased);
        let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), namespace);
        patch_instance_status(
            &instances_api,
            instance,
            ClusterInstanceStatus {
                phase: ClusterInstancePhase::Recycling,
                provisioned: status.provisioned,
                bootstrapped: status.bootstrapped,
                lease_ref: None,
                active_bootstrap: None,
                idle_since: None,
                state_since: Some(chrono::Utc::now().to_rfc3339()),
                health_failures: status.health_failures,
                spec_hash: status.spec_hash.clone(),
                message: Some("recycling: leased instance lost its lease reference".into()),
                ..Default::default()
            },
        )
        .await?;
        return Ok(Action::requeue(std::time::Duration::from_secs(10)));
    };

    let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), namespace);
    match leases_api.get(&lease_ref.name).await {
        Ok(lease) => {
            let lease_status = lease.status.unwrap_or_default();
            let should_recycle = matches!(
                lease_status.phase,
                LeasePhase::Released | LeasePhase::Expired | LeasePhase::Recycling
            );
            if should_recycle {
                info!(
                    instance = %name,
                    lease = %lease_ref.name,
                    phase = %lease_status.phase,
                    "Lease is terminating, recycling instance"
                );
                observe_recycle(instance, crate::metrics::RecycleReason::LeaseReleased);
                let instances_api: Api<ClusterInstance> =
                    Api::namespaced(ctx.client.clone(), namespace);
                let message = Some(format!(
                    "recycling: lease '{}' is {}",
                    lease_ref.name, lease_status.phase
                ));
                patch_instance_status(
                    &instances_api,
                    instance,
                    ClusterInstanceStatus {
                        phase: ClusterInstancePhase::Recycling,
                        provisioned: status.provisioned,
                        bootstrapped: status.bootstrapped,
                        lease_ref: None,
                        active_bootstrap: None,
                        idle_since: None,
                        state_since: Some(chrono::Utc::now().to_rfc3339()),
                        health_failures: status.health_failures,
                        spec_hash: status.spec_hash.clone(),
                        message,
                        ..Default::default()
                    },
                )
                .await?;
                Ok(Action::requeue(std::time::Duration::from_secs(10)))
            } else {
                // Detect an orphaned reservation. Binding is two steps — mark the
                // instance Leased, then patch the lease to Bound+clusterName. If
                // the operator dies between them, the instance is stuck Leased
                // pointing at a lease that stays Pending with no clusterName, and
                // nothing reclaims it (the pool/lease reapers don't cover this
                // case) — the warm cluster is lost from the pool forever.
                //
                // After a grace window (the normal bind completes in ms), release
                // such an instance back to Ready so the still-Pending lease can be
                // re-bound. Only act when the lease is Pending AND not bound to us,
                // so a normal in-flight bind is never disturbed.
                let bound_to_us = lease_status.cluster_name.as_deref() == Some(name);
                let reservation_orphaned =
                    lease_status.phase == LeasePhase::Pending && !bound_to_us;
                let grace = chrono::Duration::minutes(2);
                if reservation_orphaned
                    && reservation_grace_elapsed(
                        status.state_since.as_deref(),
                        chrono::Utc::now(),
                        grace,
                    )
                {
                    warn!(
                        instance = %name,
                        lease = %lease_ref.name,
                        "Leased instance points at a lease that never finished binding; \
                         releasing the reservation back to the pool"
                    );
                    let instances_api: Api<ClusterInstance> =
                        Api::namespaced(ctx.client.clone(), namespace);
                    patch_instance_status(
                        &instances_api,
                        instance,
                        ClusterInstanceStatus {
                            // The cluster was reserved but never handed to a tenant
                            // (the lease never reached Bound), so it is clean —
                            // return it to Ready rather than recycling.
                            phase: ClusterInstancePhase::Ready,
                            provisioned: status.provisioned,
                            bootstrapped: status.bootstrapped,
                            lease_ref: None,
                            active_bootstrap: None,
                            idle_since: Some(chrono::Utc::now().to_rfc3339()),
                            state_since: Some(chrono::Utc::now().to_rfc3339()),
                            health_failures: status.health_failures,
                            spec_hash: status.spec_hash.clone(),
                            message: Some(
                                "ready; reclaimed from an orphaned lease reservation".into(),
                            ),
                            ..Default::default()
                        },
                    )
                    .await?;
                    return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                }
                Ok(Action::requeue(std::time::Duration::from_secs(30)))
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(
                instance = %name,
                lease = %lease_ref.name,
                "Lease CR not found for leased instance, recycling"
            );
            observe_recycle(instance, crate::metrics::RecycleReason::LeaseReleased);
            let instances_api: Api<ClusterInstance> =
                Api::namespaced(ctx.client.clone(), namespace);
            let message = Some(format!(
                "recycling: lease '{}' no longer exists",
                lease_ref.name
            ));
            patch_instance_status(
                &instances_api,
                instance,
                ClusterInstanceStatus {
                    phase: ClusterInstancePhase::Recycling,
                    provisioned: status.provisioned,
                    bootstrapped: status.bootstrapped,
                    lease_ref: None,
                    active_bootstrap: None,
                    idle_since: None,
                    state_since: Some(chrono::Utc::now().to_rfc3339()),
                    health_failures: status.health_failures,
                    spec_hash: status.spec_hash.clone(),
                    message,
                    ..Default::default()
                },
            )
            .await?;
            Ok(Action::requeue(std::time::Duration::from_secs(10)))
        }
        Err(e) => Err(e.into()),
    }
}

/// For vkobe pools that didn't declare any readiness gates, inject
/// a default `SchedulingProbe` so a cluster that responds at the
/// apiserver but can't actually schedule workloads stays in
/// `Creating` until the stuck-Creating timeout recycles it instead
/// of silently passing as `Ready`.
///
/// Triggered only when the user-supplied list is **empty**. Any
/// non-empty list is treated as "user knows what they want" and
/// passed through unchanged — including a list that contains its
/// own explicit `SchedulingProbe` (e.g. with a non-default
/// namespace), which we'd otherwise duplicate.
fn apply_default_readiness_gates(
    backend_type: BackendType,
    gates: Vec<ReadinessGate>,
) -> Vec<ReadinessGate> {
    if gates.is_empty() && backend_type == BackendType::Vkobe {
        vec![ReadinessGate::SchedulingProbe { namespace: None }]
    } else {
        gates
    }
}

async fn resolve_instance_config(
    client: &Client,
    instance: &ClusterInstance,
    namespace: &str,
    is_deleting: bool,
) -> Result<ResolvedInstanceConfig, InstanceError> {
    if let Some(pool_ref) = &instance.spec.pool_ref {
        let profile = match get_profile(client, &pool_ref.name, namespace).await {
            Some(p) => p,
            None if is_deleting => {
                // ClusterInstances carry the pool as a controller
                // ownerReference, so deleting a ClusterPool cascades a
                // deletionTimestamp onto every child instance — but the pool
                // may already be gone by the time we reconcile the child.
                // Failing here would deadlock the delete: reconcile returns
                // Err before the finalizer path runs, so backend cleanup
                // never happens and the instance is stuck deleting forever
                // (#95-adjacent). Fall back to a config derived from the
                // instance's own `status.created_with` (the delete path
                // already pins the backend via `created_with`), so teardown
                // can still tear down the right backend resources and then
                // release the finalizer.
                return Ok(deletion_fallback_config(instance, &pool_ref.name));
            }
            None => {
                return Err(anyhow::anyhow!("Owning pool {} not found", pool_ref.name).into());
            }
        };
        let backend_type = profile.spec.backend.backend_type.clone();
        let owner_name = profile.name_any();
        let spec = profile.spec;
        // Thread the pool-level `spec.resources` into the per-instance
        // `ClusterConfig` so the backend can stamp it onto every container
        // it creates. Without this, pool-level limits are silently dropped
        // and pods land as BestEffort — the first thing kubelet evicts
        // under host pressure.
        let mut cluster = spec.cluster;
        cluster.resources = spec.resources;
        // Stamp the owning pool name so the backend can apply a
        // `kobe.kunobi.ninja/pool=<name>` label on every pod it creates.
        // Lets the inter-instance spread anti-affinity scope to
        // siblings of the SAME pool rather than every kobe-managed
        // server pod on the host cluster.
        cluster.pool_name = Some(owner_name.clone());
        return Ok(ResolvedInstanceConfig {
            owner_name,
            backend: spec.backend,
            cluster,
            addons: spec.addons,
            bootstraps: spec.bootstraps,
            health_check: spec.health_check,
            readiness_gates: apply_default_readiness_gates(backend_type, spec.readiness_gates),
            snapshot: spec.snapshot,
        });
    }

    let backend = instance
        .spec
        .backend
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Standalone ClusterInstance missing spec.backend"))?;
    let cluster = instance
        .spec
        .cluster
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Standalone ClusterInstance missing spec.cluster"))?;

    let backend_type = backend.backend_type.clone();
    Ok(ResolvedInstanceConfig {
        owner_name: instance.name_any(),
        backend,
        cluster,
        addons: instance.spec.addons.clone(),
        bootstraps: instance.spec.bootstraps.clone(),
        health_check: instance.spec.health_check.clone(),
        readiness_gates: apply_default_readiness_gates(
            backend_type,
            instance.spec.readiness_gates.clone(),
        ),
        snapshot: instance.spec.snapshot.clone(),
    })
}

/// Build a minimal [`ResolvedInstanceConfig`] for the delete path when the
/// owning pool is gone. Only `backend.backend_type` and `owner_name` are
/// load-bearing for teardown — `delete_instance_backend` reads the backend
/// type (further refined by `status.created_with` pinning) and ignores the
/// cluster/addon/bootstrap fields. We seed the backend type from
/// `status.created_with.backend_type` (the authoritative provenance), then
/// fall back to the instance's own `spec.backend` for pre-provenance
/// instances, defaulting otherwise.
fn deletion_fallback_config(
    instance: &ClusterInstance,
    owner_name: &str,
) -> ResolvedInstanceConfig {
    let backend_type = instance
        .status
        .as_ref()
        .and_then(|s| s.created_with.as_ref())
        .and_then(|cw| cw.backend_type.clone())
        .or_else(|| {
            instance
                .spec
                .backend
                .as_ref()
                .map(|b| b.backend_type.clone())
        })
        .unwrap_or_default();

    // Carry through any per-instance backend config (capi/vkobe/vcluster) the
    // instance itself recorded, so `backend_dispatch_for_config` can construct
    // the backend without the pool. Pool-backed instances usually have an
    // empty `spec.backend`; the backend constructors tolerate `None` configs.
    let mut backend = instance.spec.backend.clone().unwrap_or_default();
    backend.backend_type = backend_type;

    ResolvedInstanceConfig {
        owner_name: owner_name.to_string(),
        backend,
        cluster: instance.spec.cluster.clone().unwrap_or_default(),
        addons: Vec::new(),
        bootstraps: Vec::new(),
        health_check: None,
        readiness_gates: Vec::new(),
        snapshot: None,
    }
}

/// Read the owning ClusterPool's `status.goldenGeneration` — the generation at
/// which its golden backup was actually built. Returns `None` when the profile
/// is absent (e.g. a standalone instance) or has no golden backup recorded yet,
/// in which case a fresh create is the correct behavior.
async fn golden_generation_for<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    owner_name: &str,
) -> Option<i64> {
    let pools: Api<ClusterPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    pools
        .get(owner_name)
        .await
        .ok()
        .and_then(|p| p.status)
        .and_then(|s| s.golden_generation)
}

async fn provision_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
    owner_ref: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
) -> Result<(), InstanceError> {
    let is_k3s = matches!(config.backend.backend_type, BackendType::K3s);

    if !is_k3s
        && let (Some(velero), Some(snapshot)) = (&ctx.velero, &config.snapshot)
        && snapshot.enabled
    {
        // The golden backup is built at the profile's metadata.generation and
        // recorded in its status.goldenGeneration. Look the backup up at THAT
        // generation rather than a hardcoded gen 1, which silently 404s (and so
        // skips restore entirely) for any pool whose spec has ever been edited.
        // `None` => no golden backup recorded yet, so fall through to a fresh
        // create.
        let generation = golden_generation_for(ctx, &config.owner_name).await;
        if let Some(generation) = generation
            && let Ok(Some(backup_name)) = velero
                .get_golden_backup(&config.owner_name, snapshot, generation)
                .await
        {
            info!(
                instance = %name,
                owner = %config.owner_name,
                backup = %backup_name,
                "Restoring instance from golden backup"
            );
            if velero
                .restore_from_golden(&backup_name, snapshot, &config.owner_name, namespace)
                .await
                .is_ok()
            {
                crate::metrics::PROVISION_METHOD
                    .with_label_values(&[config.owner_name.as_str(), "restore"])
                    .inc();
                return Ok(());
            }
            warn!(instance = %name, backup = %backup_name, "Golden restore failed, falling back to fresh create");
        }
    }

    create_instance_backend(ctx, config, name, namespace, owner_ref).await?;
    crate::metrics::PROVISION_METHOD
        .with_label_values(&[config.owner_name.as_str(), "fresh"])
        .inc();
    Ok(())
}

async fn evaluate_instance_readiness<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
) -> Result<bool, InstanceError> {
    for gate in &config.readiness_gates {
        match check_instance_readiness_gate(ctx, config, name, namespace, gate).await {
            Ok(true) => {
                debug!(instance = %name, gate = ?gate, "Readiness gate passed");
            }
            Ok(false) => {
                debug!(instance = %name, gate = ?gate, "Readiness gate not yet satisfied");
                return Ok(false);
            }
            Err(e) => {
                // Use `{e:#}` (anyhow alternate Display) to surface the
                // full error chain — every `with_context(|| ...)` wrap
                // and the underlying root cause. The plain `{e}` only
                // shows the outermost message, which buried the actual
                // SSA / API error during the v0.22.x debug session and
                // forced reproduction work to recover the chain.
                warn!(
                    instance = %name,
                    gate = ?gate,
                    error = %format!("{e:#}"),
                    "Readiness gate check failed"
                );
                return Ok(false);
            }
        }
    }

    match check_instance_health(ctx, config, name, namespace).await {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
        Err(e) => {
            warn!(
                instance = %name,
                error = %format!("{e:#}"),
                "Health probe failed during readiness evaluation"
            );
            Ok(false)
        }
    }
}

async fn evaluate_ready_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    instance: &ClusterInstance,
    name: &str,
    namespace: &str,
    status: &ClusterInstanceStatus,
) -> Result<Action, InstanceError> {
    let (interval_secs, threshold) = config
        .health_check
        .as_ref()
        .map(|hc| (hc.interval_seconds, hc.failure_threshold))
        .unwrap_or((30, 3));

    match check_instance_health(ctx, config, name, namespace).await {
        Ok(true) => {
            if status.health_failures != 0 {
                let instances_api: Api<ClusterInstance> =
                    Api::namespaced(ctx.client.clone(), namespace);
                patch_instance_status(
                    &instances_api,
                    instance,
                    ClusterInstanceStatus {
                        phase: ClusterInstancePhase::Ready,
                        provisioned: status.provisioned,
                        bootstrapped: status.bootstrapped,
                        lease_ref: status.lease_ref.clone(),
                        active_bootstrap: status.active_bootstrap.clone(),
                        idle_since: status.idle_since.clone(),
                        state_since: status.state_since.clone(),
                        health_failures: 0,
                        spec_hash: status.spec_hash.clone(),
                        message: Some("ready; health check recovered".into()),
                        ..Default::default()
                    },
                )
                .await?;
            }
            Ok(Action::requeue(std::time::Duration::from_secs(
                interval_secs.into(),
            )))
        }
        Ok(false) => {
            let failures = status.health_failures + 1;
            let over_threshold = failures >= threshold;
            let next_phase = if over_threshold {
                ClusterInstancePhase::Recycling
            } else {
                ClusterInstancePhase::Ready
            };
            let message = Some(if over_threshold {
                format!("recycling: health check failed {failures}/{threshold} times")
            } else {
                format!("health check failing ({failures}/{threshold})")
            });
            let instances_api: Api<ClusterInstance> =
                Api::namespaced(ctx.client.clone(), namespace);
            patch_instance_status(
                &instances_api,
                instance,
                ClusterInstanceStatus {
                    phase: next_phase,
                    provisioned: status.provisioned,
                    bootstrapped: status.bootstrapped,
                    lease_ref: if over_threshold {
                        None
                    } else {
                        status.lease_ref.clone()
                    },
                    active_bootstrap: None,
                    idle_since: if over_threshold {
                        None
                    } else {
                        status.idle_since.clone()
                    },
                    state_since: Some(chrono::Utc::now().to_rfc3339()),
                    health_failures: failures,
                    spec_hash: status.spec_hash.clone(),
                    message,
                    ..Default::default()
                },
            )
            .await?;
            Ok(Action::requeue(std::time::Duration::from_secs(
                interval_secs.into(),
            )))
        }
        Err(e) => {
            warn!(
                instance = %name,
                error = %format!("{e:#}"),
                "Health probe errored for ready instance"
            );
            Ok(Action::requeue(std::time::Duration::from_secs(
                interval_secs.into(),
            )))
        }
    }
}

fn backend_dispatch_for_config<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
) -> Result<crate::backend::BackendDispatch, InstanceError> {
    if let Some(factory) = &ctx.factory {
        let profile = synthetic_profile(config);
        Ok(factory.backend_for(&profile)?)
    } else {
        match config.backend.backend_type {
            crate::crd::BackendType::K3s => Ok(crate::backend::BackendDispatch::K3s(
                crate::backend::K3sBackend::new(ctx.client.clone(), Default::default()),
            )),
            crate::crd::BackendType::K0s => Ok(crate::backend::BackendDispatch::K0s(
                crate::backend::K0sBackend::new(ctx.client.clone(), Default::default()),
            )),
            crate::crd::BackendType::Capi => {
                let capi = config
                    .backend
                    .capi
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Instance missing capi backend config"))?;
                Ok(crate::backend::BackendDispatch::Capi(
                    crate::backend::CapiBackend::new(ctx.client.clone(), capi),
                ))
            }
            crate::crd::BackendType::Vkobe => Ok(crate::backend::BackendDispatch::Vkobe(
                crate::backend::VkobeBackend::new(ctx.client.clone(), config.backend.vkobe.clone()),
            )),
            crate::crd::BackendType::Vcluster => Ok(crate::backend::BackendDispatch::Vcluster(
                crate::backend::VclusterBackend::new(
                    ctx.client.clone(),
                    config.backend.vcluster.clone(),
                ),
            )),
        }
    }
}

fn synthetic_profile(config: &ResolvedInstanceConfig) -> ClusterPool {
    ClusterPool {
        metadata: kube::core::ObjectMeta {
            name: Some(config.owner_name.clone()),
            ..Default::default()
        },
        spec: crate::crd::ClusterPoolSpec {
            size: 1,
            ttl: "2h".to_string(),
            backend: config.backend.clone(),
            cluster: config.cluster.clone(),
            addons: config.addons.clone(),
            bootstraps: config.bootstraps.clone(),
            resources: config.cluster.resources.clone(),
            health_check: config.health_check.clone(),
            readiness_gates: config.readiness_gates.clone(),
            scaling: None,
            upgrade_policy: None,
            diagnostics: None,
            snapshot: config.snapshot.clone(),
        },
        status: None,
    }
}

async fn reconcile_instance_bootstraps<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    instance: &ClusterInstance,
    name: &str,
    namespace: &str,
) -> Result<Option<String>, anyhow::Error> {
    let plans = resolve_bootstrap_jobs(&ctx.client, namespace, &config.bootstraps).await?;
    if plans.is_empty() {
        return Ok(None);
    }

    let jobs_api: Api<Job> = Api::namespaced(ctx.client.clone(), namespace);

    for plan in plans {
        let job_name = bootstrap_job_name(name, &plan.name);
        match jobs_api.get(&job_name).await {
            Ok(job) => {
                if job_succeeded(&job) {
                    debug!(
                        instance = %name,
                        bootstrap = %plan.name,
                        job = %job_name,
                        "Bootstrap job already completed"
                    );
                    continue;
                }

                if let Some(message) = failed_job_message(&job) {
                    anyhow::bail!(
                        "Bootstrap '{}' failed in Job {}: {}",
                        plan.name,
                        job_name,
                        message
                    );
                }

                info!(
                    instance = %name,
                    bootstrap = %plan.name,
                    job = %job_name,
                    "Waiting for bootstrap job to complete"
                );
                return Ok(Some(plan.name));
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                let job = build_bootstrap_job(instance, namespace, &job_name, &plan);
                info!(
                    instance = %name,
                    bootstrap = %plan.name,
                    job = %job_name,
                    image = %plan.image,
                    "Creating bootstrap job"
                );
                jobs_api
                    .create(&PostParams::default(), &job)
                    .await
                    .with_context(|| format!("Failed to create bootstrap Job {job_name}"))?;
                return Ok(Some(plan.name));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to read bootstrap Job {job_name}"));
            }
        }
    }

    Ok(None)
}

fn build_bootstrap_job(
    instance: &ClusterInstance,
    namespace: &str,
    job_name: &str,
    plan: &BootstrapJobPlan,
) -> Job {
    let instance_name = instance.name_any();
    let kubeconfig_secret_name = format!("{instance_name}-kubeconfig");

    let labels = BTreeMap::from([
        (
            "app.kubernetes.io/managed-by".to_string(),
            "kobe".to_string(),
        ),
        (
            "kobe.kunobi.ninja/instance".to_string(),
            instance_name.clone(),
        ),
        ("kobe.kunobi.ninja/bootstrap".to_string(), plan.name.clone()),
        (
            "kobe.kunobi.ninja/cluster".to_string(),
            instance_name.clone(),
        ),
    ]);

    let mut env = vec![EnvVar {
        name: "KUBECONFIG".to_string(),
        value: Some("/bootstrap/kubeconfig".to_string()),
        ..Default::default()
    }];
    env.extend(plan.env.iter().map(|(key, value)| EnvVar {
        name: key.clone(),
        value: Some(value.clone()),
        ..Default::default()
    }));

    Job {
        metadata: ObjectMeta {
            name: Some(job_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: instance.controller_owner_ref(&()).map(|owner| vec![owner]),
            ..Default::default()
        },
        spec: Some(JobSpec {
            backoff_limit: Some(0),
            ttl_seconds_after_finished: Some(3600),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    automount_service_account_token: Some(false),
                    restart_policy: Some("Never".to_string()),
                    containers: vec![Container {
                        name: "bootstrap".to_string(),
                        image: Some(plan.image.clone()),
                        image_pull_policy: plan.image_pull_policy.clone(),
                        command: (!plan.command.is_empty()).then_some(plan.command.clone()),
                        args: (!plan.args.is_empty()).then_some(plan.args.clone()),
                        env: Some(env),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "kubeconfig".to_string(),
                            mount_path: "/bootstrap".to_string(),
                            read_only: Some(true),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "kubeconfig".to_string(),
                        secret: Some(SecretVolumeSource {
                            secret_name: Some(kubeconfig_secret_name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn bootstrap_job_name(instance_name: &str, bootstrap_name: &str) -> String {
    let raw = format!("{instance_name}-bootstrap-{bootstrap_name}");
    if raw.len() <= 63 {
        return raw;
    }

    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    let suffix = format!("{:08x}", hasher.finish() as u32);
    let prefix_len = 63usize.saturating_sub(suffix.len() + 1);
    format!("{}-{}", &raw[..prefix_len], suffix)
}

fn job_succeeded(job: &Job) -> bool {
    job.status
        .as_ref()
        .and_then(|status| status.succeeded)
        .unwrap_or(0)
        > 0
        || job
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Complete" && condition.status == "True")
            })
}

fn failed_job_message(job: &Job) -> Option<String> {
    job.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|condition| condition.type_ == "Failed" && condition.status == "True")
        })
        .map(|condition| {
            condition
                .message
                .clone()
                .or_else(|| condition.reason.clone())
                .unwrap_or_else(|| "job failed".to_string())
        })
}

async fn create_instance_backend<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
    owner_ref: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
) -> Result<(), anyhow::Error> {
    let mut addons = config.addons.clone();
    addons.extend(resolve_bootstrap_addons(&ctx.client, namespace, &config.bootstraps).await?);

    if ctx.factory.is_some() {
        let backend = backend_dispatch_for_config(ctx, config)?;
        backend
            .create(name, namespace, &config.cluster, &addons, owner_ref)
            .await
    } else {
        ctx.backend
            .create(name, namespace, &config.cluster, &addons, owner_ref)
            .await
    }
}

async fn delete_instance_backend<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    instance: &ClusterInstance,
    name: &str,
    namespace: &str,
) -> Result<(), anyhow::Error> {
    if ctx.factory.is_some() {
        // Backend pinning: when the instance's status records a
        // `created_with.backend_type`, dispatch via that backend rather
        // than the pool's *current* spec. Otherwise a pool-level
        // backend migration (e.g., vkobe→vcluster) would route the
        // delete through the wrong backend, leaving the original
        // resources orphaned and the new backend hitting "release not
        // found" / "namespace doesn't exist" errors in a tight loop.
        //
        // Fallback to pool-spec backend for instances created by
        // kobe < 0.23.1 (when this field was introduced).
        let pinned = instance
            .status
            .as_ref()
            .and_then(|s| s.created_with.as_ref())
            .and_then(|cw| cw.backend_type.as_ref());
        let backend = if let Some(pinned_type) = pinned
            && *pinned_type != config.backend.backend_type
        {
            // Pool spec drifted; construct a config with the pinned
            // backend type so the dispatch picks the right backend.
            let mut overridden = config.clone();
            overridden.backend.backend_type = pinned_type.clone();
            tracing::debug!(
                instance = %name,
                pinned = ?pinned_type,
                pool_backend = ?config.backend.backend_type,
                "delete using pinned backend (overrides pool spec backend)"
            );
            backend_dispatch_for_config(ctx, &overridden)?
        } else {
            backend_dispatch_for_config(ctx, config)?
        };
        backend.delete(name, namespace).await
    } else {
        ctx.backend.delete(name, namespace).await
    }
}

/// Best-effort cleanup of host-side resources that a backend's `delete()`
/// doesn't own and that lack an `OwnerReference` Kubernetes GC can follow.
///
/// # Why this exists
///
/// The in-house vkobe backend ships a `kobe-sync` sidecar that **projects**
/// virtual-cluster resources to host pods in the operator's namespace. Two
/// classes of host objects are created without an `OwnerReference` linking
/// back to the parent `ClusterInstance` (or to any object that
/// `delete_instance_backend()` tears down):
///
/// 1. **Readiness-probe pods** — created in the *virtual* `kube-system` as
///    `kobe-readiness-probe`, projected by `PodSyncer` to host as
///    `kobe-readiness-probe-{instance}-x-kube-system-x-vc`. When the
///    instance is recycled, the apiserver Deployment + its kine PVC are
///    destroyed but this projected pod is orphaned.
///
/// 2. **User workload pods** projected from virtual namespaces (e.g.
///    Flux controllers) — naming convention `<name>-x-<vns>-x-vc`. Same
///    leak pattern.
///
/// At `an internal cluster` over 8 days of failed `ci-vkobe-flux` cycling we
/// accumulated ~700 leaked probes + ~170 leaked projected workloads; their
/// CPU/RAM resource requests eventually exhausted cluster capacity and
/// blocked new instances from scheduling, manifesting as
/// `FailedScheduling: 0/8 nodes are available: Insufficient cpu`.
///
/// # What this does
///
/// Best-effort delete of:
/// - the well-known probe pod by deterministic name (cheap, targeted)
/// - any pod in the instance's host namespace whose name matches the
///   projection suffix `*-x-{vns}-x-vc` for the well-known virtual
///   namespaces (`flux-system`, `default`, `kube-system`,
///   `cert-manager`, `flux-system`). This is a heuristic: kobe-sync does
///   not label projected pods with the owner instance, so we cannot
///   identify them precisely. The heuristic is safe because:
///     - the matching only happens in the operator's host namespace
///     - the suffix is unique to projected pods (no user-created pod
///       follows that exact pattern)
///     - if a pod is genuinely shared between two pools (which kobe-sync
///       does not currently do), the next reconcile of the surviving
///       instance will re-project it
///
/// # Why best-effort
///
/// Failure here is intentionally non-fatal: the instance CR delete must
/// still proceed. Leaks reappearing is a regression we can detect and
/// alert on; failing to delete the CR would block the pool from
/// recovering. A cleanup failure is logged as `warn!` so it surfaces to
/// the operator's log but doesn't poison the recycle loop.
///
/// # Backends with self-contained delete
///
/// Backends that scope projection to a per-instance namespace (the
/// proposed `vcluster` backend does this via `helm install --namespace
/// <instance>`) handle cleanup natively when the namespace is deleted.
/// For those backends this function is a no-op (404s on every probe).
async fn cleanup_orphan_projected_resources(client: &Client, instance_name: &str, host_ns: &str) {
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::{DeleteParams, ListParams};

    let pods: Api<Pod> = Api::namespaced(client.clone(), host_ns);

    // 1. Targeted delete of the readiness-probe pod (deterministic name).
    let probe_name = format!("kobe-readiness-probe-{instance_name}-x-kube-system-x-vc");
    match pods.delete(&probe_name, &DeleteParams::default()).await {
        Ok(_) => debug!(
            instance = %instance_name,
            probe = %probe_name,
            "cleaned up legacy projected probe pod"
        ),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // expected: backend doesn't project here, or gate never fired,
            // or another reconcile already cleaned it up
        }
        Err(e) => warn!(
            instance = %instance_name,
            probe = %probe_name,
            error = %format!("{e:#}"),
            "legacy probe pod cleanup failed (non-fatal)"
        ),
    }

    // 2. Heuristic delete of orphaned workload projections from
    //    well-known virtual namespaces. We list pods (un-filtered — kobe-sync
    //    does not label projections by owner) and match the projection name
    //    pattern: `*-x-{vns}-x-vc` where vns is one of the known virtual
    //    namespaces a vkobe-style pool's bootstrap touches.
    //
    //    Conservative filter: we only match if the pod's name *also* contains
    //    the instance name as a substring. This is loose — a pod named
    //    `mysvc-x-flux-system-x-vc` from a different instance won't match
    //    unless its hash collides with `instance_name` — but pod names from
    //    Kubernetes ReplicaSets always include the RS hash, so this works for
    //    Deployments. Bare pods or StatefulSets may slip through; we accept
    //    that as the cost of a heuristic.
    //
    //    Production traces show ~170 such orphans across 8 days. Even if this
    //    heuristic catches only 80%, leak rate becomes manageable.
    const PROJECTED_VIRTUAL_NAMESPACES: &[&str] = &[
        "flux-system",
        "default",
        "kube-system",
        "cert-manager",
        "monitoring",
    ];

    let list = match pods.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                instance = %instance_name,
                error = %format!("{e:#}"),
                "could not list pods for orphan cleanup (non-fatal)"
            );
            return;
        }
    };

    for pod in list.items {
        let Some(pod_name) = pod.metadata.name.as_ref() else {
            continue;
        };
        // Filter: name must end with one of the projection suffixes AND
        // contain the instance name as substring.
        let suffix_match = PROJECTED_VIRTUAL_NAMESPACES
            .iter()
            .any(|vns| pod_name.ends_with(&format!("-x-{vns}-x-vc")));
        if !suffix_match {
            continue;
        }
        if !pod_name.contains(instance_name) {
            continue;
        }

        match pods.delete(pod_name, &DeleteParams::default()).await {
            Ok(_) => debug!(
                instance = %instance_name,
                pod = %pod_name,
                "cleaned up orphaned projected workload pod"
            ),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}
            Err(e) => warn!(
                instance = %instance_name,
                pod = %pod_name,
                error = %format!("{e:#}"),
                "orphan workload cleanup failed (non-fatal)"
            ),
        }
    }
}

async fn check_instance_health<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
) -> Result<bool, anyhow::Error> {
    if ctx.factory.is_some() {
        let backend = backend_dispatch_for_config(ctx, config)?;
        backend.check_health(name, namespace).await
    } else {
        ctx.backend.check_health(name, namespace).await
    }
}

async fn check_instance_readiness_gate<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
    gate: &ReadinessGate,
) -> Result<bool, anyhow::Error> {
    if ctx.factory.is_some() {
        let backend = backend_dispatch_for_config(ctx, config)?;
        backend.check_readiness_gate(name, namespace, gate).await
    } else {
        ctx.backend
            .check_readiness_gate(name, namespace, gate)
            .await
    }
}

/// Outcome of resolving a `CIDRClaim` for a `ClusterInstance`.
enum ClaimResolution {
    /// The IPAM controller has bound the claim. The instance can now be
    /// provisioned with these CIDRs.
    Bound(ClusterInstanceNetwork),
    /// The claim exists (we may have just created it) but isn't bound
    /// yet. The IPAM controller is the next mover; we requeue.
    Pending,
    /// The IPAM controller decided the request can't be satisfied
    /// (pool full, requested CIDR overlapping, malformed pool spec).
    /// Carries the human-readable reason for log surfacing.
    Conflict(String),
}

/// Ensure a `CIDRClaim` exists for `instance` and return its current
/// resolution.
///
/// Idempotent: the claim's name is fixed at the instance's name, so a
/// retry after a partially-applied create is safe. Owner reference is
/// set to the instance, so kube GC tears the claim down when the
/// instance is deleted — the IPAM controller doesn't need a finalizer
/// because deleting the claim IS releasing the slot.
async fn ensure_claim_bound(
    client: &Client,
    namespace: &str,
    instance: &ClusterInstance,
) -> Result<ClaimResolution, InstanceError> {
    let claims_api: Api<CIDRClaim> = Api::namespaced(client.clone(), namespace);
    let name = instance.name_any();

    // Fast path: claim already exists, look at its phase.
    match claims_api.get(&name).await {
        Ok(claim) => {
            return Ok(claim_resolution(&claim));
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // Fall through to create.
        }
        Err(e) => return Err(InstanceError::Kube(e)),
    }

    let owner = instance.controller_owner_ref(&()).map(|o| vec![o]);
    let mut labels = BTreeMap::new();
    if let Some(pool) = instance.spec.pool_ref.as_ref() {
        labels.insert("kobe.kunobi.ninja/pool".to_string(), pool.name.clone());
    }
    let claim = CIDRClaim {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: owner,
            labels: if labels.is_empty() {
                None
            } else {
                Some(labels)
            },
            ..Default::default()
        },
        spec: CIDRClaimSpec {
            requested_service_cidr: None,
            requested_cluster_cidr: None,
        },
        status: None,
    };

    match claims_api.create(&PostParams::default(), &claim).await {
        Ok(_) => {
            info!(instance = %name, "Created CIDRClaim");
            Ok(ClaimResolution::Pending)
        }
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            // Lost a race; refetch and read its phase.
            let claim = claims_api.get(&name).await?;
            Ok(claim_resolution(&claim))
        }
        Err(e) => Err(InstanceError::Kube(e)),
    }
}

fn claim_resolution(claim: &CIDRClaim) -> ClaimResolution {
    let Some(status) = claim.status.as_ref() else {
        return ClaimResolution::Pending;
    };
    match &status.phase {
        CIDRClaimPhase::Bound => match (&status.service_cidr, &status.cluster_cidr) {
            (Some(svc), Some(cls)) => ClaimResolution::Bound(ClusterInstanceNetwork {
                service_cidr: svc.clone(),
                cluster_cidr: cls.clone(),
            }),
            // Phase says Bound but CIDRs missing — treat as Pending so
            // the IPAM controller has a chance to repair.
            _ => ClaimResolution::Pending,
        },
        CIDRClaimPhase::Conflict => ClaimResolution::Conflict(
            status
                .message
                .clone()
                .unwrap_or_else(|| "unspecified conflict".to_string()),
        ),
        CIDRClaimPhase::Pending => ClaimResolution::Pending,
    }
}

/// Add `finalizer` to the instance's `metadata.finalizers` list, idempotently.
///
/// Uses a JSON Merge Patch that REPLACES the entire `finalizers` array with
/// the existing values plus our finalizer. RFC 7396 specifies that arrays
/// in a Merge Patch overwrite the target rather than merging element-wise,
/// so we read-modify-write the whole list. The read is already done by the
/// caller (the `instance` Arc), so there's no extra round-trip.
async fn add_finalizer(
    instances_api: &Api<ClusterInstance>,
    instance: &ClusterInstance,
    finalizer: &str,
) -> Result<(), kube::Error> {
    let mut finalizers = instance.metadata.finalizers.clone().unwrap_or_default();
    if finalizers.iter().any(|f| f == finalizer) {
        return Ok(());
    }
    finalizers.push(finalizer.to_string());
    let patch = serde_json::json!({
        "metadata": { "finalizers": finalizers }
    });
    instances_api
        .patch(
            &instance.name_any(),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Remove `finalizer` from the instance's `metadata.finalizers` list,
/// idempotently. Same array-replace semantics as `add_finalizer`.
async fn remove_finalizer(
    instances_api: &Api<ClusterInstance>,
    instance: &ClusterInstance,
    finalizer: &str,
) -> Result<(), kube::Error> {
    let Some(existing) = instance.metadata.finalizers.as_ref() else {
        return Ok(());
    };
    let remaining: Vec<String> = existing
        .iter()
        .filter(|f| f.as_str() != finalizer)
        .cloned()
        .collect();
    if remaining.len() == existing.len() {
        // Finalizer wasn't present — nothing to do, avoid a no-op patch.
        return Ok(());
    }
    let patch = serde_json::json!({
        "metadata": { "finalizers": remaining }
    });
    instances_api
        .patch(
            &instance.name_any(),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Stable, machine-readable name for a phase, used as a condition
/// `reason` (e.g. the `Ready=False` reason is the phase that is blocking
/// readiness). Kept PascalCase so it reads as a k8s condition reason.
fn phase_reason(phase: &ClusterInstancePhase) -> &'static str {
    match phase {
        ClusterInstancePhase::Creating => "Creating",
        ClusterInstancePhase::Ready => "Ready",
        ClusterInstancePhase::Leased => "Leased",
        ClusterInstancePhase::Recycling => "Recycling",
        ClusterInstancePhase::Unhealthy => "Unhealthy",
        ClusterInstancePhase::Failed => "Failed",
    }
}

/// Derive the standard condition set for a `ClusterInstance` from its
/// status fields. PURE: no I/O, no clock — `now` is passed in so callers
/// control the timestamp and tests are deterministic.
///
/// Emits three conditions:
/// - `Provisioned`: `True` iff `status.provisioned`.
/// - `Ready`: `True` iff `phase` is `Ready` or `Leased`.
/// - `Bootstrapped`: `True` iff `status.bootstrapped`.
///
/// `lastTransitionTime` follows core/v1 / `KobeStoreCondition` semantics:
/// for each derived condition we look up the matching `condition_type` in
/// `prev`; if found AND its `status` is unchanged we keep the previous
/// timestamp, otherwise we stamp `now`. So the time only moves when the
/// condition actually flips (or is brand new), never on a redundant
/// reconcile.
fn derive_instance_conditions(
    status: &ClusterInstanceStatus,
    prev: &[ClusterInstanceCondition],
    now: &str,
) -> Vec<ClusterInstanceCondition> {
    let message = status.message.clone().unwrap_or_default();
    let bool_status = |b: bool| if b { "True" } else { "False" };

    // Helper: build one condition, preserving lastTransitionTime when the
    // status is unchanged vs. `prev`.
    let build = |condition_type: &str, new_status: &str, reason: String, message: String| {
        let last_transition_time = prev
            .iter()
            .find(|c| c.condition_type == condition_type)
            .filter(|c| c.status == new_status)
            .and_then(|c| c.last_transition_time.clone())
            .or_else(|| Some(now.to_string()));
        ClusterInstanceCondition {
            condition_type: condition_type.to_string(),
            status: new_status.to_string(),
            reason,
            message,
            last_transition_time,
        }
    };

    let is_ready = matches!(
        status.phase,
        ClusterInstancePhase::Ready | ClusterInstancePhase::Leased
    );
    let phase = phase_reason(&status.phase);

    vec![
        build(
            "Provisioned",
            bool_status(status.provisioned),
            if status.provisioned {
                "Provisioned".to_string()
            } else {
                // Not provisioned: surface the phase so a stuck create vs
                // a fresh instance is distinguishable.
                phase.to_string()
            },
            message.clone(),
        ),
        build(
            "Ready",
            bool_status(is_ready),
            // Reason is always the phase: for Ready=True it's Ready/Leased,
            // for Ready=False it names what's blocking (Creating/Failed/…).
            phase.to_string(),
            message.clone(),
        ),
        build(
            "Bootstrapped",
            bool_status(status.bootstrapped),
            if status.bootstrapped {
                "Bootstrapped".to_string()
            } else {
                phase.to_string()
            },
            message,
        ),
    ]
}

/// Central status-write helper. Every status mutation in this controller
/// routes through here, so conditions are derived in ONE place rather
/// than at the ~13 construction sites (which just leave
/// `conditions: Vec::new()` — it is overwritten here).
///
/// Derives `status.conditions` from the just-built `status`, preserving
/// `lastTransitionTime` against the instance's *current* on-disk
/// conditions (`instance.status.conditions`), then JSON-Merge-Patches
/// `{ "status": status }`.
async fn patch_instance_status(
    instances_api: &Api<ClusterInstance>,
    instance: &ClusterInstance,
    mut status: ClusterInstanceStatus,
) -> Result<(), kube::Error> {
    let prev = instance
        .status
        .as_ref()
        .map(|s| s.conditions.as_slice())
        .unwrap_or(&[]);
    let now = chrono::Utc::now().to_rfc3339();
    status.conditions = derive_instance_conditions(&status, prev, &now);

    let patch = serde_json::json!({ "status": status });
    instances_api
        .patch_status(
            &instance.name_any(),
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

async fn get_profile(client: &Client, name: &str, namespace: &str) -> Option<ClusterPool> {
    let profiles_api: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    profiles_api.get(name).await.ok()
}

fn error_policy<B: ClusterBackend>(
    _instance: Arc<ClusterInstance>,
    error: &InstanceError,
    _ctx: Arc<InstanceContext<B>>,
) -> Action {
    error!("Instance reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockBackend;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Find a derived condition by type. Panics if absent (tests assert
    /// all three are always present).
    fn cond<'a>(conds: &'a [ClusterInstanceCondition], ty: &str) -> &'a ClusterInstanceCondition {
        conds
            .iter()
            .find(|c| c.condition_type == ty)
            .unwrap_or_else(|| panic!("missing condition {ty}"))
    }

    fn status_for(
        phase: ClusterInstancePhase,
        provisioned: bool,
        bootstrapped: bool,
    ) -> ClusterInstanceStatus {
        ClusterInstanceStatus {
            phase,
            provisioned,
            bootstrapped,
            message: Some("hello".into()),
            ..Default::default()
        }
    }

    #[test]
    fn derive_conditions_ready_phase_is_ready_true() {
        let now = "2026-01-01T00:00:00Z";
        for phase in [ClusterInstancePhase::Ready, ClusterInstancePhase::Leased] {
            let phase_name = phase_reason(&phase).to_string();
            let st = status_for(phase, true, true);
            let conds = derive_instance_conditions(&st, &[], now);

            let ready = cond(&conds, "Ready");
            assert_eq!(ready.status, "True");
            assert_eq!(ready.reason, phase_name);
            assert_eq!(ready.message, "hello");

            assert_eq!(cond(&conds, "Provisioned").status, "True");
            assert_eq!(cond(&conds, "Provisioned").reason, "Provisioned");
            assert_eq!(cond(&conds, "Bootstrapped").status, "True");
            assert_eq!(cond(&conds, "Bootstrapped").reason, "Bootstrapped");
        }
    }

    #[test]
    fn derive_conditions_non_ready_phase_is_ready_false_with_phase_reason() {
        let now = "2026-01-01T00:00:00Z";
        for phase in [
            ClusterInstancePhase::Creating,
            ClusterInstancePhase::Recycling,
            ClusterInstancePhase::Unhealthy,
            ClusterInstancePhase::Failed,
        ] {
            let phase_name = phase_reason(&phase).to_string();
            // not provisioned, not bootstrapped
            let st = status_for(phase, false, false);
            let conds = derive_instance_conditions(&st, &[], now);

            let ready = cond(&conds, "Ready");
            assert_eq!(ready.status, "False");
            assert_eq!(ready.reason, phase_name, "Ready reason names the phase");

            // Provisioned False -> reason is the phase.
            let prov = cond(&conds, "Provisioned");
            assert_eq!(prov.status, "False");
            assert_eq!(prov.reason, phase_name);

            // Bootstrapped False -> reason is the phase.
            let boot = cond(&conds, "Bootstrapped");
            assert_eq!(boot.status, "False");
            assert_eq!(boot.reason, phase_name);
        }
    }

    #[test]
    fn derive_conditions_provisioned_and_bootstrapped_toggle() {
        let now = "2026-01-01T00:00:00Z";
        // Provisioned but not yet bootstrapped, still Creating.
        let st = status_for(ClusterInstancePhase::Creating, true, false);
        let conds = derive_instance_conditions(&st, &[], now);
        assert_eq!(cond(&conds, "Provisioned").status, "True");
        assert_eq!(cond(&conds, "Bootstrapped").status, "False");
        assert_eq!(cond(&conds, "Ready").status, "False");
    }

    #[test]
    fn derive_conditions_message_defaults_to_empty_when_none() {
        let now = "2026-01-01T00:00:00Z";
        let st = ClusterInstanceStatus {
            phase: ClusterInstancePhase::Creating,
            message: None,
            ..Default::default()
        };
        let conds = derive_instance_conditions(&st, &[], now);
        assert_eq!(cond(&conds, "Ready").message, "");
    }

    #[test]
    fn derive_conditions_preserves_transition_time_when_status_unchanged() {
        let prev_time = "2025-12-31T00:00:00Z";
        let now = "2026-01-01T00:00:00Z";
        // Previous: Ready=True (Leased phase).
        let prev = vec![ClusterInstanceCondition {
            condition_type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "Leased".to_string(),
            message: "old".to_string(),
            last_transition_time: Some(prev_time.to_string()),
        }];
        // Now: still Ready=True (Ready phase). Status unchanged -> keep time.
        let st = status_for(ClusterInstancePhase::Ready, true, true);
        let conds = derive_instance_conditions(&st, &prev, now);
        let ready = cond(&conds, "Ready");
        assert_eq!(ready.status, "True");
        assert_eq!(
            ready.last_transition_time.as_deref(),
            Some(prev_time),
            "transition time preserved when status does not flip"
        );
    }

    #[test]
    fn derive_conditions_updates_transition_time_when_status_flips() {
        let prev_time = "2025-12-31T00:00:00Z";
        let now = "2026-01-01T00:00:00Z";
        // Previous: Ready=True.
        let prev = vec![ClusterInstanceCondition {
            condition_type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "Ready".to_string(),
            message: String::new(),
            last_transition_time: Some(prev_time.to_string()),
        }];
        // Now: phase Failed -> Ready=False. Status flipped -> stamp now.
        let st = status_for(ClusterInstancePhase::Failed, true, false);
        let conds = derive_instance_conditions(&st, &prev, now);
        let ready = cond(&conds, "Ready");
        assert_eq!(ready.status, "False");
        assert_eq!(
            ready.last_transition_time.as_deref(),
            Some(now),
            "transition time updated when status flips"
        );
    }

    #[test]
    fn derive_conditions_stamps_now_for_new_condition_type() {
        let now = "2026-01-01T00:00:00Z";
        // prev has only Ready; Provisioned/Bootstrapped are brand new.
        let prev = vec![ClusterInstanceCondition {
            condition_type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "Creating".to_string(),
            message: String::new(),
            last_transition_time: Some("2025-01-01T00:00:00Z".to_string()),
        }];
        let st = status_for(ClusterInstancePhase::Creating, true, false);
        let conds = derive_instance_conditions(&st, &prev, now);
        // Provisioned is new -> stamped now.
        assert_eq!(
            cond(&conds, "Provisioned").last_transition_time.as_deref(),
            Some(now)
        );
        // Ready unchanged (False) -> preserves old time.
        assert_eq!(
            cond(&conds, "Ready").last_transition_time.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn status_omits_empty_conditions_and_none_message() {
        // A status with no conditions and no message must serialize
        // WITHOUT those keys, so a merge-patch from a writer that did not
        // set them never carries `"conditions": []` / `"message": null`
        // (which would erase another writer's value per RFC 7396).
        let st = ClusterInstanceStatus {
            phase: ClusterInstancePhase::Creating,
            conditions: vec![],
            message: None,
            ..Default::default()
        };
        let json = serde_json::to_value(&st).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            !obj.contains_key("conditions"),
            "empty conditions must be omitted, got: {json}"
        );
        assert!(
            !obj.contains_key("message"),
            "None message must be omitted, got: {json}"
        );
    }

    #[test]
    fn status_serializes_conditions_and_message_when_present() {
        let st = ClusterInstanceStatus {
            phase: ClusterInstancePhase::Ready,
            message: Some("ready".into()),
            conditions: vec![ClusterInstanceCondition {
                condition_type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "Ready".to_string(),
                message: "ready".to_string(),
                last_transition_time: Some("2026-01-01T00:00:00Z".to_string()),
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&st).unwrap();
        assert_eq!(json["message"], "ready");
        assert_eq!(json["conditions"][0]["type"], "Ready");
        assert_eq!(json["conditions"][0]["status"], "True");
        assert_eq!(
            json["conditions"][0]["lastTransitionTime"],
            "2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn standalone_terminal_recycle_respects_grace() {
        let now = chrono::Utc::now();
        let grace = chrono::Duration::minutes(5);
        let recent = (now - chrono::Duration::minutes(1)).to_rfc3339();
        let old = (now - chrono::Duration::minutes(10)).to_rfc3339();

        // Within the grace window: keep for inspection.
        assert!(!standalone_terminal_should_recycle(
            Some(&recent),
            now,
            grace
        ));
        // Past the grace window: recycle to release backend resources.
        assert!(standalone_terminal_should_recycle(Some(&old), now, grace));
        // Missing / unparseable state_since: recycle (never strand a leak).
        assert!(standalone_terminal_should_recycle(None, now, grace));
        assert!(standalone_terminal_should_recycle(
            Some("nonsense"),
            now,
            grace
        ));
    }

    #[test]
    fn reservation_grace_gates_orphan_release() {
        let now = chrono::Utc::now();
        let grace = chrono::Duration::minutes(2);
        let recent = (now - chrono::Duration::seconds(10)).to_rfc3339();
        let old = (now - chrono::Duration::minutes(5)).to_rfc3339();
        // In-flight bind (just became Leased): do not disturb.
        assert!(!reservation_grace_elapsed(Some(&recent), now, grace));
        // Long-stuck reservation: eligible for release.
        assert!(reservation_grace_elapsed(Some(&old), now, grace));
        // Unknown age: conservative — don't release.
        assert!(!reservation_grace_elapsed(None, now, grace));
        assert!(!reservation_grace_elapsed(Some("garbage"), now, grace));
    }

    async fn test_instance_context() -> (Arc<InstanceContext<MockBackend>>, MockServer, MockBackend)
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = MockBackend::new();
        let ctx = Arc::new(InstanceContext {
            client,
            backend: backend.clone(),
            namespace: "test-ns".to_string(),
            factory: None,
            velero: None,
        });
        (ctx, server, backend)
    }

    fn standalone_instance(
        name: &str,
        phase: ClusterInstancePhase,
        provisioned: bool,
        health_failures: u32,
    ) -> Arc<ClusterInstance> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    // Pre-stamp the finalizer so the reconciler exits its
                    // "add finalizer" short-circuit and proceeds to the
                    // phase logic the test is actually exercising.
                    "finalizers": [INSTANCE_FINALIZER]
                },
                "spec": {
                    "backend": {
                        "type": "k3s"
                    },
                    "cluster": {
                        "version": "v1.31.3+k3s1"
                    },
                    "addons": [],
                    "readinessGates": []
                },
                "status": {
                    "phase": phase,
                    "provisioned": provisioned,
                    "leaseRef": null,
                    "healthFailures": health_failures,
                    // Pre-populate the network slot so reconcile skips
                    // the allocation phase. The allocator is exercised
                    // by `pool::cidr_alloc::tests` and (separately) by
                    // a focused reconciler test that mocks the list
                    // endpoint; this fixture is for testing downstream
                    // behaviour assuming allocation already happened.
                    "network": {
                        "serviceCidr": "10.240.0.0/20",
                        "clusterCidr": "10.248.0.0/20"
                    }
                }
            }))
            .unwrap(),
        )
    }

    fn instance_api_response(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": name,
                "namespace": "test-ns"
            },
            "spec": {
                "backend": { "type": "k3s" },
                "cluster": { "version": "v1.31.3+k3s1" }
            },
            "status": {
                "phase": "Creating",
                "provisioned": true
            }
        })
    }

    #[tokio::test]
    async fn standalone_creating_instance_provisions_from_its_own_spec() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance =
            standalone_instance("standalone-1", ClusterInstancePhase::Creating, false, 0);

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/standalone-1/status",
            ))
            .and(body_partial_json(serde_json::json!({
                "status": {
                    "phase": "Creating",
                    "provisioned": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("standalone-1")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
        assert_eq!(backend.call_count().create, 1);
    }

    #[tokio::test]
    async fn standalone_provisioned_instance_promotes_to_ready() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = standalone_instance("standalone-2", ClusterInstancePhase::Creating, true, 0);

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/standalone-2/status",
            ))
            .and(body_partial_json(serde_json::json!({
                "status": {
                    "phase": "Ready",
                    "provisioned": true,
                    "healthFailures": 0
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("standalone-2")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
        let calls = backend.call_count();
        assert_eq!(calls.create, 0);
        assert_eq!(calls.check_health, 1);
    }

    #[tokio::test]
    async fn standalone_ready_instance_recycles_after_health_threshold() {
        let (ctx, server, backend) = test_instance_context().await;
        backend.set_health(false);
        let instance = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": "standalone-3",
                    "namespace": "test-ns",
                    "finalizers": [INSTANCE_FINALIZER]
                },
                "spec": {
                    "backend": { "type": "k3s" },
                    "cluster": { "version": "v1.31.3+k3s1" },
                    "healthCheck": {
                        "intervalSeconds": 10,
                        "failureThreshold": 3
                    }
                },
                "status": {
                    "phase": "Ready",
                    "provisioned": true,
                    "leaseRef": { "name": "lease-a" },
                    "healthFailures": 2
                }
            }))
            .unwrap(),
        );

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/standalone-3/status",
            ))
            .and(body_partial_json(serde_json::json!({
                "status": {
                    "phase": "Recycling",
                    "leaseRef": null,
                    "healthFailures": 3
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("standalone-3")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        assert_eq!(backend.call_count().check_health, 1);
    }

    #[tokio::test]
    async fn standalone_recycling_instance_deletes_backend_and_cr() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance =
            standalone_instance("standalone-4", ClusterInstancePhase::Recycling, true, 0);

        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/standalone-4",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(instance_api_response("standalone-4")),
            )
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::await_change());
        assert_eq!(backend.call_count().delete, 1);
    }

    #[tokio::test]
    async fn leased_instance_with_missing_lease_recycles() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": "leased-1",
                    "namespace": "test-ns",
                    "finalizers": [INSTANCE_FINALIZER]
                },
                "spec": {
                    "backend": { "type": "k3s" },
                    "cluster": { "version": "v1.31.3+k3s1" }
                },
                "status": {
                    "phase": "Leased",
                    "provisioned": true,
                    "leaseRef": { "name": "lease-gone" },
                    "healthFailures": 0
                }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-gone",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/leased-1/status",
            ))
            .and(body_partial_json(serde_json::json!({
                "status": {
                    "phase": "Recycling",
                    "leaseRef": null
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("leased-1")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        let calls = backend.call_count();
        assert_eq!(calls.check_health, 0);
        assert_eq!(calls.delete, 0);
    }

    #[tokio::test]
    async fn leased_instance_with_released_lease_recycles() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": "leased-2",
                    "namespace": "test-ns",
                    "finalizers": [INSTANCE_FINALIZER]
                },
                "spec": {
                    "backend": { "type": "k3s" },
                    "cluster": { "version": "v1.31.3+k3s1" }
                },
                "status": {
                    "phase": "Leased",
                    "provisioned": true,
                    "leaseRef": { "name": "lease-released" },
                    "healthFailures": 0
                }
            }))
            .unwrap(),
        );

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-released",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "lease-released",
                    "namespace": "test-ns"
                },
                "spec": {
                    "poolRef": "ci-small",
                    "ttl": "1h",
                    "requester": { "type": "ssh:user", "identity": "user" }
                },
                "status": {
                    "phase": "Released"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/leased-2/status",
            ))
            .and(body_partial_json(serde_json::json!({
                "status": {
                    "phase": "Recycling",
                    "leaseRef": null
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("leased-2")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        let calls = backend.call_count();
        assert_eq!(calls.check_health, 0);
        assert_eq!(calls.delete, 0);
    }

    // === apply_default_readiness_gates ===

    /// vkobe pool with no user-supplied gates gets a default
    /// SchedulingProbe injected. Without this, every default
    /// vkobe pool would silently report Healthy with zero
    /// schedulable nodes — the bug `ci-vkobe-flux` was hiding
    /// behind for 7 days on an internal cluster.
    #[test]
    fn vkobe_pool_with_no_gates_gets_default_scheduling_probe() {
        let gates = apply_default_readiness_gates(BackendType::Vkobe, vec![]);
        assert_eq!(gates.len(), 1);
        assert!(matches!(
            gates[0],
            ReadinessGate::SchedulingProbe { namespace: None }
        ));
    }

    /// k3s/k0s/capi pools do **not** get the default — those backends
    /// run real kubelets so a usable apiserver implies a usable
    /// cluster (modulo whatever readiness gates the user separately
    /// declares for their workloads). The probe is vkobe-specific
    /// because vkobe's no-real-kubelet design is what makes the
    /// silent-no-nodes failure mode possible.
    #[test]
    fn non_vkobe_backends_do_not_get_default_scheduling_probe() {
        for backend in [BackendType::K3s, BackendType::K0s, BackendType::Capi] {
            let gates = apply_default_readiness_gates(backend, vec![]);
            assert!(
                gates.is_empty(),
                "non-vkobe backend should not gain a default gate"
            );
        }
    }

    /// User explicitly declares any non-empty `readiness_gates` list
    /// → don't inject the default. The user knows what they want; a
    /// default added on top would surprise them and slow their pool.
    /// They can still get the probe by adding it to their list.
    #[test]
    fn user_supplied_gates_are_passed_through_unchanged() {
        let user_gates = vec![ReadinessGate::CrdExists {
            name: "kustomizations.kustomize.toolkit.fluxcd.io".to_string(),
        }];
        let result = apply_default_readiness_gates(BackendType::Vkobe, user_gates.clone());
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], ReadinessGate::CrdExists { .. }));
    }

    // === Finalizer (issue #95) ===

    /// Helper: build an instance with optional `deletion_timestamp` and
    /// `finalizers`. Status is intentionally minimal — the finalizer
    /// branches in `reconcile_instance` run before the phase match and
    /// must work regardless of phase / provisioned state.
    fn instance_with_finalizer_state(
        name: &str,
        deletion_timestamp: Option<&str>,
        finalizers: Vec<&str>,
    ) -> Arc<ClusterInstance> {
        let mut metadata = serde_json::json!({
            "name": name,
            "namespace": "test-ns",
            "finalizers": finalizers,
        });
        if let Some(ts) = deletion_timestamp {
            metadata["deletionTimestamp"] = serde_json::Value::String(ts.to_string());
        }
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": metadata,
                "spec": {
                    "backend": { "type": "k3s" },
                    "cluster": { "version": "v1.31.3+k3s1" },
                    "addons": [],
                    "readinessGates": []
                },
                "status": {
                    "phase": "Creating",
                    "provisioned": true,
                    "network": {
                        "serviceCidr": "10.240.0.0/20",
                        "clusterCidr": "10.248.0.0/20"
                    }
                }
            }))
            .unwrap(),
        )
    }

    /// First-ever reconcile of a fresh `ClusterInstance` MUST stamp the
    /// finalizer onto `metadata.finalizers`. Without this the abnormal-
    /// path delete in #95 (kubectl delete clusterinstance while
    /// Creating/Unhealthy/Failed) skips backend cleanup entirely.
    #[tokio::test]
    async fn reconcile_adds_finalizer_when_missing() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = instance_with_finalizer_state("no-finalizer-1", None, vec![]);

        // Expect exactly one Merge PATCH on the root object (NOT /status)
        // adding our finalizer to the array.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/no-finalizer-1",
            ))
            .and(body_partial_json(serde_json::json!({
                "metadata": { "finalizers": [INSTANCE_FINALIZER] }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("no-finalizer-1")))
            .expect(1)
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        // Tight re-reconcile so the next pass sees the updated metadata.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(0)));
        // Backend MUST NOT be touched on a finalizer-add-only reconcile.
        let calls = backend.call_count();
        assert_eq!(calls.create, 0);
        assert_eq!(calls.delete, 0);
        assert_eq!(calls.check_health, 0);
    }

    /// When `deletion_timestamp` is set AND our finalizer is present,
    /// reconcile MUST run `backend.delete()` and then remove the
    /// finalizer via a Merge PATCH. This is the path that fixes #95
    /// for `kubectl delete clusterinstance` against a non-Ready instance.
    #[tokio::test]
    async fn reconcile_runs_backend_delete_then_removes_finalizer_on_deletion() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = instance_with_finalizer_state(
            "deleting-1",
            Some("2026-05-21T10:00:00Z"),
            vec![INSTANCE_FINALIZER],
        );

        // Expect the finalizer-removal PATCH. The body should contain an
        // empty finalizers array (we filtered out our finalizer and there
        // were no others).
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/deleting-1",
            ))
            .and(body_partial_json(serde_json::json!({
                "metadata": { "finalizers": [] }
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(instance_api_response("deleting-1")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // cleanup_orphan_projected_resources lists pods + targets a probe
        // pod by name. The probe DELETE is best-effort; the LIST must
        // succeed so we feed it an empty list.
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/test-ns/pods/kobe-readiness-probe-deleting-1-x-kube-system-x-vc",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                crate::testutil::k8s_not_found("pods", "kobe-readiness-probe-deleting-1-x-kube-system-x-vc"),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": []
            })))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::await_change());
        let calls = backend.call_count();
        assert_eq!(
            calls.delete, 1,
            "backend.delete() MUST run before the finalizer is released"
        );
    }

    /// When `deletion_timestamp` is set but our finalizer was never
    /// stamped (legacy CRs created pre-#95, or another controller
    /// already removed it), reconcile just waits for the API server to
    /// complete the delete. Backend cleanup is skipped — there's
    /// nothing left to block on.
    #[tokio::test]
    async fn reconcile_no_op_when_deleting_without_our_finalizer() {
        let (ctx, _server, backend) = test_instance_context().await;
        let instance =
            instance_with_finalizer_state("legacy-deleting", Some("2026-05-21T10:00:00Z"), vec![]);

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::await_change());
        let calls = backend.call_count();
        assert_eq!(calls.delete, 0);
    }

    /// `add_finalizer` MUST preserve any finalizers already on the
    /// object (e.g. another controller's). The Merge PATCH body should
    /// contain BOTH the existing finalizer and ours.
    #[tokio::test]
    async fn add_finalizer_preserves_existing_finalizers() {
        let (ctx, server, _backend) = test_instance_context().await;
        let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), "test-ns");
        let instance =
            instance_with_finalizer_state("multi-final", None, vec!["other-controller/finalizer"]);

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/multi-final",
            ))
            .and(body_partial_json(serde_json::json!({
                "metadata": {
                    "finalizers": ["other-controller/finalizer", INSTANCE_FINALIZER]
                }
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(instance_api_response("multi-final")),
            )
            .expect(1)
            .mount(&server)
            .await;

        add_finalizer(&instances_api, &instance, INSTANCE_FINALIZER)
            .await
            .unwrap();
    }

    /// `remove_finalizer` MUST preserve any finalizers other than ours.
    #[tokio::test]
    async fn remove_finalizer_preserves_other_finalizers() {
        let (ctx, server, _backend) = test_instance_context().await;
        let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), "test-ns");
        let instance = instance_with_finalizer_state(
            "multi-final-rm",
            None,
            vec!["other-controller/finalizer", INSTANCE_FINALIZER],
        );

        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/multi-final-rm",
            ))
            .and(body_partial_json(serde_json::json!({
                "metadata": { "finalizers": ["other-controller/finalizer"] }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("multi-final-rm")))
            .expect(1)
            .mount(&server)
            .await;

        remove_finalizer(&instances_api, &instance, INSTANCE_FINALIZER)
            .await
            .unwrap();
    }

    /// Helper: a pool-managed instance that is being deleted while its
    /// owning pool is already gone (the cascading-delete deadlock from
    /// FIX 2). Carries `status.created_with.backend_type` so the delete
    /// path can pin the backend without the pool.
    fn pool_managed_deleting_instance(name: &str, pool: &str) -> Arc<ClusterInstance> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "deletionTimestamp": "2026-05-21T10:00:00Z",
                    "finalizers": [INSTANCE_FINALIZER]
                },
                "spec": {
                    "poolRef": { "name": pool },
                    "addons": [],
                    "readinessGates": []
                },
                "status": {
                    "phase": "Creating",
                    "provisioned": true,
                    "createdWith": { "operatorVersion": "0.23.1", "type": "k3s" },
                    "network": {
                        "serviceCidr": "10.240.0.0/20",
                        "clusterCidr": "10.248.0.0/20"
                    }
                }
            }))
            .unwrap(),
        )
    }

    /// FIX 2 regression: a ClusterPool delete cascades a deletionTimestamp
    /// onto every child ClusterInstance, but the pool may already be gone
    /// when we reconcile the child. Previously `resolve_instance_config`
    /// ran BEFORE the finalizer path and Err'd on the missing pool, so
    /// `remove_finalizer` was never reached and the instance was stuck
    /// deleting forever. Now the finalizer path must still run: backend
    /// cleanup happens and the finalizer is released.
    #[tokio::test]
    async fn reconcile_deletes_and_releases_finalizer_when_owning_pool_is_gone() {
        let (ctx, server, backend) = test_instance_context().await;
        let instance = pool_managed_deleting_instance("orphan-deleting", "gone-pool");

        // Owning pool GET returns 404 — the pool is already deleted.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/gone-pool",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("clusterpools", "gone-pool")),
            )
            .mount(&server)
            .await;

        // Finalizer-removal PATCH (empty finalizers array after filtering ours).
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/orphan-deleting",
            ))
            .and(body_partial_json(serde_json::json!({
                "metadata": { "finalizers": [] }
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(instance_api_response("orphan-deleting")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // cleanup_orphan_projected_resources lists pods + best-effort deletes
        // a probe pod by name. Feed it an empty list + 404 on the probe.
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/test-ns/pods/kobe-readiness-probe-orphan-deleting-x-kube-system-x-vc",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                crate::testutil::k8s_not_found(
                    "pods",
                    "kobe-readiness-probe-orphan-deleting-x-kube-system-x-vc",
                ),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": []
            })))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx)
            .await
            .expect("reconcile must NOT error when the owning pool is gone during deletion");

        assert_eq!(action, Action::await_change());
        let calls = backend.call_count();
        assert_eq!(
            calls.delete, 1,
            "backend.delete() MUST run even when the owning pool is gone"
        );
    }

    /// `add_finalizer` MUST be a no-op (zero API calls) when the
    /// finalizer is already present. Without this guard, every
    /// reconcile of a healthy instance would emit a useless PATCH and
    /// double the API-server load.
    #[tokio::test]
    async fn add_finalizer_is_no_op_when_already_present() {
        let (ctx, _server, _backend) = test_instance_context().await;
        let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), "test-ns");
        let instance =
            instance_with_finalizer_state("already-final", None, vec![INSTANCE_FINALIZER]);

        // No mock mounted — any PATCH would 404 from wiremock's default
        // and fail the call. The fact that this succeeds proves no
        // request was issued.
        add_finalizer(&instances_api, &instance, INSTANCE_FINALIZER)
            .await
            .unwrap();
    }
}
