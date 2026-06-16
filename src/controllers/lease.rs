use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::auth::JwtAuthenticator;
use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{
    ClusterInstance, ClusterInstancePhase, ClusterLease, ClusterLeaseCondition, ClusterLeaseStatus,
    ClusterPool, ClusterPoolPhase, ClusterPoolStatus, LeasePhase,
};
use crate::diagnostics;
use crate::pool::{PoolState, parse_duration};

/// Shared state for the lease controller.
pub struct LeaseContext<B: ClusterBackend> {
    pub client: Client,
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
                return Ok(Action::await_change());
            }
            Err(err) => return Err(LeaseError::Kube(err)),
        }
    } else {
        lease
    };

    let status = lease.status.clone().unwrap_or_default();
    if status.phase == LeasePhase::Pending && status.cluster_name.is_some() {
        info!(
            lease = %name,
            cluster = ?status.cluster_name,
            "Lease has an assigned cluster while still marked Pending; restoring Bound phase"
        );

        let mut repaired_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: status.cluster_name.clone(),
            bound_at: status.bound_at.clone(),
            expires_at: status.expires_at.clone(),
            queue_position: 0,
            diagnostics_url: status.diagnostics_url.clone(),
            extensions_count: status.extensions_count,
            max_extensions: status.max_extensions,
            // Now bound: clear any stale "no Ready cluster" exhaustion message.
            message: None,
            conditions: Vec::new(),
        };
        repaired_status.conditions = derive_lease_conditions(
            &repaired_status,
            &status.conditions,
            None,
            &chrono::Utc::now().to_rfc3339(),
        );

        leases_api
            .patch_status(
                &name,
                &PatchParams::apply("kobe-operator"),
                &Patch::Merge(&serde_json::json!({ "status": repaired_status })),
            )
            .await?;
        remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;
        return Ok(Action::requeue(std::time::Duration::from_secs(60)));
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

            let patch = serde_json::json!({
                "status": {
                    "phase": "Pending",
                    "queuePosition": position
                }
            });
            leases_api
                .patch_status(
                    &name,
                    &PatchParams::apply("kobe-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;

            if let Some(profile) = get_profile(&ctx.client, &lease.spec.pool_ref, &ns).await
                && let Some(scaling) = &profile.spec.scaling
                && let Some(timeout) = parse_duration(&scaling.queue_timeout)
            {
                let age = chrono::Utc::now() - created_at;
                if age > timeout {
                    warn!(lease = %name, "Lease exceeded queue timeout, expiring");
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

            let reserved_cluster =
                reserve_ready_instance(&ctx.client, &ns, &lease.spec.pool_ref, &name).await?;

            if let Some(cluster_name) = reserved_cluster {
                let ttl =
                    parse_duration(&lease.spec.ttl).unwrap_or_else(|| chrono::Duration::hours(1));
                let now = chrono::Utc::now();
                let expires_at = now + ttl;

                let policy = ctx
                    .authenticator
                    .policy_for_requester_type(&lease.spec.requester.requester_type)
                    .await;
                let max_extensions = policy.map(|p| p.max_extensions).unwrap_or(2);
                let mut new_status = ClusterLeaseStatus {
                    phase: LeasePhase::Bound,
                    cluster_name: Some(cluster_name.clone()),
                    bound_at: Some(now.to_rfc3339()),
                    expires_at: Some(expires_at.to_rfc3339()),
                    queue_position: 0,
                    diagnostics_url: None,
                    extensions_count: 0,
                    max_extensions,
                    // Bound now: clear any prior "no Ready cluster" message.
                    message: None,
                    conditions: Vec::new(),
                };
                new_status.conditions = derive_lease_conditions(
                    &new_status,
                    &status.conditions,
                    None,
                    &now.to_rfc3339(),
                );

                let patch = serde_json::json!({ "status": new_status });
                match leases_api
                    .patch_status(
                        &name,
                        &PatchParams::apply("kobe-operator"),
                        &Patch::Merge(&patch),
                    )
                    .await
                {
                    Ok(_) => {
                        remove_from_queue(&ctx.queues, &lease.spec.pool_ref, &name).await;

                        let bind_duration =
                            (chrono::Utc::now() - created_at).num_milliseconds() as f64 / 1000.0;
                        crate::metrics::CLAIM_BIND_DURATION
                            .with_label_values(&[&lease.spec.pool_ref])
                            .observe(bind_duration);

                        crate::metrics::CLAIMS_TOTAL
                            .with_label_values(&[lease.spec.pool_ref.as_str(), "bound"])
                            .inc();

                        info!(
                            lease = %name,
                            cluster = %cluster_name,
                            expires_at = %expires_at,
                            bind_seconds = bind_duration,
                            "Lease bound to cluster"
                        );

                        Ok(Action::requeue(std::time::Duration::from_secs(60)))
                    }
                    Err(e) => {
                        warn!(lease = %name, cluster = %cluster_name, "Bind patch failed, rolling back reservation");
                        rollback_instance_reservation(&ctx.client, &ns, &cluster_name).await;
                        Err(LeaseError::Kube(e))
                    }
                }
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

            // Explicitly delete the lease's connect-token Secret now, rather
            // than waiting for owner-ref GC when the lease CRD is deleted at the
            // end of Recycling (#178). Closes the window where a released lease's
            // token still validates if the CRD delete is interrupted; access is
            // also bounded per-request by the proxy phase/expiry re-check (#116).
            // Best-effort: a failure must not abort recycling.
            if let Err(e) =
                crate::api::connect::delete_lease_connect_token(&ctx.client, &ns, &name).await
            {
                warn!(lease = %name, "best-effort connect-token delete failed (continuing): {e:#}");
            }

            // Capture diagnostics BEFORE flipping to Recycling: the cluster is
            // still alive (we mark the instance recycling only after the patch
            // below), and recording the URL in the SAME patch that advances the
            // phase means a transient status-write failure is retried — via the
            // `?` below, while the lease is still Released/Expired — instead of
            // losing the URL (the Recycling arm never re-captures).
            let mut diag_url: Option<String> = None;
            if let Some(cluster_name) = &status.cluster_name {
                let profile = get_profile(&ctx.client, &lease.spec.pool_ref, &ns).await;
                if let Some(ref profile) = profile
                    && let Some(ref diag_config) = profile.spec.diagnostics
                    && diag_config.enabled
                {
                    info!(lease = %name, "Capturing diagnostic bundle");
                    match diagnostics::capture_bundle(
                        cluster_name,
                        &ns,
                        diag_config,
                        &name,
                        &ctx.backend,
                    )
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
            }

            let recycling_status = ClusterLeaseStatus {
                phase: LeasePhase::Recycling,
                ..Default::default()
            };
            let conditions = derive_lease_conditions(
                &recycling_status,
                &status.conditions,
                None,
                &chrono::Utc::now().to_rfc3339(),
            );
            let mut status_fields =
                serde_json::json!({ "phase": "Recycling", "conditions": conditions });
            if let Some(url) = &diag_url {
                status_fields["diagnosticsUrl"] = serde_json::Value::String(url.clone());
            }
            leases_api
                .patch_status(
                    &name,
                    &PatchParams::apply("kobe-operator"),
                    &Patch::Merge(&serde_json::json!({ "status": status_fields })),
                )
                .await?;

            if let Some(cluster_name) = &status.cluster_name {
                mark_instance_recycling(&ctx.client, &ns, cluster_name).await;
                debug!(cluster = %cluster_name, "Marked ClusterInstance recycling");
            } else {
                info!(lease = %name, "No cluster to recycle, lease will be cleaned up");
            }

            Ok(Action::requeue(std::time::Duration::from_secs(10)))
        }

        LeasePhase::Recycling => {
            let cluster_gone = if let Some(cluster_name) = &status.cluster_name {
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
                match instances_api.get(cluster_name).await {
                    Ok(_) => false,
                    Err(kube::Error::Api(ae)) if ae.code == 404 => true,
                    Err(e) => {
                        warn!(lease = %name, cluster = %cluster_name, "Failed to query ClusterInstance during recycle: {e}");
                        false
                    }
                }
            } else {
                true
            };

            if cluster_gone {
                info!(lease = %name, "Recycling complete, deleting lease CRD");
                match leases_api.delete(&name, &Default::default()).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(ae)) if ae.code == 404 => {
                        // Already deleted, that's fine
                    }
                    Err(e) => {
                        warn!(lease = %name, "Failed to delete recycled lease CRD: {e}");
                    }
                }
                Ok(Action::await_change())
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
    authenticator: &JwtAuthenticator,
) -> Result<String, LeaseError> {
    let leases_api: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = leases_api.get(lease_name).await?;
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

    let patch = serde_json::json!({
        "status": {
            "expiresAt": new_expiry.to_rfc3339(),
            "extensionsCount": status.extensions_count + 1
        }
    });
    leases_api
        .patch_status(
            lease_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
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

async fn reserve_ready_instance(
    client: &Client,
    namespace: &str,
    pool_ref: &str,
    lease_name: &str,
) -> Result<Option<String>, LeaseError> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/pool={pool_ref}"));
    let instances = instances_api.list(&lp).await?;
    let mut ready: Vec<ClusterInstance> = instances
        .into_iter()
        .filter(|instance| {
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

    let Some(instance) = ready.first() else {
        return Ok(None);
    };

    let cluster_name = instance.name_any();
    let current = instance.status.clone().unwrap_or_default();
    let patch = serde_json::json!({
        "status": {
            "phase": "Leased",
            "leaseRef": { "name": lease_name },
            "idleSince": serde_json::Value::Null,
            "stateSince": chrono::Utc::now().to_rfc3339(),
            "healthFailures": current.health_failures,
            "specHash": current.spec_hash
        }
    });
    instances_api
        .patch_status(
            &cluster_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(Some(cluster_name))
}

async fn rollback_instance_reservation(client: &Client, namespace: &str, cluster_name: &str) {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({
        "status": {
            "phase": "Ready",
            "leaseRef": serde_json::Value::Null,
            "idleSince": chrono::Utc::now().to_rfc3339(),
            "stateSince": chrono::Utc::now().to_rfc3339()
        }
    });
    let _ = instances_api
        .patch_status(
            cluster_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await;
}

async fn mark_instance_recycling(client: &Client, namespace: &str, cluster_name: &str) {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({
        "status": {
            "phase": "Recycling",
            "leaseRef": serde_json::Value::Null,
            "idleSince": serde_json::Value::Null,
            "stateSince": chrono::Utc::now().to_rfc3339()
        }
    });
    let _ = instances_api
        .patch_status(
            cluster_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await;
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

    #[tokio::test]
    async fn reserve_skips_ready_instance_with_stale_lease_ref() {
        // A Ready instance that still carries a leaseRef (e.g. a stale phase
        // write reverted it Leased->Ready without clearing leaseRef) must NOT be
        // reserved, or the same cluster is double-leased to a second tenant.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

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

        let result = reserve_ready_instance(&client, "test-ns", "p", "lease-new").await;
        assert!(
            matches!(result, Ok(None)),
            "a Ready instance still carrying a leaseRef must not be reserved, got {result:?}"
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
                    "namespace": "test-ns"
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

    /// Build a minimal `ClusterPool` JSON value for K8s API responses.
    fn make_test_profile() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "test-profile",
                "namespace": "test-ns"
            },
            "spec": {
                "size": 3,
                "ttl": "2h",
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
        let lease = make_test_lease("pending-1", "Pending");

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
    async fn test_reconcile_pending_lease_binds_to_ready_cluster() {
        let (ctx, server) = test_lease_context().await;
        let lease = make_test_lease("bind-1", "Pending");

        // Mock PATCH for queue-position status update.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/bind-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "bind-1", "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Bound", "clusterName": "pool-test-1" }
            })))
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
                        "provisioned": true,
                        "leaseRef": null,
                        "idleSince": chrono::Utc::now().to_rfc3339(),
                        "stateSince": chrono::Utc::now().to_rfc3339(),
                        "healthFailures": 0,
                        "specHash": "0000000000000001"
                    }
                })]),
            ))
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
                "status": { "phase": "Leased", "provisioned": true, "leaseRef": { "name": "bind-1" } }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (404 — no profile, no queue timeout).
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

        let action = reconcile_lease(lease, ctx.clone()).await.unwrap();
        // Successful bind → requeue at 60s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));
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
    async fn test_reconcile_repairs_pending_lease_with_assigned_cluster() {
        let (ctx, server) = test_lease_context().await;
        let lease: Arc<ClusterLease> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": "repair-1",
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));
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
        let lease = make_test_lease("released-1", "Released");

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

        // The connect-token Secret must be explicitly deleted at release (#178),
        // not left to owner-ref GC. expect(1) verifies the controller issues it.
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
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));
        let calls = ctx.backend.call_count();
        assert_eq!(calls.delete, 0);
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Recycling — cluster gone, lease deleted
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_recycling_lease_cluster_gone() {
        let (ctx, server) = test_lease_context().await;
        let lease = make_test_lease("recycling-1", "Recycling");

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
        assert_eq!(action, Action::await_change());
    }

    // -----------------------------------------------------------------------
    // reconcile_lease: Recycling — cluster NOT gone, requeue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_recycling_lease_cluster_still_present() {
        let (ctx, server) = test_lease_context().await;
        let lease = make_test_lease("recycling-2", "Recycling");

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
                "metadata": { "name": "extend-1", "namespace": "test-ns" },
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
                "metadata": { "name": "extend-1", "namespace": "test-ns" },
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
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_ok());
        // The returned string should be a valid RFC3339 timestamp.
        let new_expiry_str = result.unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(&new_expiry_str).is_ok());
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
                "metadata": { "name": "extend-2", "namespace": "test-ns" },
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
                "metadata": { "name": "pending-ext", "namespace": "test-ns" },
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
                "metadata": { "name": "maxext-1", "namespace": "test-ns" },
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
        let lease = make_test_lease("unsat-1", "Pending");

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
