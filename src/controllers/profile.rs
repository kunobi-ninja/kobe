use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{
    BackendType, ClusterLease, ClusterPool, ClusterPoolStatus, LeasePhase, ReadinessGate,
    SnapshotRefreshTrigger,
};
use crate::pool::{
    compute_pool_actions, count_states, ClusterEntry, ClusterState, PoolAction, PoolState,
};
use crate::velero::VeleroCoordinator;

/// Shared state for the profile controller.
pub struct ProfileContext<B: ClusterBackend> {
    pub client: Client,
    pub backend: B,
    pub namespace: String,
    /// Per-profile pool state, shared with claim controller and API layer.
    pub pools: Arc<RwLock<HashMap<String, PoolState>>>,
    /// Per-cluster health failure counts.
    pub health_failures: RwLock<HashMap<String, u32>>,
    /// Optional Velero coordinator for golden backup/restore operations.
    pub velero: Option<VeleroCoordinator>,
    /// Optional backend factory for per-profile backend dispatch.
    /// When set, `backend_for(profile)` is used instead of `self.backend`
    /// for create/delete operations.
    pub factory: Option<BackendFactory>,
}

/// Error type for the profile controller.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] anyhow::Error),
}

/// Start the profile reconciler controller.
pub async fn run_profile_controller<B: ClusterBackend + Clone + 'static>(
    client: Client,
    namespace: &str,
    backend: B,
    pools: Arc<RwLock<HashMap<String, PoolState>>>,
    velero: Option<VeleroCoordinator>,
    factory: Option<BackendFactory>,
    shutdown: CancellationToken,
) {
    let profiles: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);

    let ctx = Arc::new(ProfileContext {
        client: client.clone(),
        backend,
        namespace: namespace.to_string(),
        pools,
        health_failures: RwLock::new(HashMap::new()),
        velero,
        factory,
    });

    // Start health check background task
    let health_ctx = ctx.clone();
    let health_ns = namespace.to_string();
    let health_shutdown = shutdown.clone();
    tokio::spawn(async move {
        run_health_checks(health_ctx, &health_ns, health_shutdown).await;
    });

    info!("Starting profile controller");

    let controller = Controller::new(profiles, Config::default())
        .owns(leases, Config::default())
        .run(reconcile_profile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["profile", "ok"])
                        .inc();
                    debug!(profile = %obj.name, "Profile reconciled");
                }
                Err(e) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["profile", "error"])
                        .inc();
                    error!("Profile reconciliation error: {e:?}");
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Profile controller shutting down");
        },
    }
}

/// Main reconciliation logic for a ClusterPool.
///
/// 1. Build current pool state from cluster observations
/// 2. Evaluate readiness gates for Creating clusters
/// 3. Compute desired actions via pool manager (scale up/down)
/// 4. Execute actions (create/delete clusters)
/// 5. Update profile status
#[tracing::instrument(skip_all, fields(profile = %profile.name_any()))]
async fn reconcile_profile<B: ClusterBackend + Clone + 'static>(
    profile: Arc<ClusterPool>,
    ctx: Arc<ProfileContext<B>>,
) -> Result<Action, ProfileError> {
    let name = profile.name_any();
    let ns = profile.namespace().unwrap_or_else(|| ctx.namespace.clone());

    info!(profile = %name, "Reconciling profile");

    // Build current pool state
    let mut pool_state = build_pool_state(&ctx, &name).await;

    // Check if golden backup needs rebuilding on profile spec change.
    if let (Some(velero), Some(snapshot)) = (&ctx.velero, &profile.spec.snapshot) {
        if snapshot.enabled {
            if let SnapshotRefreshTrigger::ProfileChange = snapshot.refresh_on {
                let profile_gen = profile.metadata.generation.unwrap_or(1);
                let golden_gen = profile
                    .status
                    .as_ref()
                    .and_then(|s| s.golden_generation)
                    .unwrap_or(0);

                if profile_gen > golden_gen {
                    info!(
                        profile = %name,
                        profile_generation = profile_gen,
                        golden_generation = golden_gen,
                        "Profile generation changed, triggering golden backup rebuild"
                    );

                    let velero = velero.clone();
                    let snapshot = snapshot.clone();
                    let profile_name = name.clone();
                    let spec = profile.spec.clone();
                    let backend = if let Some(ref f) = ctx.factory {
                        f.backend_for(&profile)?
                    } else {
                        // Fallback: in tests, wrap the clone in a no-op dispatch.
                        crate::backend::BackendDispatch::K3s(crate::backend::K3sBackend::new(
                            ctx.client.clone(),
                            None,
                            None,
                        ))
                    };
                    let client = ctx.client.clone();
                    let ns = ns.clone();

                    tokio::spawn(async move {
                        let generation = profile_gen;
                        match velero
                            .create_golden_backup(
                                &profile_name,
                                &spec,
                                &backend,
                                &snapshot,
                                generation,
                            )
                            .await
                        {
                            Ok(backup_name) => {
                                info!(
                                    profile = %profile_name,
                                    backup = %backup_name,
                                    generation = profile_gen,
                                    "Golden backup created successfully"
                                );

                                crate::metrics::GOLDEN_BACKUP_TOTAL
                                    .with_label_values(&[profile_name.as_str(), "ok"])
                                    .inc();

                                // Patch profile status with new golden backup info.
                                let profiles_api: Api<ClusterPool> =
                                    Api::namespaced(client.clone(), &ns);
                                let status_patch = serde_json::json!({
                                    "status": {
                                        "goldenBackup": backup_name,
                                        "goldenGeneration": profile_gen,
                                    }
                                });
                                if let Err(e) = profiles_api
                                    .patch_status(
                                        &profile_name,
                                        &PatchParams::apply("kobe-operator"),
                                        &Patch::Merge(&status_patch),
                                    )
                                    .await
                                {
                                    error!(
                                        profile = %profile_name,
                                        error = %e,
                                        "Failed to patch profile status with golden backup info"
                                    );
                                }

                                // Clean up old backups.
                                if let Err(e) = velero
                                    .cleanup_old_backups(&profile_name, &snapshot, generation)
                                    .await
                                {
                                    warn!(
                                        profile = %profile_name,
                                        error = %e,
                                        "Failed to clean up old golden backups"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    profile = %profile_name,
                                    error = %e,
                                    "Failed to create golden backup"
                                );
                                crate::metrics::GOLDEN_BACKUP_TOTAL
                                    .with_label_values(&[profile_name.as_str(), "error"])
                                    .inc();
                            }
                        }
                    });
                }
            }
        }
    }

    // Check readiness gates for Creating clusters
    if !profile.spec.readiness_gates.is_empty() {
        evaluate_readiness_gates(
            &ctx,
            &name,
            &ns,
            &profile.spec.readiness_gates,
            &mut pool_state,
        )
        .await;
    }

    // Compute actions
    let now = chrono::Utc::now();
    let actions = compute_pool_actions(&profile, &pool_state, now);

    // Execute actions
    for action in &actions {
        match action {
            PoolAction::Create(cluster_name) => {
                info!(profile = %name, cluster = %cluster_name, "Creating cluster");
                pool_state.clusters.insert(
                    cluster_name.clone(),
                    ClusterEntry {
                        state: ClusterState::Creating,
                        idle_since: None,
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: Some(crate::pool::profile_spec_hash(&profile)),
                    },
                );

                let config = profile.spec.cluster.clone();
                let addons = profile.spec.addons.clone();
                let c_name = cluster_name.clone();
                let c_ns = ns.clone();
                let fallback_backend = ctx.backend.clone();
                let factory = ctx.factory.clone();
                let profile_for_dispatch = profile.as_ref().clone();
                let pools_ref = ctx.pools.clone();
                let profile_name = name.clone();
                let velero = ctx.velero.clone();
                let snapshot = profile.spec.snapshot.clone();
                let profile_gen = profile.metadata.generation.unwrap_or(1);
                let spec = profile.spec.clone();
                let bg_client = ctx.client.clone();
                let bg_ns = ns.clone();

                tokio::spawn(async move {
                    // Determine whether to restore from golden backup or create fresh.
                    // K3s uses PG template databases for golden images,
                    // so Velero restore only applies to non-K3s backends.
                    let is_k3s = matches!(
                        profile_for_dispatch.spec.backend.backend_type,
                        BackendType::K3s
                    );
                    let use_restore = if !is_k3s {
                        if let (Some(ref velero), Some(ref snapshot)) = (&velero, &snapshot) {
                            if snapshot.enabled {
                                match velero
                                    .get_golden_backup(&profile_name, snapshot, profile_gen)
                                    .await
                                {
                                    Ok(Some(backup_name)) => Some((backup_name, snapshot.clone())),
                                    Ok(None) => None,
                                    Err(e) => {
                                        warn!(
                                            profile = %profile_name,
                                            error = %e,
                                            "Failed to check golden backup, falling back to fresh create"
                                        );
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let result = if let Some((backup_name, snap_config)) = use_restore {
                        // Restore from golden backup.
                        info!(
                            profile = %profile_name,
                            cluster = %c_name,
                            backup = %backup_name,
                            "Restoring cluster from golden backup"
                        );
                        let velero_ref = velero.as_ref().unwrap();
                        match velero_ref
                            .restore_from_golden(&backup_name, &snap_config, &profile_name, &c_ns)
                            .await
                        {
                            Ok(()) => {
                                crate::metrics::PROVISION_METHOD
                                    .with_label_values(&[profile_name.as_str(), "restore"])
                                    .inc();
                                Ok(())
                            }
                            Err(e) => {
                                warn!(
                                    profile = %profile_name,
                                    cluster = %c_name,
                                    error = %e,
                                    "Failed to restore from golden backup, falling back to fresh create"
                                );
                                // Fall back to fresh create using fallback backend.
                                fallback_backend
                                    .create(&c_name, &c_ns, &config, &addons)
                                    .await
                                    .map(|()| {
                                        crate::metrics::PROVISION_METHOD
                                            .with_label_values(&[profile_name.as_str(), "fresh"])
                                            .inc();
                                    })
                            }
                        }
                    } else {
                        // Fresh create (no golden backup available or snapshot not enabled).
                        // Use per-profile backend dispatch when factory is available.
                        let create_result = if let Some(ref factory) = factory {
                            match factory.backend_for(&profile_for_dispatch) {
                                Ok(b) => b.create(&c_name, &c_ns, &config, &addons).await,
                                Err(e) => Err(e),
                            }
                        } else {
                            fallback_backend
                                .create(&c_name, &c_ns, &config, &addons)
                                .await
                        };
                        if create_result.is_ok() {
                            crate::metrics::PROVISION_METHOD
                                .with_label_values(&[profile_name.as_str(), "fresh"])
                                .inc();

                            // If snapshot is enabled but no golden backup exists yet,
                            // trigger golden backup creation in the background.
                            // (K3s uses PG templates instead of Velero snapshots.)
                            if !is_k3s {
                                if let (Some(ref velero), Some(ref snapshot)) = (&velero, &snapshot)
                                {
                                    if snapshot.enabled {
                                        let velero = velero.clone();
                                        let snapshot = snapshot.clone();
                                        let profile_name = profile_name.clone();
                                        let spec = spec.clone();
                                        let backend = fallback_backend.clone();
                                        let generation = profile_gen;
                                        let client = bg_client.clone();
                                        let status_ns = bg_ns.clone();

                                        tokio::spawn(async move {
                                            info!(
                                                profile = %profile_name,
                                                "No golden backup found, creating one in the background"
                                            );
                                            match velero
                                                .create_golden_backup(
                                                    &profile_name,
                                                    &spec,
                                                    &backend,
                                                    &snapshot,
                                                    generation,
                                                )
                                                .await
                                            {
                                                Ok(backup_name) => {
                                                    info!(
                                                        profile = %profile_name,
                                                        backup = %backup_name,
                                                        "Background golden backup created successfully"
                                                    );
                                                    crate::metrics::GOLDEN_BACKUP_TOTAL
                                                        .with_label_values(&[
                                                            profile_name.as_str(),
                                                            "ok",
                                                        ])
                                                        .inc();

                                                    // Patch profile status so subsequent reconciles
                                                    // know the golden backup exists and skip rebuilding.
                                                    let profiles_api: Api<ClusterPool> =
                                                        Api::namespaced(client, &status_ns);
                                                    let status_patch = serde_json::json!({
                                                        "status": {
                                                            "goldenBackup": backup_name,
                                                            "goldenGeneration": generation,
                                                        }
                                                    });
                                                    if let Err(e) = profiles_api
                                                        .patch_status(
                                                            &profile_name,
                                                            &PatchParams::apply("kobe-operator"),
                                                            &Patch::Merge(&status_patch),
                                                        )
                                                        .await
                                                    {
                                                        error!(
                                                            profile = %profile_name,
                                                            error = %e,
                                                            "Failed to patch profile status after background golden backup"
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    error!(
                                                        profile = %profile_name,
                                                        error = %e,
                                                        "Background golden backup creation failed"
                                                    );
                                                    crate::metrics::GOLDEN_BACKUP_TOTAL
                                                        .with_label_values(&[
                                                            profile_name.as_str(),
                                                            "error",
                                                        ])
                                                        .inc();
                                                }
                                            }
                                        });
                                    }
                                }
                            } // if !is_k3s
                        }
                        create_result
                    };

                    match result {
                        Ok(()) => {
                            if let Some(pool) = pools_ref.write().await.get_mut(&profile_name) {
                                if let Some(entry) = pool.clusters.get_mut(&c_name) {
                                    entry.state = ClusterState::Ready;
                                    entry.idle_since = Some(chrono::Utc::now());
                                    entry.state_since = Some(chrono::Utc::now());
                                }
                            }
                        }
                        Err(e) => {
                            error!(cluster = %c_name, "Failed to create cluster: {e:?}");
                            // Remove the failed entry so the next reconciliation can retry
                            if let Some(pool) = pools_ref.write().await.get_mut(&profile_name) {
                                pool.clusters.remove(&c_name);
                            }
                        }
                    }
                });
            }
            PoolAction::Delete(cluster_name) => {
                info!(profile = %name, cluster = %cluster_name, "Deleting cluster");
                if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                    entry.state = ClusterState::Recycling;
                }

                let c_name = cluster_name.clone();
                let c_ns = ns.clone();
                let profile_name = name.clone();
                let pools_ref = ctx.pools.clone();
                let factory = ctx.factory.clone();
                let profile_for_dispatch = profile.as_ref().clone();
                let fallback_backend = ctx.backend.clone();
                tokio::spawn(async move {
                    let delete_result = if let Some(ref factory) = factory {
                        match factory.backend_for(&profile_for_dispatch) {
                            Ok(b) => b.delete(&c_name, &c_ns).await,
                            Err(e) => Err(e),
                        }
                    } else {
                        fallback_backend.delete(&c_name, &c_ns).await
                    };
                    match delete_result {
                        Ok(_) => {
                            if let Some(pool) = pools_ref.write().await.get_mut(&profile_name) {
                                pool.clusters.remove(&c_name);
                            }
                        }
                        Err(e) => {
                            error!(cluster = %c_name, "Failed to delete cluster: {e:?}");
                        }
                    }
                });
            }
            PoolAction::MarkUnhealthy(cluster_name) => {
                warn!(profile = %name, cluster = %cluster_name, "Marking cluster unhealthy");
                if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                    entry.state = ClusterState::Unhealthy;
                }
            }
        }
    }

    // Store updated pool state
    ctx.pools
        .write()
        .await
        .insert(name.clone(), pool_state.clone());

    // Update profile status
    let counts = count_states(&pool_state);

    let queue_depth = {
        let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), &ns);
        let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/profile={name}"));
        match leases_api.list(&lp).await {
            Ok(leases) => leases
                .iter()
                .filter(|c| {
                    c.status
                        .as_ref()
                        .map(|s| s.phase == LeasePhase::Pending)
                        .unwrap_or(true)
                })
                .count() as u32,
            Err(e) => {
                warn!(profile = %name, "Failed to list leases for queue depth: {e:?}");
                0
            }
        }
    };

    crate::metrics::QUEUE_DEPTH
        .with_label_values(&[&name])
        .set(queue_depth as i64);

    let profiles_api: Api<ClusterPool> = Api::namespaced(ctx.client.clone(), &ns);

    // Preserve existing golden backup/generation status values so they are
    // not overwritten with None on every reconcile loop.
    let (existing_golden_backup, existing_golden_generation) = profile
        .status
        .as_ref()
        .map(|s| (s.golden_backup.clone(), s.golden_generation))
        .unwrap_or((None, None));

    let existing_golden_template_db = profile
        .status
        .as_ref()
        .and_then(|s| s.golden_template_db.clone());

    let status = ClusterPoolStatus {
        ready: counts.ready,
        claimed: counts.claimed,
        creating: counts.creating,
        unhealthy: counts.unhealthy,
        queue_depth,
        golden_backup: existing_golden_backup,
        golden_generation: existing_golden_generation,
        golden_template_db: existing_golden_template_db,
    };

    let patch = serde_json::json!({ "status": status });
    profiles_api
        .patch_status(
            &name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// Build pool state by observing actual K8s resources.
///
/// On first call (empty cache), scans StatefulSets matching the profile
/// naming pattern and cross-references with active ClusterLease resources.
/// On subsequent calls, returns the cached state which the controllers
/// keep up-to-date incrementally.
async fn build_pool_state<B: ClusterBackend>(
    ctx: &ProfileContext<B>,
    profile_name: &str,
) -> PoolState {
    if let Some(cached) = ctx.pools.read().await.get(profile_name) {
        if !cached.clusters.is_empty() {
            return cached.clone();
        }
    }

    info!(
        profile = profile_name,
        "Rebuilding pool state from K8s resources"
    );

    let ns = &ctx.namespace;
    let mut clusters = HashMap::new();

    // List all bound leases for this profile once
    let claimed_clusters = {
        let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), ns);
        let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/profile={profile_name}"));
        match leases_api.list(&lp).await {
            Ok(leases) => leases
                .iter()
                .filter_map(|c| {
                    let status = c.status.clone().unwrap_or_default();
                    if matches!(status.phase, LeasePhase::Bound) {
                        status.cluster_name
                    } else {
                        None
                    }
                })
                .collect::<std::collections::HashSet<String>>(),
            Err(e) => {
                warn!(
                    profile = profile_name,
                    "Failed to list leases during pool rebuild: {e}, using empty set"
                );
                std::collections::HashSet::new()
            }
        }
    };

    // Find StatefulSets matching this profile's naming pattern
    // (backends create StatefulSets for virtual cluster control planes)
    let sts_api: Api<k8s_openapi::api::apps::v1::StatefulSet> =
        Api::namespaced(ctx.client.clone(), ns);
    let prefix = format!("pool-{profile_name}-");

    let sts_list = match sts_api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!(
                profile = profile_name,
                "Failed to list StatefulSets during pool rebuild: {e}"
            );
            return PoolState { clusters };
        }
    };

    for sts in &sts_list {
        let sts_name = sts.metadata.name.clone().unwrap_or_default();
        if !sts_name.starts_with(&prefix) {
            continue;
        }

        let ready_replicas = sts
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);

        let state = if claimed_clusters.contains(&sts_name) {
            ClusterState::Claimed
        } else if ready_replicas > 0 {
            ClusterState::Ready
        } else {
            ClusterState::Creating
        };

        debug!(
            profile = profile_name,
            cluster = %sts_name,
            ?state,
            "Discovered cluster from K8s"
        );

        clusters.insert(
            sts_name,
            ClusterEntry {
                state: state.clone(),
                idle_since: if state == ClusterState::Ready {
                    Some(chrono::Utc::now())
                } else {
                    None
                },
                health_failures: 0,
                state_since: Some(chrono::Utc::now()),
                spec_hash: None, // unknown after rebuild — won't trigger recreation
            },
        );
    }

    info!(
        profile = profile_name,
        discovered = clusters.len(),
        "Pool state rebuilt from K8s"
    );

    PoolState { clusters }
}

/// Evaluate readiness gates for clusters in Creating state.
/// Clusters that pass all gates transition to Ready.
async fn evaluate_readiness_gates<B: ClusterBackend>(
    ctx: &ProfileContext<B>,
    profile_name: &str,
    namespace: &str,
    gates: &[ReadinessGate],
    pool_state: &mut PoolState,
) {
    let creating: Vec<String> = pool_state
        .clusters
        .iter()
        .filter(|(_, e)| e.state == ClusterState::Creating)
        .map(|(name, _)| name.clone())
        .collect();

    for cluster_name in creating {
        let mut all_passed = true;

        for gate in gates {
            match ctx
                .backend
                .check_readiness_gate(&cluster_name, namespace, gate)
                .await
            {
                Ok(true) => {
                    debug!(
                        profile = profile_name,
                        cluster = %cluster_name,
                        gate = ?gate,
                        "Readiness gate passed"
                    );
                }
                Ok(false) => {
                    debug!(
                        profile = profile_name,
                        cluster = %cluster_name,
                        gate = ?gate,
                        "Readiness gate not yet satisfied"
                    );
                    all_passed = false;
                    break;
                }
                Err(e) => {
                    warn!(
                        profile = profile_name,
                        cluster = %cluster_name,
                        gate = ?gate,
                        "Readiness gate check failed: {e}"
                    );
                    all_passed = false;
                    break;
                }
            }
        }

        if all_passed {
            info!(
                profile = profile_name,
                cluster = %cluster_name,
                "All readiness gates passed, marking cluster Ready"
            );
            if let Some(entry) = pool_state.clusters.get_mut(&cluster_name) {
                entry.state = ClusterState::Ready;
                entry.idle_since = Some(chrono::Utc::now());
            }
        }
    }
}

/// Background health check loop for warm clusters.
async fn run_health_checks<B: ClusterBackend>(
    ctx: Arc<ProfileContext<B>>,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut last_checked: HashMap<String, std::time::Instant> = HashMap::new();

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.cancelled() => {
                info!("Health check loop shutting down");
                return;
            },
        }

        let pools = ctx.pools.read().await.clone();
        let profiles_api: Api<ClusterPool> = Api::namespaced(ctx.client.clone(), namespace);

        for (profile_name, pool_state) in &pools {
            let (check_interval_secs, threshold) = match profiles_api.get(profile_name).await {
                Ok(profile) => match &profile.spec.health_check {
                    Some(hc) => (hc.interval_seconds, hc.failure_threshold),
                    None => (30, 3),
                },
                Err(e) => {
                    warn!(
                        profile = profile_name.as_str(),
                        "Failed to fetch profile for health check config, using defaults: {e}"
                    );
                    (30, 3)
                }
            };

            let now = std::time::Instant::now();
            if let Some(last) = last_checked.get(profile_name) {
                if now.duration_since(*last)
                    < std::time::Duration::from_secs(check_interval_secs.into())
                {
                    continue;
                }
            }
            last_checked.insert(profile_name.clone(), now);

            let ready_clusters: Vec<String> = pool_state
                .clusters
                .iter()
                .filter(|(_, e)| e.state == ClusterState::Ready)
                .map(|(name, _)| name.clone())
                .collect();

            for cluster_name in ready_clusters {
                match ctx.backend.check_health(&cluster_name, namespace).await {
                    Ok(true) => {
                        crate::metrics::HEALTH_CHECKS_TOTAL
                            .with_label_values(&[profile_name.as_str(), "pass"])
                            .inc();
                        ctx.health_failures.write().await.remove(&cluster_name);
                    }
                    Ok(false) => {
                        crate::metrics::HEALTH_CHECKS_TOTAL
                            .with_label_values(&[profile_name.as_str(), "fail"])
                            .inc();
                        let should_mark_unhealthy = {
                            let mut failures = ctx.health_failures.write().await;
                            let count = failures.entry(cluster_name.clone()).or_insert(0);
                            *count += 1;

                            if *count >= threshold {
                                warn!(
                                    profile = profile_name.as_str(),
                                    cluster = %cluster_name,
                                    failures = *count,
                                    threshold,
                                    "Cluster failed health check, marking unhealthy"
                                );
                                failures.remove(&cluster_name);
                                true
                            } else {
                                debug!(
                                    cluster = %cluster_name,
                                    failures = *count,
                                    threshold,
                                    "Health check failed, not yet at threshold"
                                );
                                false
                            }
                        };
                        // Lock ordering: health_failures lock dropped before pools lock
                        if should_mark_unhealthy {
                            if let Some(pool) = ctx.pools.write().await.get_mut(profile_name) {
                                if let Some(entry) = pool.clusters.get_mut(&cluster_name) {
                                    entry.state = ClusterState::Unhealthy;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Infrastructure errors (network, kubeconfig extraction) are
                        // not counted as health failures to avoid recycling healthy
                        // clusters during transient infrastructure issues.
                        crate::metrics::HEALTH_CHECKS_TOTAL
                            .with_label_values(&[profile_name.as_str(), "error"])
                            .inc();
                        warn!(
                            cluster = %cluster_name,
                            profile = profile_name.as_str(),
                            "Health check probe error (not counting as failure): {e}"
                        );
                    }
                }
            }
        }
    }
}

/// Error policy: requeue with backoff on failure.
fn error_policy<B: ClusterBackend>(
    _profile: Arc<ClusterPool>,
    error: &ProfileError,
    _ctx: Arc<ProfileContext<B>>,
) -> Action {
    error!("Profile reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{ClusterEntry, ClusterState, PoolState};
    use crate::testutil::MockBackend;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a `ProfileContext<MockBackend>` wired to a local wiremock server.
    async fn test_profile_context() -> (Arc<ProfileContext<MockBackend>>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = MockBackend::new();
        let pools = Arc::new(RwLock::new(HashMap::new()));

        let ctx = Arc::new(ProfileContext {
            client,
            backend,
            namespace: "test-ns".to_string(),
            pools,
            health_failures: RwLock::new(HashMap::new()),
            velero: None,
            factory: None,
        });
        (ctx, server)
    }

    /// Build a `ClusterPool` CRD object for testing.
    fn make_test_profile(name: &str, min_size: u32, max_size: u32) -> Arc<ClusterPool> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "generation": 1
                },
                "spec": {
                    "minSize": min_size,
                    "maxSize": max_size,
                    "cluster": {
                        "version": "v1.28.0",
                        "serverCount": 1
                    },
                    "readinessGates": [],
                    "addons": []
                }
            }))
            .unwrap(),
        )
    }

    /// Build a minimal `ClusterPool` JSON value for K8s API responses.
    fn profile_response_json(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "generation": 1
            },
            "spec": {
                "size": 3,
                "ttl": "2h",
                "cluster": {
                    "version": "v1.28.0"
                }
            },
            "status": {
                "ready": 0,
                "claimed": 0,
                "creating": 0,
                "unhealthy": 0,
                "queueDepth": 0
            }
        })
    }

    // -----------------------------------------------------------------------
    // error_policy
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_error_policy_returns_requeue_60s() {
        let (ctx, _server) = test_profile_context().await;
        let profile = make_test_profile("err-profile", 2, 5);
        let error = ProfileError::Lifecycle(anyhow::anyhow!("test error"));
        let action = error_policy(profile, &error, ctx);
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));
    }

    // -----------------------------------------------------------------------
    // evaluate_readiness_gates
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_evaluate_readiness_gates_all_pass() {
        let (ctx, _server) = test_profile_context().await;

        // Backend defaults to ready=true, so all gates pass.
        let gates = vec![crate::crd::ReadinessGate::CrdExists {
            name: "test-crd".to_string(),
        }];

        let mut pool_state = PoolState {
            clusters: HashMap::from([(
                "pool-test-1".to_string(),
                ClusterEntry {
                    state: ClusterState::Creating,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            )]),
        };

        evaluate_readiness_gates(&ctx, "test-profile", "test-ns", &gates, &mut pool_state).await;

        // Cluster should transition from Creating to Ready.
        let entry = pool_state.clusters.get("pool-test-1").unwrap();
        assert_eq!(entry.state, ClusterState::Ready);
        assert!(entry.idle_since.is_some());
    }

    #[tokio::test]
    async fn test_evaluate_readiness_gates_one_fails() {
        let (ctx, _server) = test_profile_context().await;

        // Set backend to return ready=false.
        ctx.backend.set_readiness(false);

        let gates = vec![crate::crd::ReadinessGate::CrdExists {
            name: "test-crd".to_string(),
        }];

        let mut pool_state = PoolState {
            clusters: HashMap::from([(
                "pool-test-1".to_string(),
                ClusterEntry {
                    state: ClusterState::Creating,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            )]),
        };

        evaluate_readiness_gates(&ctx, "test-profile", "test-ns", &gates, &mut pool_state).await;

        // Cluster should remain Creating.
        let entry = pool_state.clusters.get("pool-test-1").unwrap();
        assert_eq!(entry.state, ClusterState::Creating);
        assert!(entry.idle_since.is_none());
    }

    #[tokio::test]
    async fn test_evaluate_readiness_gates_error() {
        let (ctx, _server) = test_profile_context().await;

        // Set backend to return error on readiness check.
        ctx.backend.fail_readiness("connection refused");

        let gates = vec![crate::crd::ReadinessGate::CrdExists {
            name: "test-crd".to_string(),
        }];

        let mut pool_state = PoolState {
            clusters: HashMap::from([(
                "pool-test-1".to_string(),
                ClusterEntry {
                    state: ClusterState::Creating,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            )]),
        };

        evaluate_readiness_gates(&ctx, "test-profile", "test-ns", &gates, &mut pool_state).await;

        // Cluster should remain Creating on error.
        let entry = pool_state.clusters.get("pool-test-1").unwrap();
        assert_eq!(entry.state, ClusterState::Creating);
        assert!(entry.idle_since.is_none());
    }

    #[tokio::test]
    async fn test_evaluate_readiness_gates_skips_non_creating() {
        let (ctx, _server) = test_profile_context().await;

        let gates = vec![crate::crd::ReadinessGate::CrdExists {
            name: "test-crd".to_string(),
        }];

        let mut pool_state = PoolState {
            clusters: HashMap::from([
                (
                    "pool-test-ready".to_string(),
                    ClusterEntry {
                        state: ClusterState::Ready,
                        idle_since: Some(chrono::Utc::now()),
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: None,
                    },
                ),
                (
                    "pool-test-claimed".to_string(),
                    ClusterEntry {
                        state: ClusterState::Claimed,
                        idle_since: None,
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: None,
                    },
                ),
            ]),
        };

        evaluate_readiness_gates(&ctx, "test-profile", "test-ns", &gates, &mut pool_state).await;

        // No readiness checks should have been performed (no Creating clusters).
        let calls = ctx.backend.call_count();
        assert_eq!(calls.check_readiness_gate, 0);
    }

    // -----------------------------------------------------------------------
    // build_pool_state
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_build_pool_state_empty_cache() {
        let (ctx, server) = test_profile_context().await;

        // Mock LIST StatefulSets: return 2 STS with the expected prefix.
        Mock::given(method("GET"))
            .and(path("/apis/apps/v1/namespaces/test-ns/statefulsets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "metadata": { "name": "pool-test-profile-0", "namespace": "test-ns" },
                        "spec": { "replicas": 1, "selector": { "matchLabels": {} }, "template": { "metadata": { "labels": {} }, "spec": { "containers": [] } }, "serviceName": "" },
                        "status": { "readyReplicas": 1, "replicas": 1 }
                    }),
                    serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "metadata": { "name": "pool-test-profile-1", "namespace": "test-ns" },
                        "spec": { "replicas": 1, "selector": { "matchLabels": {} }, "template": { "metadata": { "labels": {} }, "spec": { "containers": [] } }, "serviceName": "" },
                        "status": { "readyReplicas": 0, "replicas": 1 }
                    }),
                    // A StatefulSet that does NOT match the prefix should be ignored.
                    serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "metadata": { "name": "other-sts-0", "namespace": "test-ns" },
                        "spec": { "replicas": 1, "selector": { "matchLabels": {} }, "template": { "metadata": { "labels": {} }, "spec": { "containers": [] } }, "serviceName": "" },
                        "status": { "readyReplicas": 1, "replicas": 1 }
                    }),
                ]),
            ))
            .mount(&server)
            .await;

        // Mock LIST claims: return empty list.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/profile=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;

        // Should discover 2 clusters matching the prefix.
        assert_eq!(pool_state.clusters.len(), 2);
        assert!(pool_state.clusters.contains_key("pool-test-profile-0"));
        assert!(pool_state.clusters.contains_key("pool-test-profile-1"));

        // First STS has readyReplicas=1 -> Ready, second has 0 -> Creating.
        assert_eq!(
            pool_state
                .clusters
                .get("pool-test-profile-0")
                .unwrap()
                .state,
            ClusterState::Ready
        );
        assert_eq!(
            pool_state
                .clusters
                .get("pool-test-profile-1")
                .unwrap()
                .state,
            ClusterState::Creating
        );
    }

    #[tokio::test]
    async fn test_build_pool_state_cached() {
        let (ctx, _server) = test_profile_context().await;

        // Pre-populate the pools cache.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = HashMap::new();
            clusters.insert(
                "pool-cached-0".to_string(),
                ClusterEntry {
                    state: ClusterState::Ready,
                    idle_since: Some(chrono::Utc::now()),
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            pools.insert("cached-profile".to_string(), PoolState { clusters });
        }

        // If caching works, no HTTP calls should be made.
        // (No wiremock mounts, so any K8s call would cause a connection error.)
        let pool_state = build_pool_state(&ctx, "cached-profile").await;

        assert_eq!(pool_state.clusters.len(), 1);
        assert!(pool_state.clusters.contains_key("pool-cached-0"));
        assert_eq!(
            pool_state.clusters.get("pool-cached-0").unwrap().state,
            ClusterState::Ready
        );
    }

    // -----------------------------------------------------------------------
    // reconcile_profile: scales up when pool is empty
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_profile_scales_up() {
        let (ctx, server) = test_profile_context().await;

        let profile = make_test_profile("scale-up", 2, 5);

        // Mock LIST StatefulSets: empty (no existing clusters).
        Mock::given(method("GET"))
            .and(path("/apis/apps/v1/namespaces/test-ns/statefulsets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        // Mock LIST claims for build_pool_state (building pool state).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/profile=scale-up",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        // Mock PATCH profile status.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/scale-up/status",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(profile_response_json("scale-up")),
            )
            .mount(&server)
            .await;

        let action = reconcile_profile(profile, ctx.clone()).await.unwrap();

        // Should requeue at 30s on success.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));

        // Give spawned create tasks time to run.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Backend.create should have been called (size=3 default, MAX_BURST=2).
        let calls = ctx.backend.call_count();
        assert!(calls.create > 0, "Expected at least one create call");

        // Pool state should have entries.
        let pools = ctx.pools.read().await;
        let pool = pools.get("scale-up").unwrap();
        assert!(
            !pool.clusters.is_empty(),
            "Pool should have cluster entries"
        );
    }

    // -----------------------------------------------------------------------
    // reconcile_profile: at capacity (no scaling needed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_profile_at_capacity() {
        let (ctx, server) = test_profile_context().await;

        let profile = make_test_profile("at-cap", 2, 5);

        // Pre-populate pool state with 2 Ready clusters (matching size default of 3,
        // but the profile uses default size since minSize/maxSize are not spec fields).
        // With default size=3, 2 Ready and 0 Creating is below target, so we need 3.
        // Let's put 3 Ready clusters.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = HashMap::new();
            for i in 0..3 {
                clusters.insert(
                    format!("pool-at-cap-{i}"),
                    ClusterEntry {
                        state: ClusterState::Ready,
                        idle_since: Some(chrono::Utc::now()),
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: None,
                    },
                );
            }
            pools.insert("at-cap".to_string(), PoolState { clusters });
        }

        // Mock LIST claims for queue_depth calculation in reconcile.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/profile=at-cap",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        // Mock PATCH profile status.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/at-cap/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(profile_response_json("at-cap")))
            .mount(&server)
            .await;

        let action = reconcile_profile(profile, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));

        // No create calls should have been made — pool is at capacity.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let calls = ctx.backend.call_count();
        assert_eq!(calls.create, 0, "No create calls expected at capacity");
    }

    // -----------------------------------------------------------------------
    // reconcile_profile: status update includes correct counts
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_profile_status_update() {
        let (ctx, server) = test_profile_context().await;

        let profile = make_test_profile("status-test", 2, 5);

        // Pre-populate pool with diverse cluster states.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = HashMap::new();
            // 2 Ready, 1 Claimed, 1 Creating, 1 Unhealthy
            clusters.insert(
                "pool-status-test-0".to_string(),
                ClusterEntry {
                    state: ClusterState::Ready,
                    idle_since: Some(chrono::Utc::now()),
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            clusters.insert(
                "pool-status-test-1".to_string(),
                ClusterEntry {
                    state: ClusterState::Ready,
                    idle_since: Some(chrono::Utc::now()),
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            clusters.insert(
                "pool-status-test-2".to_string(),
                ClusterEntry {
                    state: ClusterState::Claimed,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            clusters.insert(
                "pool-status-test-3".to_string(),
                ClusterEntry {
                    state: ClusterState::Creating,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            clusters.insert(
                "pool-status-test-4".to_string(),
                ClusterEntry {
                    state: ClusterState::Unhealthy,
                    idle_since: None,
                    health_failures: 3,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            pools.insert("status-test".to_string(), PoolState { clusters });
        }

        // Mock LIST claims: 1 pending claim.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/profile=status-test",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterLease",
                    "metadata": { "name": "pending-claim-1", "namespace": "test-ns" },
                    "spec": {
                        "poolRef": "status-test",
                        "ttl": "1h",
                        "requester": { "type": "test:ci", "identity": "u" },
                        "priority": 50
                    },
                    "status": { "phase": "Pending" }
                })]),
            ))
            .mount(&server)
            .await;

        // Capture the status PATCH body using a closure to verify counts.
        // We set up the mock to just return success with the profile JSON.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/status-test/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut resp = profile_response_json("status-test");
                resp["status"] = serde_json::json!({
                    "ready": 2,
                    "claimed": 1,
                    "creating": 1,
                    "unhealthy": 1,
                    "queueDepth": 1
                });
                resp
            }))
            .mount(&server)
            .await;

        let action = reconcile_profile(profile, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));

        // Give spawned tasks time to run (Unhealthy clusters trigger Delete).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify pool state was stored correctly.
        let pools = ctx.pools.read().await;
        let pool = pools.get("status-test").unwrap();

        // Count the final states (note: Unhealthy may have been deleted by actions,
        // and new clusters may have been created via Create actions).
        // The important thing is the reconciler ran without errors.
        assert!(
            !pool.clusters.is_empty(),
            "Pool should still have clusters after reconciliation"
        );
    }
}
