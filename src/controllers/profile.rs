use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::BackendFactory;
use crate::crd::{
    ClusterInstance, ClusterInstancePhase, ClusterInstanceStatus, ClusterLease, ClusterPool,
    ClusterPoolStatus, LeasePhase, ResourceRef, SnapshotRefreshTrigger,
};
use crate::pool::{
    ClusterEntry, ClusterState, PoolAction, PoolState, compute_pool_actions, count_states,
};
use crate::velero::VeleroCoordinator;

/// Shared state for the profile controller.
pub struct ProfileContext {
    pub client: Client,
    pub namespace: String,
    /// Per-profile pool state, shared with claim controller and API layer.
    pub pools: Arc<RwLock<HashMap<String, PoolState>>>,
    /// Optional Velero coordinator for golden backup/restore operations.
    pub velero: Option<VeleroCoordinator>,
    /// Optional backend factory for per-profile backend dispatch.
    /// When set, `backend_for(profile)` is used instead of `self.backend`
    /// for create/delete operations.
    pub factory: Option<BackendFactory>,
}

#[cfg(test)]
mod cluster_instance_tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn test_profile_context() -> (Arc<ProfileContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let pools = Arc::new(RwLock::new(HashMap::new()));

        let ctx = Arc::new(ProfileContext {
            client,
            namespace: "test-ns".to_string(),
            pools,
            velero: None,
            factory: None,
        });
        (ctx, server)
    }

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

    fn instance_response_json(
        name: &str,
        pool: &str,
        phase: ClusterInstancePhase,
        idle_since: Option<&str>,
        health_failures: u32,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "labels": {
                    "kobe.kunobi.ninja/pool": pool
                }
            },
            "spec": {
                "poolRef": {
                    "name": pool
                }
            },
            "status": {
                "phase": phase,
                "provisioned": true,
                "leaseRef": null,
                "idleSince": idle_since,
                "stateSince": "2026-04-13T10:00:00Z",
                "healthFailures": health_failures,
                "specHash": 42
            }
        })
    }

    #[tokio::test]
    async fn test_error_policy_returns_requeue_60s() {
        let (ctx, _server) = test_profile_context().await;
        let profile = make_test_profile("err-profile", 2, 5);
        let error = ProfileError::Lifecycle(anyhow::anyhow!("test error"));
        let action = error_policy(profile, &error, ctx);
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_build_pool_state_uses_cluster_instances() {
        let (ctx, server) = test_profile_context().await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    instance_response_json(
                        "pool-test-profile-0",
                        "test-profile",
                        ClusterInstancePhase::Ready,
                        Some("2026-04-13T10:01:00Z"),
                        0,
                    ),
                    instance_response_json(
                        "pool-test-profile-1",
                        "test-profile",
                        ClusterInstancePhase::Creating,
                        None,
                        0,
                    ),
                ]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;

        assert_eq!(pool_state.clusters.len(), 2);
        assert_eq!(
            pool_state.clusters["pool-test-profile-0"].state,
            ClusterState::Ready
        );
        assert_eq!(
            pool_state.clusters["pool-test-profile-1"].state,
            ClusterState::Creating
        );
    }

    #[tokio::test]
    async fn test_build_pool_state_preserves_instance_status_fields() {
        let (ctx, server) = test_profile_context().await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![instance_response_json(
                    "pool-test-profile-0",
                    "test-profile",
                    ClusterInstancePhase::Leased,
                    Some("2026-04-13T10:01:00Z"),
                    2,
                )]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;
        let entry = pool_state.clusters.get("pool-test-profile-0").unwrap();
        assert_eq!(entry.state, ClusterState::Leased);
        assert_eq!(entry.health_failures, 2);
        assert_eq!(entry.spec_hash, Some(42));
        assert!(entry.idle_since.is_some());
    }
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
pub async fn run_profile_controller(
    client: Client,
    namespace: &str,
    pools: Arc<RwLock<HashMap<String, PoolState>>>,
    velero: Option<VeleroCoordinator>,
    factory: Option<BackendFactory>,
    shutdown: CancellationToken,
) {
    let profiles: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);

    let ctx = Arc::new(ProfileContext {
        client: client.clone(),
        namespace: namespace.to_string(),
        pools,
        velero,
        factory,
    });

    info!("Starting profile controller");

    let controller = Controller::new(profiles, Config::default())
        .owns(instances, Config::default())
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
/// 2. Evaluate readiness gates and discovery health for Creating clusters
/// 3. Compute desired actions via pool manager (scale up/down)
/// 4. Execute actions (create/delete clusters)
/// 5. Update profile status
#[tracing::instrument(skip_all, fields(profile = %profile.name_any()))]
async fn reconcile_profile(
    profile: Arc<ClusterPool>,
    ctx: Arc<ProfileContext>,
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

    let now = chrono::Utc::now();
    let actions = compute_pool_actions(&profile, &pool_state, now);

    for action in &actions {
        match action {
            PoolAction::Create(cluster_name) => {
                info!(profile = %name, cluster = %cluster_name, "Creating cluster");
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
                ensure_cluster_instance(&instances_api, &profile, cluster_name).await?;
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
            }
            PoolAction::Delete(cluster_name) => {
                info!(profile = %name, cluster = %cluster_name, "Deleting cluster");
                if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                    entry.state = ClusterState::Recycling;
                }
                let current = get_cluster_instance_status(&ctx.client, &ns, cluster_name)
                    .await
                    .unwrap_or_default();
                let _ = patch_cluster_instance_status(
                    &ctx.client,
                    &ns,
                    cluster_name,
                    ClusterInstanceStatus {
                        phase: ClusterInstancePhase::Recycling,
                        provisioned: current.provisioned,
                        bootstrapped: current.bootstrapped,
                        lease_ref: current.lease_ref,
                        active_bootstrap: None,
                        idle_since: None,
                        state_since: Some(chrono::Utc::now().to_rfc3339()),
                        health_failures: current.health_failures,
                        spec_hash: current.spec_hash,
                    },
                )
                .await;
            }
            PoolAction::MarkUnhealthy(cluster_name) => {
                warn!(profile = %name, cluster = %cluster_name, "Marking cluster unhealthy");
                if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                    entry.state = ClusterState::Unhealthy;
                }
            }
        }
    }

    ctx.pools
        .write()
        .await
        .insert(name.clone(), pool_state.clone());
    sync_cluster_instance_statuses(&ctx.client, &ns, &pool_state).await;

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

    let (existing_golden_backup, existing_golden_generation) = profile
        .status
        .as_ref()
        .map(|s| (s.golden_backup.clone(), s.golden_generation))
        .unwrap_or((None, None));

    let existing_golden_template_db = profile
        .status
        .as_ref()
        .and_then(|s| s.golden_template_db.clone());

    let (consecutive_failures, next_attempt_at, last_failure_reason) =
        compute_backoff_state(&profile, &pool_state, &counts, now);

    let phase = crate::pool::manager::compute_pool_phase(
        &profile,
        &counts,
        consecutive_failures,
        next_attempt_at.as_deref(),
        now,
    );

    let status = ClusterPoolStatus {
        phase: Some(phase),
        ready: counts.ready,
        leased: counts.leased,
        creating: counts.creating,
        recycling: counts.recycling,
        unhealthy: counts.unhealthy,
        queue_depth,
        golden_backup: existing_golden_backup,
        golden_generation: existing_golden_generation,
        golden_template_db: existing_golden_template_db,
        consecutive_failures,
        next_attempt_at,
        last_failure_reason,
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

/// Build pool state from ClusterInstance inventory.
async fn build_pool_state(ctx: &ProfileContext, profile_name: &str) -> PoolState {
    info!(
        profile = profile_name,
        "Refreshing pool state from ClusterInstances"
    );

    let ns = &ctx.namespace;
    let mut clusters = HashMap::new();
    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), ns);
    let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/pool={profile_name}"));
    let instances = match instances_api.list(&lp).await {
        Ok(list) => list,
        Err(e) => {
            warn!(
                profile = profile_name,
                "Failed to list ClusterInstances during pool rebuild: {e}"
            );
            return PoolState { clusters };
        }
    };

    for instance in &instances {
        let cluster_name = instance.name_any();
        let status = instance.status.clone().unwrap_or_default();
        let state = cluster_state_from_phase(&status.phase);

        debug!(
            profile = profile_name,
            cluster = %cluster_name,
            ?state,
            "Discovered cluster from ClusterInstance"
        );

        clusters.insert(
            cluster_name,
            ClusterEntry {
                state,
                idle_since: parse_optional_time(status.idle_since.as_deref()),
                health_failures: status.health_failures,
                state_since: parse_optional_time(status.state_since.as_deref()),
                spec_hash: status.spec_hash,
            },
        );
    }

    info!(
        profile = profile_name,
        discovered = clusters.len(),
        "Pool state refreshed from ClusterInstances"
    );

    PoolState { clusters }
}

fn error_policy(
    _profile: Arc<ClusterPool>,
    error: &ProfileError,
    _ctx: Arc<ProfileContext>,
) -> Action {
    error!("Profile reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(60))
}

async fn ensure_cluster_instance(
    instances_api: &Api<ClusterInstance>,
    profile: &ClusterPool,
    cluster_name: &str,
) -> Result<(), ProfileError> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/pool".to_string(), profile.name_any());

    let instance = ClusterInstance {
        metadata: kube::core::ObjectMeta {
            name: Some(cluster_name.to_string()),
            namespace: profile.namespace(),
            labels: Some(labels),
            owner_references: profile.controller_owner_ref(&()).map(|owner| vec![owner]),
            ..Default::default()
        },
        spec: crate::crd::ClusterInstanceSpec {
            pool_ref: Some(ResourceRef {
                name: profile.name_any(),
            }),
            backend: None,
            cluster: None,
            addons: Vec::new(),
            bootstraps: Vec::new(),
            health_check: None,
            readiness_gates: Vec::new(),
            snapshot: None,
        },
        status: Some(ClusterInstanceStatus {
            phase: ClusterInstancePhase::Creating,
            provisioned: false,
            bootstrapped: false,
            lease_ref: None,
            active_bootstrap: None,
            idle_since: None,
            state_since: Some(chrono::Utc::now().to_rfc3339()),
            health_failures: 0,
            spec_hash: Some(crate::pool::profile_spec_hash(profile)),
        }),
    };

    match instances_api.create(&Default::default(), &instance).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 409 => Ok(()),
        Err(e) => Err(ProfileError::Kube(e)),
    }
}

async fn patch_cluster_instance_status(
    client: &Client,
    namespace: &str,
    cluster_name: &str,
    status: ClusterInstanceStatus,
) -> Result<(), kube::Error> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({ "status": status });
    instances_api
        .patch_status(
            cluster_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

async fn sync_cluster_instance_statuses(client: &Client, namespace: &str, pool_state: &PoolState) {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    for (cluster_name, entry) in &pool_state.clusters {
        let current = match instances_api.get(cluster_name).await {
            Ok(instance) => instance.status.unwrap_or_default(),
            Err(_) => continue,
        };
        let _ = patch_cluster_instance_status(
            client,
            namespace,
            cluster_name,
            ClusterInstanceStatus {
                phase: cluster_phase_from_state(&entry.state),
                provisioned: current.provisioned,
                bootstrapped: current.bootstrapped,
                lease_ref: current.lease_ref,
                active_bootstrap: current.active_bootstrap,
                idle_since: entry.idle_since.map(|ts| ts.to_rfc3339()),
                state_since: entry.state_since.map(|ts| ts.to_rfc3339()),
                health_failures: entry.health_failures,
                spec_hash: entry.spec_hash,
            },
        )
        .await;
    }
}

/// Compute the next backoff state for a pool given the previous status,
/// current pool state, and counts.
///
/// Semantics:
/// - If any instance is `Ready` now OR was ever `Ready` in its lifetime
///   (`idle_since` populated) → healthy. Reset counter to 0.
/// - Otherwise, if there is any `Recycling` instance and nothing is
///   `Creating`, the pool is in a "can't make progress" state. Bump the
///   counter once per backoff window (gated by `next_attempt_at`) so that
///   repeated reconciles within the same window don't over-increment.
/// - Leaves state unchanged while `Creating > 0` (a new attempt is in flight).
///
/// Returns `(consecutive_failures, next_attempt_at, last_failure_reason)`.
fn compute_backoff_state(
    profile: &ClusterPool,
    pool_state: &PoolState,
    counts: &crate::pool::manager::StateCounts,
    now: chrono::DateTime<chrono::Utc>,
) -> (u32, Option<String>, Option<String>) {
    let prev = profile
        .status
        .as_ref()
        .map(|s| {
            (
                s.consecutive_failures,
                s.next_attempt_at.clone(),
                s.last_failure_reason.clone(),
            )
        })
        .unwrap_or((0, None, None));

    let (prev_failures, prev_next_attempt, prev_reason) = prev;

    // Anything Ready (now or historically) = pool is healthy.
    let any_ready_or_ever_ready = counts.ready > 0
        || counts.leased > 0
        || pool_state.clusters.values().any(|e| e.idle_since.is_some());

    if any_ready_or_ever_ready {
        return (0, None, None);
    }

    // A create attempt is still in flight — wait to see its outcome.
    if counts.creating > 0 {
        return (prev_failures, prev_next_attempt, prev_reason);
    }

    // Pool has failures and is not making progress. Bump only if the prior
    // backoff window has elapsed (or no window was set), so repeated
    // reconciles inside one window don't over-count.
    if counts.recycling == 0 {
        // Nothing has actually failed; hold the previous state.
        return (prev_failures, prev_next_attempt, prev_reason);
    }

    let window_elapsed = match prev_next_attempt.as_deref() {
        None => true,
        Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
            Ok(t) => now >= t.with_timezone(&chrono::Utc),
            Err(_) => true,
        },
    };

    if !window_elapsed {
        return (prev_failures, prev_next_attempt, prev_reason);
    }

    let new_failures = prev_failures.saturating_add(1);
    let delay = crate::pool::manager::backoff_delay_for(profile, new_failures);
    let next_attempt = delay.map(|d| (now + d).to_rfc3339());

    (new_failures, next_attempt, prev_reason)
}

fn cluster_state_from_phase(phase: &ClusterInstancePhase) -> ClusterState {
    match phase {
        ClusterInstancePhase::Creating => ClusterState::Creating,
        ClusterInstancePhase::Ready => ClusterState::Ready,
        ClusterInstancePhase::Leased => ClusterState::Leased,
        ClusterInstancePhase::Recycling => ClusterState::Recycling,
        ClusterInstancePhase::Unhealthy => ClusterState::Unhealthy,
        ClusterInstancePhase::Failed => ClusterState::Unhealthy,
    }
}

fn cluster_phase_from_state(state: &ClusterState) -> ClusterInstancePhase {
    match state {
        ClusterState::Creating => ClusterInstancePhase::Creating,
        ClusterState::Ready => ClusterInstancePhase::Ready,
        ClusterState::Leased => ClusterInstancePhase::Leased,
        ClusterState::Recycling => ClusterInstancePhase::Recycling,
        ClusterState::Unhealthy => ClusterInstancePhase::Unhealthy,
    }
}

fn parse_optional_time(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

async fn get_cluster_instance_status(
    client: &Client,
    namespace: &str,
    cluster_name: &str,
) -> Option<ClusterInstanceStatus> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    instances_api
        .get(cluster_name)
        .await
        .ok()
        .and_then(|instance| instance.status)
}
