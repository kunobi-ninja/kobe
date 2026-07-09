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
    /// Operator-level config that affects rendered backend resources
    /// (currently the kobe-sync sidecar image). Folded into
    /// `profile_spec_hash` so a sidecar bump triggers vkobe pool
    /// recycling automatically. See `pool::manager::RenderContext`.
    pub render_ctx: crate::pool::RenderContext,
    /// `(profile, generation)` pairs whose golden backup is currently being
    /// built. A golden backup runs for minutes and only records its generation
    /// on success, so without this guard every ~30s reconcile would respawn a
    /// duplicate task that races on the same temp cluster + Velero Backup name.
    pub golden_in_progress: Arc<std::sync::Mutex<std::collections::HashSet<(String, i64)>>>,
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
            render_ctx: crate::pool::RenderContext::with_kobe_sync_image("zondax/kobe-sync:test"),
            golden_in_progress: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
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

    fn profile_with_status(status: serde_json::Value) -> ClusterPool {
        profile_with_status_named("p", status)
    }

    fn profile_with_status_named(name: &str, status: serde_json::Value) -> ClusterPool {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": { "name": name, "namespace": "test-ns" },
            "spec": {
                "minSize": 2, "maxSize": 5,
                "cluster": { "version": "v1.28.0", "serverCount": 1 },
                "readinessGates": [], "addons": []
            },
            "status": status
        }))
        .unwrap()
    }

    #[test]
    fn backoff_populates_last_failure_reason_when_failing() {
        // attempted up to index 3, only reached Ready at 1 → 2 failures.
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let pool_state = PoolState {
            clusters: HashMap::new(),
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
        assert!(backoff.consecutive_failures > 0);
        let reason = backoff
            .last_failure_reason
            .expect("last_failure_reason must be populated while failing");
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        assert!(reason.contains("pool=p"), "got: {reason}");
    }

    #[test]
    fn backoff_clears_last_failure_reason_on_recovery() {
        // Every attempted index has reached Ready → caught up → reason cleared.
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 0, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 3,
            "lastFailureReason": "stale reason"
        }));
        let pool_state = PoolState {
            clusters: HashMap::new(),
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
        assert_eq!(backoff.consecutive_failures, 0);
        assert!(backoff.last_failure_reason.is_none());
    }

    /// Minimal `ClusterEntry` for backoff/gauge tests, with `scheduling_blocked`
    /// configurable. Other fields are inert for these computations.
    fn entry_with_block(state: ClusterState, scheduling_blocked: bool) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: None,
            health_failures: 0,
            state_since: None,
            spec_hash: None,
            scheduling_blocked,
            crashlooping: false,
        }
    }

    /// #189 (observability): when the #191 scheduling-blocked backpressure is
    /// engaged, the reason string gains the `capacity-blocked:` wording so it's
    /// classifiable as `PoolFailureClass::Capacity`. This is a STRING-ONLY
    /// enrichment — the failure count (control-flow signal) is unchanged.
    #[test]
    fn backoff_reason_carries_capacity_wording_when_scheduling_blocked() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, true),
        );
        let pool_state = PoolState { clusters };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        let reason = backoff
            .last_failure_reason
            .clone()
            .expect("reason populated while scheduling-blocked");
        assert!(
            reason.starts_with("capacity-blocked:"),
            "expected capacity wording, got: {reason}"
        );
        assert!(reason.contains("unschedulable"), "got: {reason}");
        // The original triage detail is preserved (only prefixed).
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        // The structural failure class reflects the capacity wedge.
        assert_eq!(
            backoff.failure_class,
            crate::metrics::PoolFailureClass::Capacity
        );
        // Control-flow signal (failure count) is still engaged, unchanged.
        assert!(backoff.consecutive_failures > 0);
    }

    /// A non-blocked failing pool produces the SAME backoff result it does
    /// today: no capacity wording, same failure count / reason content. Guards
    /// against the #189 string enrichment leaking into the non-blocked path.
    #[test]
    fn backoff_reason_unchanged_for_non_blocked_failing_pool() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, false),
        );
        let pool_state = PoolState { clusters };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        let reason = backoff
            .last_failure_reason
            .expect("reason populated while failing");
        assert!(
            !reason.contains("capacity-blocked"),
            "non-blocked pool must not get capacity wording, got: {reason}"
        );
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        // Failure count is the plain index-gap (3 - 1 = 2), unchanged.
        assert_eq!(backoff.consecutive_failures, 2);
    }

    /// The generic (non-capacity) pool failure carries no attributable cause, so
    /// its structural `failure_class` MUST be `Other`.
    #[test]
    fn generic_failure_class_is_other() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, false),
        );
        let pool_state = PoolState { clusters };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        assert_eq!(
            backoff.failure_class,
            crate::metrics::PoolFailureClass::Other
        );
    }

    /// The metric's `failure_class` is set STRUCTURALLY, so a pool whose NAME
    /// happens to contain a `from_reason` cause keyword must NOT be misclassified
    /// — even though the free-form reason text (which embeds the pool name) would
    /// trip that keyword if it were ever parsed. This is the general form of the
    /// `Unhealthy`→`health` collision: the reason string carries dynamic data and
    /// can never be a sound classification source.
    #[test]
    fn structural_failure_class_ignores_keyword_in_pool_name() {
        use crate::metrics::PoolFailureClass as P;
        // Each name embeds a distinct cause keyword; the generic failure class
        // must stay `Other` regardless, while `from_reason` on the same text
        // demonstrates the collision the structural approach avoids.
        let cases = [
            ("health-pool", P::Health),
            ("create-pool", P::BackendCreate),
            ("bootstrap-pool", P::Bootstrap),
            ("delete-pool", P::BackendDelete),
            ("ipam-pool", P::Ipam),
        ];
        for (name, collided) in cases {
            let profile = profile_with_status_named(
                name,
                serde_json::json!({
                    "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
                }),
            );
            let mut clusters = HashMap::new();
            clusters.insert(
                format!("pool-{name}-0"),
                entry_with_block(ClusterState::Creating, false),
            );
            let pool_state = PoolState { clusters };
            let counts = crate::pool::manager::StateCounts::default();
            let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
            let reason = backoff
                .last_failure_reason
                .as_deref()
                .expect("reason populated while failing");

            // The string classifier WOULD mislabel it (documents the hazard)…
            assert_eq!(
                P::from_reason(reason),
                collided,
                "expected the string classifier to collide on name {name}"
            );
            // …but the structural class the metric actually uses is correct.
            assert_eq!(
                backoff.failure_class,
                P::Other,
                "structural class must ignore pool-name keyword for {name}"
            );
        }
    }

    /// `persisted_failure_class` recovers a prior reconcile's class from the
    /// capacity marker ONLY — never by keyword-parsing the free-form text, so a
    /// pool named with a cause keyword is still recovered as `Other`.
    #[test]
    fn persisted_failure_class_recovers_via_marker_not_keywords() {
        use crate::metrics::PoolFailureClass as P;
        assert_eq!(persisted_failure_class(None), P::Other);
        assert_eq!(
            persisted_failure_class(Some(
                "capacity-blocked: 2 instance(s) unschedulable; 2 instance(s) not reaching Ready"
            )),
            P::Capacity
        );
        // Generic reason — even one whose pool name embeds a keyword — is `Other`.
        assert_eq!(
            persisted_failure_class(Some(
                "2 instance(s) not reaching Ready ... kubectl get ci -l \
                 kobe.kunobi.ninja/pool=health-pool ..."
            )),
            P::Other
        );
    }

    /// The reason-change counter fires on a class TRANSITION even when the
    /// failure count is unchanged (`Other`→`Capacity` at the same count), but not
    /// on steady-state failure at an unchanged class.
    #[test]
    fn reason_change_counter_fires_on_class_transition_at_equal_count() {
        use crate::metrics::PoolFailureClass as P;
        crate::metrics::init();
        let counter = &crate::metrics::POOL_FAILURE_REASON_CHANGES_TOTAL;
        let profile = "xition-test-pool";

        // Steady state: same count, same class → no increment.
        let before_other = counter.with_label_values(&[profile, "other"]).get();
        emit_pool_failure_metrics(
            profile,
            &PoolFailureSignals {
                consecutive_failures: 2,
                prev_failures: 2,
                failure_class: P::Other,
                prev_failure_class: P::Other,
            },
        );
        assert_eq!(
            counter.with_label_values(&[profile, "other"]).get(),
            before_other,
            "unchanged class at unchanged count must not re-count"
        );

        // Class flip Other→Capacity at the SAME count → one increment on capacity.
        let before_cap = counter.with_label_values(&[profile, "capacity"]).get();
        emit_pool_failure_metrics(
            profile,
            &PoolFailureSignals {
                consecutive_failures: 2,
                prev_failures: 2,
                failure_class: P::Capacity,
                prev_failure_class: P::Other,
            },
        );
        assert_eq!(
            counter.with_label_values(&[profile, "capacity"]).get(),
            before_cap + 1,
            "a class transition at equal count must be counted"
        );
    }

    /// #189 (observability): the `kobe_pool_capacity_blocked` gauge reflects the
    /// presence of any scheduling-blocked instance in pool_state — 0 when none,
    /// 1 when present. Read-only mirror of the #191 backpressure signal.
    #[test]
    fn pool_capacity_blocked_gauge_reflects_scheduling_blocked_presence() {
        crate::metrics::init();
        let g = &crate::metrics::POOL_CAPACITY_BLOCKED;

        // No blocked instances → 0.
        let none = [
            entry_with_block(ClusterState::Ready, false),
            entry_with_block(ClusterState::Creating, false),
        ];
        let blocked_none = none.iter().any(|e| e.scheduling_blocked);
        g.with_label_values(&["gauge-test-none"])
            .set(i64::from(blocked_none));
        assert_eq!(g.with_label_values(&["gauge-test-none"]).get(), 0);

        // Any blocked instance → 1.
        let some = [
            entry_with_block(ClusterState::Ready, false),
            entry_with_block(ClusterState::Creating, true),
        ];
        let blocked_some = some.iter().any(|e| e.scheduling_blocked);
        g.with_label_values(&["gauge-test-some"])
            .set(i64::from(blocked_some));
        assert_eq!(g.with_label_values(&["gauge-test-some"]).get(), 1);
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
                "specHash": "002a000000000000"
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
        assert_eq!(entry.spec_hash.as_deref(), Some("002a000000000000"));
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
    render_ctx: crate::pool::RenderContext,
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
        render_ctx,
        golden_in_progress: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
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
    if let (Some(velero), Some(snapshot)) = (&ctx.velero, &profile.spec.snapshot)
        && snapshot.enabled
        && let SnapshotRefreshTrigger::ProfileChange = snapshot.refresh_on
    {
        let profile_gen = profile.metadata.generation.unwrap_or(1);
        let golden_gen = profile
            .status
            .as_ref()
            .and_then(|s| s.golden_generation)
            .unwrap_or(0);

        if profile_gen > golden_gen {
            // Skip if a backup for this generation is already running. The guard
            // is released by the spawned task on completion (success OR failure).
            // status.goldenGeneration is only written on success, so without this
            // every ~30s reconcile during the multi-minute backup would respawn a
            // duplicate task racing on the same temp cluster + Velero Backup name.
            let key = (name.clone(), profile_gen);
            let newly_started = ctx.golden_in_progress.lock().unwrap().insert(key.clone());
            if !newly_started {
                debug!(
                    profile = %name,
                    generation = profile_gen,
                    "Golden backup already in progress for this generation, not respawning"
                );
            } else {
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
                        Default::default(),
                    ))
                };
                let client = ctx.client.clone();
                let ns = ns.clone();
                let in_progress = ctx.golden_in_progress.clone();

                tokio::spawn(async move {
                    let generation = profile_gen;
                    match velero
                        .create_golden_backup(&profile_name, &spec, &backend, &snapshot, generation)
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

                    // Release the guard so a later generation (or a retry after
                    // failure) can rebuild.
                    in_progress.lock().unwrap().remove(&key);
                });
            }
        }
    }

    let now = chrono::Utc::now();

    // Resolve every BootstrapConfig CR this pool references so the
    // hash captures their CONTENT, not just their names. A user
    // editing a bootstrap (new flux install manifest, different
    // shell script, …) without touching the pool spec would
    // otherwise silently apply only to NEW pool members, leaving
    // existing idle ones running stale logic. Failures here are
    // logged and skipped — a missing bootstrap maps to an
    // "<unresolved>" sentinel inside the hasher, so the hash flips
    // deterministically rather than depending on whether the lookup
    // happened to succeed at this exact reconcile.
    let bootstrap_specs = resolve_bootstrap_specs(&ctx.client, &ns, &profile).await;

    let actions = compute_pool_actions(
        &profile,
        &pool_state,
        now,
        &ctx.render_ctx,
        &bootstrap_specs,
    );

    // Check whether the backend datastore is degraded. When kine/etcd
    // is OOMKilling or in a restart loop, every new ClusterInstance we
    // create will fail to bootstrap (apiserver lease writes time out
    // → kube-controller-manager loses its lease → flux install hangs
    // → BackoffLimitExceeded → recycle), and the recycle adds more
    // load to the already-broken backend. Refusing to spawn new
    // instances breaks that cycle. Other actions (Delete, Recycle of
    // already-failed instances) still proceed so we don't strand
    // resources.
    //
    // `None` means OK-to-create; `Some(reason)` means halt creates for this
    // reconcile. The reason is LOGGED only — it is deliberately NOT written into
    // `ClusterPool.status` and does NOT feed the pool-failure metrics: a
    // degraded datastore is not a per-pool provision failure, and it already has
    // its own first-class signal (`kobe_kobestore_healthy`, emitted by
    // `controllers::kobestore_health`, which is also the condition this reads
    // from). Folding it into `consecutiveFailures`/`failure_class` would double-
    // count a cluster-wide outage as N pool failures and perturb backoff/phase.
    let backend_block = pool_creation_blocked_by_backend(&ctx.client, &ns, &profile).await;
    if let Some(ref reason) = backend_block {
        warn!(profile = %name, reason = %reason,
              "Pool creates paused: backend datastore is degraded");
    }

    for action in &actions {
        match action {
            PoolAction::Create(cluster_name) => {
                if let Some(ref reason) = backend_block {
                    debug!(
                        profile = %name, cluster = %cluster_name,
                        reason = %reason,
                        "Skipping Create: backend datastore degraded"
                    );
                    continue;
                }
                info!(profile = %name, cluster = %cluster_name, "Creating cluster");
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
                ensure_cluster_instance(
                    &instances_api,
                    &profile,
                    cluster_name,
                    &ctx.render_ctx,
                    &bootstrap_specs,
                )
                .await?;
                pool_state.clusters.insert(
                    cluster_name.clone(),
                    ClusterEntry {
                        state: ClusterState::Creating,
                        idle_since: None,
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: Some(crate::pool::profile_spec_hash(
                            &profile,
                            &ctx.render_ctx,
                            &bootstrap_specs,
                        )),
                        // Freshly created — it hasn't had a chance to report a
                        // scheduling block or crashloop yet; build_pool_state
                        // recomputes both from status.message next reconcile.
                        scheduling_blocked: false,
                        crashlooping: false,
                    },
                );
            }
            PoolAction::Delete(cluster_name) => {
                info!(profile = %name, cluster = %cluster_name, "Deleting cluster");
                if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                    entry.state = ClusterState::Recycling;
                }
                // `PoolAction::Delete` bundles scale-down, drift-recycle,
                // and post-lease recycle without a reason axis on the
                // action itself; we tag everything as `SpecDrift` here
                // because that's the most common cause and also what an
                // operator sees in `kobectl get clusterinstance` (the
                // spec_hash mismatched). When `PoolAction` gains a
                // typed reason, this label can be split apart.
                crate::metrics::INSTANCE_RECYCLES_TOTAL
                    .with_label_values(&[
                        name.as_str(),
                        crate::metrics::RecycleReason::SpecDrift.as_str(),
                    ])
                    .inc();
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
                        ..Default::default()
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
    emit_cert_expiry_metrics(&ctx.client, &ns, &name, &pool_state).await;

    // Phase metrics here only need the base state taxonomy — pass
    // `None` for `current_hash` so the drift-aware buckets stay 0.
    // `compute_pool_actions` above does its own hash-aware count.
    let counts = count_states(&pool_state, None);

    // Phase 3 state gauges: per-pool size by dimension.
    // `min`/`max` come from the spec; the rest are observed phase
    // counts. Single emit per reconcile, capacity ~10 series per pool
    // — well within Prometheus's comfort zone.
    let pool_size_set = |dim: &str, val: u32| {
        crate::metrics::POOL_SIZE
            .with_label_values(&[name.as_str(), dim])
            .set(val as i64);
    };
    // `desired` is the size target (legacy field) OR the scaling.min_ready
    // floor. `max` is unset for non-scaling pools (gauge stays at default).
    pool_size_set("desired", profile.spec.size);
    if let Some(scaling) = profile.spec.scaling.as_ref() {
        pool_size_set("min", scaling.min_ready);
        pool_size_set("max", scaling.max_clusters);
    }
    pool_size_set("creating", counts.creating);
    pool_size_set("ready", counts.ready);
    pool_size_set("leased", counts.leased);
    pool_size_set("unhealthy", counts.unhealthy);
    pool_size_set("recycling", counts.recycling);

    // Surface hidden CPU over-reservation (issue #189): a pool that sets
    // `resources.limits` with empty `requests` makes the kubelet copy each
    // limit into the request, reserving the full limit on every guest pod
    // (server AND agent). This silently wedged ci-k3s-kunobi (8c → 16/cluster).
    // Meter the effective CPU request and warn so it's visible before the
    // nodes saturate.
    let (effective_cpu_millicores, effective_memory_bytes) =
        if let Some(res) = profile.spec.resources.as_ref() {
            let defaulted = res.limits_without_requests();
            if !defaulted.is_empty() {
                warn!(
                    profile = %name,
                    keys = ?defaulted,
                    "ClusterPool sets resource limits without explicit requests; \
                     Kubernetes reserves the full limit as the request on every guest \
                     pod (server + agent). Set spec.resources.requests to avoid silent \
                     over-reservation."
                );
            }
            (
                res.effective_cpu_millicores().unwrap_or(0),
                res.effective_memory_bytes().unwrap_or(0),
            )
        } else {
            (0, 0)
        };
    crate::metrics::POOL_EFFECTIVE_CPU_REQUEST_MILLICORES
        .with_label_values(&[name.as_str()])
        .set(effective_cpu_millicores);
    crate::metrics::POOL_EFFECTIVE_MEMORY_REQUEST_BYTES
        .with_label_values(&[name.as_str()])
        .set(effective_memory_bytes);

    // #189 (observability): surface "this pool is wedged on capacity" derived
    // from the existing #191 scheduling-blocked state. 1 when any instance is
    // scheduling-blocked (guest Pods unschedulable), else 0. Read-only mirror
    // of the backpressure signal — it does NOT gate admission or alter any
    // create/recycle/backoff decision.
    let capacity_blocked = pool_state.clusters.values().any(|e| e.scheduling_blocked);
    crate::metrics::POOL_CAPACITY_BLOCKED
        .with_label_values(&[name.as_str()])
        .set(i64::from(capacity_blocked));

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

    let backoff = compute_backoff_state(&profile, &pool_state, &counts, now);

    // Snapshot the P0 pool-failure observability inputs BEFORE `backoff` is
    // partially moved into `ClusterPoolStatus` below. `prev_failures` comes
    // from the pre-reconcile status so the reason-change counter fires only on
    // the rising edge; `failure_class` is the bounded class decided
    // structurally in `compute_backoff_state` (never parsed from the free-form
    // reason text). Emitted after the status patch.
    let pool_failure_signals = PoolFailureSignals {
        consecutive_failures: backoff.consecutive_failures,
        prev_failures: profile
            .status
            .as_ref()
            .map(|s| s.consecutive_failures)
            .unwrap_or(0),
        failure_class: backoff.failure_class,
        prev_failure_class: persisted_failure_class(
            profile
                .status
                .as_ref()
                .and_then(|s| s.last_failure_reason.as_deref()),
        ),
    };

    let phase = crate::pool::manager::compute_pool_phase(
        &profile,
        &counts,
        backoff.consecutive_failures,
        backoff.next_attempt_at.as_deref(),
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
        consecutive_failures: backoff.consecutive_failures,
        next_attempt_at: backoff.next_attempt_at,
        last_failure_reason: backoff.last_failure_reason,
        max_attempted_index: backoff.max_attempted_index,
        last_ready_max_index: backoff.last_ready_max_index,
    };

    let patch = serde_json::json!({ "status": status });
    profiles_api
        .patch_status(
            &name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    // P0 observability: pool failure gauge + reason-change edge counter.
    // Emitted after the status patch so the gauge mirrors the value we just
    // persisted (signals snapshotted above before `backoff` was consumed).
    emit_pool_failure_metrics(&name, &pool_failure_signals);

    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// Pre-extracted inputs for the P0 pool-failure metrics, captured before the
/// `BackoffState` is partially moved into `ClusterPoolStatus`.
struct PoolFailureSignals {
    consecutive_failures: u32,
    prev_failures: u32,
    failure_class: crate::metrics::PoolFailureClass,
    prev_failure_class: crate::metrics::PoolFailureClass,
}

/// Emit the P0 pool-failure observability signals for one reconcile.
///
/// - `kobe_pool_consecutive_failures{profile}` — gauge set to the current
///   `consecutive_failures`.
/// - `kobe_pool_failure_reason_changes_total{profile, failure_class}` —
///   incremented on a *new failure edge* (`new > prev`) OR a *class transition
///   while still failing* (e.g. `Other`→`Capacity` when a wedge becomes visible
///   without the count rising). Steady-state failures at an unchanged class
///   aren't re-counted, so this stays a "something changed" signal rather than a
///   reconcile-frequency counter. `failure_class` is the bounded
///   [`crate::metrics::PoolFailureClass`] set structurally on `BackoffState`
///   where the cause is known — never parsed from the reason string.
fn emit_pool_failure_metrics(profile: &str, signals: &PoolFailureSignals) {
    crate::metrics::POOL_CONSECUTIVE_FAILURES
        .with_label_values(&[profile])
        .set(signals.consecutive_failures as i64);

    let new_failure_edge = signals.consecutive_failures > signals.prev_failures;
    let class_transition =
        signals.consecutive_failures > 0 && signals.failure_class != signals.prev_failure_class;
    if new_failure_edge || class_transition {
        crate::metrics::POOL_FAILURE_REASON_CHANGES_TOTAL
            .with_label_values(&[profile, signals.failure_class.as_str()])
            .inc();
    }
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

        // #189: a Creating instance whose backend reported its guest Pods are
        // Unschedulable stamps a known prefix on `status.message`. Surface it
        // as `scheduling_blocked` so the pool manager holds it (backpressure)
        // instead of recycling it on the creating-timeout. Only meaningful
        // while Creating — a Ready/Leased instance has long since scheduled.
        let scheduling_blocked = state == ClusterState::Creating
            && status.message.as_deref().is_some_and(|m| {
                m.starts_with(crate::pool::manager::SCHEDULING_BLOCKED_MESSAGE_PREFIX)
            });

        // #197: a Creating instance whose backend reported its guest container
        // is crashlooping carries the CRASHLOOP marker in `status.message`.
        // Surface it as `crashlooping` so the stuck-Creating recycle is
        // *labelled* `CrashLooping` — but, unlike scheduling_blocked, it is NOT
        // held: a crashlooper still recycles on the creating-timeout as before.
        // Only meaningful while Creating.
        let crashlooping = state == ClusterState::Creating
            && status
                .message
                .as_deref()
                .is_some_and(|m| m.contains(crate::pool::manager::CRASHLOOP_MESSAGE_MARKER));

        debug!(
            profile = profile_name,
            cluster = %cluster_name,
            ?state,
            scheduling_blocked,
            crashlooping,
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
                scheduling_blocked,
                crashlooping,
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

/// Resolve every `BootstrapConfig` referenced by `profile.spec.bootstraps`,
/// returning a name → spec map suitable for feeding into
/// `pool::profile_spec_hash`.
///
/// Best-effort: if a referenced BootstrapConfig is missing or
/// unreadable, it's omitted from the result and the caller will see
/// the `<unresolved>` sentinel inside the hasher (see
/// `pool::profile_spec_hash`). This means a transient lookup failure
/// produces a *different* hash than a successful resolution — drift is
/// detected once the bootstrap reappears, recycle happens, problem
/// solved. The alternative (failing the entire reconcile) would block
/// every other pool action behind a missing CRD.
async fn resolve_bootstrap_specs(
    client: &Client,
    namespace: &str,
    profile: &ClusterPool,
) -> std::collections::BTreeMap<String, crate::crd::BootstrapConfigSpec> {
    use crate::crd::BootstrapConfig;
    use kube::ResourceExt;

    let mut specs = std::collections::BTreeMap::new();
    if profile.spec.bootstraps.is_empty() {
        return specs;
    }

    let api: Api<BootstrapConfig> = Api::namespaced(client.clone(), namespace);
    for bs_ref in &profile.spec.bootstraps {
        match api.get(&bs_ref.name).await {
            Ok(cr) => {
                specs.insert(cr.name_any(), cr.spec);
            }
            Err(e) => {
                tracing::warn!(
                    profile = %profile.name_any(),
                    bootstrap = %bs_ref.name,
                    error = %e,
                    "Failed to resolve BootstrapConfig for spec-hash; \
                     drift detection will treat it as unresolved"
                );
            }
        }
    }
    specs
}

/// Returns `Some(reason)` when the pool's backend datastore (a
/// `KobeStore`, currently only relevant for vkobe pools) is in a
/// `Healthy=False` state, so the profile controller should refuse to
/// create new ClusterInstances against it. `None` means either the
/// pool doesn't reference a KobeStore (k3s/k0s/CAPI) or the backend
/// is healthy / unknown / unevaluated.
///
/// Why not just always check the KobeStore? For vkobe pools we look
/// up `profile.spec.backend.vkobe.data_store_ref.name` and read its
/// status. For non-vkobe pools, the concept doesn't apply, so we skip.
///
/// Why "Unknown" doesn't block: the `Unknown` state is what the health
/// controller writes for externally-managed KobeStores it can't
/// observe. Blocking creates against external stores would be a
/// regression — the operator has no basis to claim they're degraded.
async fn pool_creation_blocked_by_backend(
    client: &Client,
    namespace: &str,
    profile: &ClusterPool,
) -> Option<String> {
    let store_name = profile
        .spec
        .backend
        .vkobe
        .as_ref()
        .map(|v| v.data_store_ref.name.clone())?;

    let stores: Api<crate::crd::KobeStore> = Api::namespaced(client.clone(), namespace);
    let store = stores.get(&store_name).await.ok()?;
    crate::controllers::kobestore_health::unhealthy_reason(&store)
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
    render_ctx: &crate::pool::RenderContext,
    bootstrap_specs: &std::collections::BTreeMap<String, crate::crd::BootstrapConfigSpec>,
) -> Result<(), ProfileError> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/pool".to_string(), profile.name_any());

    // Stamp provenance on the initial status. `created_with` is set
    // here once and never overwritten — every subsequent
    // `patch_instance_status` constructs a fresh status with
    // `created_with: None` (via `..Default::default()`), and the field's
    // `skip_serializing_if = "Option::is_none"` keeps JSON Merge Patch
    // from clobbering the on-disk write. See the field doc comment in
    // `crd::instance::ClusterInstanceStatus`.
    //
    // `kobe_sync_image` is stamped only for vkobe pools — other
    // backends don't run the sync sidecar, so the field would be
    // misleading noise.
    //
    // We read `BUILD_VERSION` (stamped by `build.rs` from the
    // CI-injected env var, falling back to `CARGO_PKG_VERSION` then
    // `"dev"`), NOT `CARGO_PKG_VERSION` directly. `Cargo.toml` keeps
    // `version = "0.0.0"` as a deliberate placeholder so the same
    // workspace builds for every release tag without manual edits;
    // CI sets `BUILD_VERSION=v0.17.0` (etc.) to override. Reading
    // `CARGO_PKG_VERSION` here would always stamp `"0.0.0"`, defeating
    // the entire point of provenance. Same env var that
    // `kobe --version` prints, so the two surfaces stay in sync.
    let provenance = crate::crd::ClusterInstanceProvenance {
        operator_version: env!("BUILD_VERSION").to_string(),
        kobe_sync_image: matches!(
            profile.spec.backend.backend_type,
            crate::crd::BackendType::Vkobe
        )
        .then(|| render_ctx.kobe_sync_image.clone()),
        // Pin the backend that created this instance so future
        // delete / health / addon dispatches use the right backend
        // even after a pool-level backend migration.
        backend_type: Some(profile.spec.backend.backend_type.clone()),
    };

    let initial_status = ClusterInstanceStatus {
        phase: ClusterInstancePhase::Creating,
        provisioned: false,
        bootstrapped: false,
        lease_ref: None,
        active_bootstrap: None,
        idle_since: None,
        state_since: Some(chrono::Utc::now().to_rfc3339()),
        health_failures: 0,
        spec_hash: Some(crate::pool::profile_spec_hash(
            profile,
            render_ctx,
            bootstrap_specs,
        )),
        created_with: Some(provenance),
        ..Default::default()
    };

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
        // The status field set here is silently dropped by the apiserver —
        // status is a subresource and only `patch_status` / `update_status`
        // persist it. We follow up with an explicit status patch below so the
        // initial spec_hash is actually written, instead of staying `None`
        // until the next reconcile sync (which previously could overwrite
        // with `None` if in-memory pool_state lost the entry across an
        // operator restart). See drift detection in
        // `pool::compute_pool_actions`.
        status: Some(initial_status.clone()),
    };

    let created = match instances_api.create(&Default::default(), &instance).await {
        Ok(_) => true,
        Err(kube::Error::Api(ae)) if ae.code == 409 => false,
        Err(e) => return Err(ProfileError::Kube(e)),
    };

    if created {
        let patch = serde_json::json!({ "status": initial_status });
        if let Err(err) = instances_api
            .patch_status(
                cluster_name,
                &PatchParams::apply("kobe-operator"),
                &Patch::Merge(&patch),
            )
            .await
        {
            // Best-effort: the periodic sync will retry. Log so an operator
            // upgrade race is visible rather than silently leaving a hash
            // unset.
            warn!(
                cluster = %cluster_name,
                error = %err,
                "Failed to write initial status (spec_hash) after create; pool sync will retry"
            );
        }
    }

    Ok(())
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

/// Best-effort: emit `kobe_cert_expiry_seconds` for a pool by reading each
/// instance's `{name}-certs` Secret and tracking the soonest-expiring cert per
/// component. Never fails a reconcile — a missing secret (k3s/k0s backends,
/// which manage their own PKI, or an instance not yet provisioned) is simply
/// skipped, so a pool with no kobe-managed PKI emits nothing. See #169.
async fn emit_cert_expiry_metrics(
    client: &Client,
    namespace: &str,
    profile: &str,
    pool_state: &PoolState,
) {
    use k8s_openapi::api::core::v1::Secret;

    // Secret data key -> metric `component` label.
    const COMPONENTS: [(&str, &str); 3] = [
        ("ca.crt", "ca"),
        ("apiserver.crt", "apiserver"),
        ("front-proxy-ca.crt", "front_proxy_ca"),
    ];

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let now = chrono::Utc::now().timestamp();
    let mut worst: HashMap<&str, i64> = HashMap::new();

    for cluster_name in pool_state.clusters.keys() {
        // 404 (non-PKI backend / not yet created) or a transient error → skip.
        let secret = match secrets.get_opt(&format!("{cluster_name}-certs")).await {
            Ok(Some(s)) => s,
            _ => continue,
        };
        let Some(data) = secret.data else { continue };
        for (key, component) in COMPONENTS {
            let Some(pem) = data.get(key).and_then(|b| std::str::from_utf8(&b.0).ok()) else {
                continue;
            };
            let Some(not_after) = crate::pki::cert_not_after_unix(pem) else {
                continue;
            };
            let horizon = not_after - now;
            worst
                .entry(component)
                .and_modify(|m| *m = (*m).min(horizon))
                .or_insert(horizon);
        }
    }

    for (component, horizon) in worst {
        crate::metrics::CERT_EXPIRY_SECONDS
            .with_label_values(&[profile, component])
            .set(horizon);
    }
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
                // Prefer the on-disk hash over the in-memory entry: an
                // operator restart that rebuilds pool_state from the API may
                // briefly hold `entry.spec_hash = None` for a cluster whose
                // status already has a hash recorded. Without this `or`,
                // the sync would clobber that hash to null and break drift
                // detection until a manual ClusterInstance delete.
                spec_hash: current.spec_hash.or_else(|| entry.spec_hash.clone()),
                ..Default::default()
            },
        )
        .await;
    }
}

/// Marker prefix stamped on `last_failure_reason` when the #191 capacity wedge
/// is engaged. It is the ONLY structured marker in the otherwise free-form
/// reason text, so it doubles as the sound inverse used by
/// [`persisted_failure_class`] to recover a prior reconcile's class.
pub(crate) const CAPACITY_BLOCKED_REASON_PREFIX: &str = "capacity-blocked:";

/// Recover the [`crate::metrics::PoolFailureClass`] a *previously persisted*
/// pool reason was emitted with. Only `Capacity` carries a marker
/// ([`CAPACITY_BLOCKED_REASON_PREFIX`]); every other persisted reason was
/// `Other`. This is a marker-based inverse of the structural class — NOT the
/// unsound keyword parsing of [`crate::metrics::PoolFailureClass::from_reason`].
fn persisted_failure_class(reason: Option<&str>) -> crate::metrics::PoolFailureClass {
    match reason {
        Some(r) if r.starts_with(CAPACITY_BLOCKED_REASON_PREFIX) => {
            crate::metrics::PoolFailureClass::Capacity
        }
        _ => crate::metrics::PoolFailureClass::Other,
    }
}

/// Backoff bookkeeping computed once per reconcile.
pub(crate) struct BackoffState {
    pub consecutive_failures: u32,
    pub next_attempt_at: Option<String>,
    pub last_failure_reason: Option<String>,
    /// Bounded failure class for the `kobe_pool_failure_reason_changes_total`
    /// label, set STRUCTURALLY here where the cause is known — never parsed back
    /// out of `last_failure_reason` (that string embeds dynamic data such as the
    /// pool name, so substring classification is unsound: a pool named e.g.
    /// `…-health…` or `create-…` would mislabel the metric).
    pub failure_class: crate::metrics::PoolFailureClass,
    pub max_attempted_index: u32,
    pub last_ready_max_index: u32,
}

/// Compute the next backoff state for a pool.
///
/// Index-based detection:
/// - `max_attempted_index` is the high-water mark of every cluster index the
///   pool has tried (sticky across reconciles).
/// - `last_ready_max_index` is the highest index that ever reached `Ready`
///   (sticky too).
/// - `consecutive_failures` is then derived as the gap:
///   `max_attempted_index - last_ready_max_index`.
///
/// This counts failed attempts correctly even during rapid create→recycle
/// churn, where the previous "no creating, only recycling" detector would
/// never trigger because the next attempt has already started.
///
/// Window gate: `next_attempt_at` is only refreshed when `consecutive_failures`
/// increases — repeated reconciles inside the same window do not over-extend
/// the wait.
fn compute_backoff_state(
    profile: &ClusterPool,
    pool_state: &PoolState,
    counts: &crate::pool::manager::StateCounts,
    now: chrono::DateTime<chrono::Utc>,
) -> BackoffState {
    let prev = profile.status.as_ref();
    let prev_failures = prev.map(|s| s.consecutive_failures).unwrap_or(0);
    let prev_next_attempt = prev.and_then(|s| s.next_attempt_at.clone());
    let prev_reason = prev.and_then(|s| s.last_failure_reason.clone());
    let prev_max_attempted = prev.map(|s| s.max_attempted_index).unwrap_or(0);
    let prev_last_ready_max = prev.map(|s| s.last_ready_max_index).unwrap_or(0);

    // #189: a Creating instance whose guest Pods are Unschedulable is the
    // explicit backpressure signal. The index-gap math below only engages
    // backoff once an attempted index outruns the highest Ready one, which
    // can lag (or never fire) for a single wedged member. Treat a live
    // scheduling block as "engage backoff now" so scale-up is suppressed and
    // `next_attempt_at` is extended — exactly the fail-closed backoff #166
    // wires up — instead of churning new (still-unschedulable) members.
    let scheduling_blocked_present = pool_state.clusters.values().any(|e| e.scheduling_blocked);

    // High-water mark of any cluster name we've ever seen, including the
    // current state and the sticky previous status value.
    let profile_name = profile.metadata.name.clone().unwrap_or_default();
    let live_max = max_index_in_state(pool_state, &profile_name);
    let new_max_attempted = live_max.max(prev_max_attempted);

    // Highest index of any instance that has ever reached `Ready` (or is
    // currently Ready / Leased) in this reconcile's snapshot.
    let max_ready_now = pool_state
        .clusters
        .iter()
        .filter(|(_, e)| {
            e.idle_since.is_some()
                || matches!(
                    e.state,
                    crate::pool::ClusterState::Ready | crate::pool::ClusterState::Leased
                )
        })
        .filter_map(|(name, _)| extract_cluster_index(name, &profile_name))
        .max()
        .unwrap_or(0);
    let new_last_ready_max = max_ready_now.max(prev_last_ready_max);

    // Anything currently Ready/leased OR an instance reached Ready in this
    // pool's lifetime → reset failures to 0. A live scheduling block holds
    // the pool in backpressure though, so we don't take the clean-clear path
    // even when other members are Ready (otherwise scale-up would resume and
    // spawn more Pods the scheduler still can't place).
    let any_ready = counts.ready > 0 || counts.leased > 0 || new_last_ready_max > 0;
    if any_ready && new_last_ready_max >= new_max_attempted && !scheduling_blocked_present {
        // Pool has caught up — every attempted index has reached Ready at
        // some point. Clear failures.
        return BackoffState {
            consecutive_failures: 0,
            next_attempt_at: None,
            last_failure_reason: None,
            failure_class: crate::metrics::PoolFailureClass::Other,
            max_attempted_index: new_max_attempted,
            last_ready_max_index: new_last_ready_max,
        };
    }

    // Index-gap failures, floored to at least 1 while a scheduling block is
    // live so the backoff window is always engaged for the wedged member.
    let new_failures = new_max_attempted
        .saturating_sub(new_last_ready_max)
        .max(u32::from(scheduling_blocked_present));

    // Refresh next_attempt_at only when failure count strictly increased,
    // so repeated reconciles inside one window don't push the wait further.
    // A scheduling block must always carry a (possibly preserved) future
    // attempt time so `backoff_active` keeps suppressing scale-up/recycle.
    let next_attempt = if new_failures > prev_failures && new_failures > 0 {
        crate::pool::manager::backoff_delay_for(profile, new_failures)
            .map(|d| (now + d).to_rfc3339())
    } else if scheduling_blocked_present {
        // Hold the window: refresh if we somehow lost it, else carry forward.
        prev_next_attempt.clone().or_else(|| {
            crate::pool::manager::backoff_delay_for(profile, new_failures.max(1))
                .map(|d| (now + d).to_rfc3339())
        })
    } else if new_failures == 0 {
        None
    } else {
        prev_next_attempt
    };

    // Bounded failure class for the metric label, decided from the signals we
    // actually have — NOT parsed back out of `last_failure_reason` below. That
    // string embeds dynamic data (the pool name, indexes, free-form guidance),
    // so substring classification is unsound. Today the only cause the pool loop
    // can attribute is the #191 capacity wedge; everything else is `Other`.
    let failure_class = if new_failures > 0 && scheduling_blocked_present {
        crate::metrics::PoolFailureClass::Capacity
    } else {
        crate::metrics::PoolFailureClass::Other
    };

    // Populate a triage-actionable reason from the signals we have (the
    // per-instance error isn't carried in PoolState, so we point operators at
    // the failing ClusterInstances rather than inventing detail). Previously
    // this field was only ever carried forward or cleared, so it was always
    // empty — defeating the status field's purpose. This text is human-facing
    // ONLY; the metric label comes from `failure_class` above.
    let last_failure_reason = if new_failures > 0 {
        let base = format!(
            "{new_failures} instance(s) not reaching Ready (attempted up to index \
             {new_max_attempted}, highest Ready {new_last_ready_max}); inspect the \
             Failed/not-Ready ClusterInstances (kubectl get ci -l \
             kobe.kunobi.ninja/pool={profile_name}) and their pod logs/events"
        );
        // #189 (observability): when the #191 scheduling-blocked backpressure is
        // engaged, prefix the reason so it clearly reads as a capacity wedge
        // (`failure_class` above is already `Capacity`). This is a STRING-ONLY
        // enrichment: it does NOT change the phase, the failure count, or any
        // create/recycle/backoff decision — those already reacted to
        // `scheduling_blocked_present` above.
        if scheduling_blocked_present {
            let blocked = pool_state
                .clusters
                .values()
                .filter(|e| e.scheduling_blocked)
                .count();
            Some(format!(
                "{CAPACITY_BLOCKED_REASON_PREFIX} {blocked} instance(s) unschedulable; {base}"
            ))
        } else {
            Some(base)
        }
    } else {
        prev_reason
    };

    BackoffState {
        consecutive_failures: new_failures,
        next_attempt_at: next_attempt,
        last_failure_reason,
        failure_class,
        max_attempted_index: new_max_attempted,
        last_ready_max_index: new_last_ready_max,
    }
}

/// Compute the highest cluster index in the current pool state.
/// Names follow `pool-{profile}-{index}`.
fn max_index_in_state(state: &PoolState, profile_name: &str) -> u32 {
    let prefix = format!("pool-{profile_name}-");
    state
        .clusters
        .keys()
        .filter_map(|name| extract_index_with_prefix(name, &prefix))
        .max()
        .unwrap_or(0)
}

fn extract_cluster_index(name: &str, profile_name: &str) -> Option<u32> {
    let prefix = format!("pool-{profile_name}-");
    extract_index_with_prefix(name, &prefix)
}

fn extract_index_with_prefix(name: &str, prefix: &str) -> Option<u32> {
    name.strip_prefix(prefix)
        .and_then(|suffix| suffix.parse::<u32>().ok())
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
