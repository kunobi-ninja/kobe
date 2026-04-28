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

                        let profiles_api: Api<ClusterPool> = Api::namespaced(client.clone(), &ns);
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

    for action in &actions {
        match action {
            PoolAction::Create(cluster_name) => {
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

    let backoff = compute_backoff_state(&profile, &pool_state, &counts, now);

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
    let provenance = crate::crd::ClusterInstanceProvenance {
        operator_version: env!("CARGO_PKG_VERSION").to_string(),
        kobe_sync_image: matches!(
            profile.spec.backend.backend_type,
            crate::crd::BackendType::Vkobe
        )
        .then(|| render_ctx.kobe_sync_image.clone()),
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

/// Backoff bookkeeping computed once per reconcile.
pub(crate) struct BackoffState {
    pub consecutive_failures: u32,
    pub next_attempt_at: Option<String>,
    pub last_failure_reason: Option<String>,
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
    // pool's lifetime → reset failures to 0.
    let any_ready = counts.ready > 0 || counts.leased > 0 || new_last_ready_max > 0;
    if any_ready && new_last_ready_max >= new_max_attempted {
        // Pool has caught up — every attempted index has reached Ready at
        // some point. Clear failures.
        return BackoffState {
            consecutive_failures: 0,
            next_attempt_at: None,
            last_failure_reason: None,
            max_attempted_index: new_max_attempted,
            last_ready_max_index: new_last_ready_max,
        };
    }

    let new_failures = new_max_attempted.saturating_sub(new_last_ready_max);

    // Refresh next_attempt_at only when failure count strictly increased,
    // so repeated reconciles inside one window don't push the wait further.
    let next_attempt = if new_failures > prev_failures && new_failures > 0 {
        crate::pool::manager::backoff_delay_for(profile, new_failures)
            .map(|d| (now + d).to_rfc3339())
    } else if new_failures == 0 {
        None
    } else {
        prev_next_attempt
    };

    BackoffState {
        consecutive_failures: new_failures,
        next_attempt_at: next_attempt,
        last_failure_reason: prev_reason,
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
