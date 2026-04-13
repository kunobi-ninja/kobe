use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{
    Addon, BackendConfig, BackendType, ClusterConfig, ClusterInstance, ClusterInstancePhase,
    ClusterInstanceStatus, ClusterPool, HealthCheckConfig, ReadinessGate, SnapshotConfig,
};
use crate::velero::VeleroCoordinator;

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
    let config = resolve_instance_config(&ctx.client, &instance, &ns).await?;
    let profile_name = instance.spec.pool_ref.as_ref().map(|r| r.name.clone());
    let owner = profile_name.as_deref().unwrap_or(name.as_str());

    match status.phase {
        ClusterInstancePhase::Creating if !status.provisioned => {
            info!(instance = %name, owner = %owner, "Provisioning backend resources");
            match provision_instance(&ctx, &config, &name, &ns).await {
                Ok(()) => {
                    patch_instance_status(
                        &instances_api,
                        &name,
                        ClusterInstanceStatus {
                            phase: ClusterInstancePhase::Creating,
                            provisioned: true,
                            lease_ref: status.lease_ref,
                            idle_since: status.idle_since,
                            state_since: Some(chrono::Utc::now().to_rfc3339()),
                            health_failures: status.health_failures,
                            spec_hash: status.spec_hash,
                        },
                    )
                    .await?;
                    Ok(Action::requeue(std::time::Duration::from_secs(5)))
                }
                Err(e) => {
                    warn!(instance = %name, error = %e, "Provisioning failed");
                    patch_instance_status(
                        &instances_api,
                        &name,
                        ClusterInstanceStatus {
                            phase: ClusterInstancePhase::Failed,
                            provisioned: false,
                            lease_ref: status.lease_ref,
                            idle_since: None,
                            state_since: Some(chrono::Utc::now().to_rfc3339()),
                            health_failures: status.health_failures,
                            spec_hash: status.spec_hash,
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
                patch_instance_status(
                    &instances_api,
                    &name,
                    ClusterInstanceStatus {
                        phase: ClusterInstancePhase::Ready,
                        provisioned: true,
                        lease_ref: status.lease_ref,
                        idle_since: Some(chrono::Utc::now().to_rfc3339()),
                        state_since: Some(chrono::Utc::now().to_rfc3339()),
                        health_failures: 0,
                        spec_hash: status.spec_hash,
                    },
                )
                .await?;
                Ok(Action::requeue(std::time::Duration::from_secs(30)))
            } else {
                Ok(Action::requeue(std::time::Duration::from_secs(5)))
            }
        }
        ClusterInstancePhase::Ready => {
            let next = evaluate_ready_instance(&ctx, &config, &name, &ns, &status).await?;
            Ok(next)
        }
        ClusterInstancePhase::Recycling => {
            info!(instance = %name, owner = %owner, "Deleting backend resources");
            match delete_instance_backend(&ctx, &config, &name, &ns).await {
                Ok(()) => {
                    instances_api.delete(&name, &Default::default()).await?;
                    Ok(Action::await_change())
                }
                Err(e) => {
                    warn!(instance = %name, error = %e, "Delete failed");
                    Ok(Action::requeue(std::time::Duration::from_secs(15)))
                }
            }
        }
        _ => Ok(Action::requeue(std::time::Duration::from_secs(30))),
    }
}

async fn resolve_instance_config(
    client: &Client,
    instance: &ClusterInstance,
    namespace: &str,
) -> Result<ResolvedInstanceConfig, InstanceError> {
    if let Some(pool_ref) = &instance.spec.pool_ref {
        let Some(profile) = get_profile(client, &pool_ref.name, namespace).await else {
            return Err(anyhow::anyhow!("Owning pool {} not found", pool_ref.name).into());
        };
        return Ok(ResolvedInstanceConfig {
            owner_name: profile.name_any(),
            backend: profile.spec.backend,
            cluster: profile.spec.cluster,
            addons: profile.spec.addons,
            health_check: profile.spec.health_check,
            readiness_gates: profile.spec.readiness_gates,
            snapshot: profile.spec.snapshot,
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

    Ok(ResolvedInstanceConfig {
        owner_name: instance.name_any(),
        backend,
        cluster,
        addons: instance.spec.addons.clone(),
        health_check: instance.spec.health_check.clone(),
        readiness_gates: instance.spec.readiness_gates.clone(),
        snapshot: instance.spec.snapshot.clone(),
    })
}

async fn provision_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
) -> Result<(), InstanceError> {
    let is_k3s = matches!(config.backend.backend_type, BackendType::K3s);

    if !is_k3s {
        if let (Some(velero), Some(snapshot)) = (&ctx.velero, &config.snapshot) {
            if snapshot.enabled {
                let generation = 1;
                if let Ok(Some(backup_name)) = velero
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
        }
    }

    create_instance_backend(ctx, config, name, namespace).await?;
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
                warn!(instance = %name, gate = ?gate, error = %e, "Readiness gate check failed");
                return Ok(false);
            }
        }
    }

    match check_instance_health(ctx, config, name, namespace).await {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
        Err(e) => {
            warn!(instance = %name, error = %e, "Health probe failed during readiness evaluation");
            Ok(false)
        }
    }
}

async fn evaluate_ready_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
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
                    name,
                    ClusterInstanceStatus {
                        phase: ClusterInstancePhase::Ready,
                        provisioned: status.provisioned,
                        lease_ref: status.lease_ref.clone(),
                        idle_since: status.idle_since.clone(),
                        state_since: status.state_since.clone(),
                        health_failures: 0,
                        spec_hash: status.spec_hash,
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
            let next_phase = if failures >= threshold {
                ClusterInstancePhase::Recycling
            } else {
                ClusterInstancePhase::Ready
            };
            let instances_api: Api<ClusterInstance> =
                Api::namespaced(ctx.client.clone(), namespace);
            patch_instance_status(
                &instances_api,
                name,
                ClusterInstanceStatus {
                    phase: next_phase,
                    provisioned: status.provisioned,
                    lease_ref: if failures >= threshold {
                        None
                    } else {
                        status.lease_ref.clone()
                    },
                    idle_since: if failures >= threshold {
                        None
                    } else {
                        status.idle_since.clone()
                    },
                    state_since: Some(chrono::Utc::now().to_rfc3339()),
                    health_failures: failures,
                    spec_hash: status.spec_hash,
                },
            )
            .await?;
            Ok(Action::requeue(std::time::Duration::from_secs(
                interval_secs.into(),
            )))
        }
        Err(e) => {
            warn!(instance = %name, error = %e, "Health probe errored for ready instance");
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
                crate::backend::K3sBackend::new(ctx.client.clone(), None, None),
            )),
            crate::crd::BackendType::K0s => Ok(crate::backend::BackendDispatch::K0s(
                crate::backend::K0sBackend::new(ctx.client.clone(), None, None),
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
                crate::backend::VkobeBackend::new(ctx.client.clone()),
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
            resources: None,
            health_check: config.health_check.clone(),
            readiness_gates: config.readiness_gates.clone(),
            scaling: None,
            diagnostics: None,
            snapshot: config.snapshot.clone(),
        },
        status: None,
    }
}

async fn create_instance_backend<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
) -> Result<(), anyhow::Error> {
    if ctx.factory.is_some() {
        let backend = backend_dispatch_for_config(ctx, config)?;
        backend
            .create(name, namespace, &config.cluster, &config.addons)
            .await
    } else {
        ctx.backend
            .create(name, namespace, &config.cluster, &config.addons)
            .await
    }
}

async fn delete_instance_backend<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    config: &ResolvedInstanceConfig,
    name: &str,
    namespace: &str,
) -> Result<(), anyhow::Error> {
    if ctx.factory.is_some() {
        let backend = backend_dispatch_for_config(ctx, config)?;
        backend.delete(name, namespace).await
    } else {
        ctx.backend.delete(name, namespace).await
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

async fn patch_instance_status(
    instances_api: &Api<ClusterInstance>,
    name: &str,
    status: ClusterInstanceStatus,
) -> Result<(), kube::Error> {
    let patch = serde_json::json!({ "status": status });
    instances_api
        .patch_status(
            name,
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
                    "namespace": "test-ns"
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
                    "healthFailures": health_failures
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
                    "namespace": "test-ns"
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
            .respond_with(ResponseTemplate::new(200).set_body_json(instance_api_response("standalone-4")))
            .mount(&server)
            .await;

        let action = reconcile_instance(instance, ctx).await.unwrap();

        assert_eq!(action, Action::await_change());
        assert_eq!(backend.call_count().delete, 1);
    }
}
