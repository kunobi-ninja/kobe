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
    BackendType, ClusterInstance, ClusterInstancePhase, ClusterInstanceStatus, ClusterPool,
};
use crate::velero::VeleroCoordinator;

pub struct InstanceContext<B: ClusterBackend> {
    pub client: Client,
    pub _backend: B,
    pub namespace: String,
    pub factory: Option<BackendFactory>,
    pub velero: Option<VeleroCoordinator>,
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
        _backend: backend,
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
    let ns = instance.namespace().unwrap_or_else(|| ctx.namespace.clone());
    let status = instance.status.clone().unwrap_or_default();
    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);

    let Some(profile_name) = instance.spec.pool_ref.as_ref().map(|r| r.name.clone()) else {
        warn!(instance = %name, "Standalone ClusterInstance lifecycle is not implemented yet");
        return Ok(Action::await_change());
    };

    let Some(profile) = get_profile(&ctx.client, &profile_name, &ns).await else {
        warn!(instance = %name, pool = %profile_name, "Owning pool not found");
        return Ok(Action::requeue(std::time::Duration::from_secs(10)));
    };

    match status.phase {
        ClusterInstancePhase::Creating if !status.provisioned => {
            info!(instance = %name, pool = %profile_name, "Provisioning backend resources");
            match provision_instance(&ctx, &profile, &name, &ns).await {
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
            let ready = evaluate_instance_readiness(&ctx, &profile, &name, &ns).await?;
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
            let next = evaluate_ready_instance(&ctx, &profile, &name, &ns, &status).await?;
            Ok(next)
        }
        ClusterInstancePhase::Recycling => {
            info!(instance = %name, pool = %profile_name, "Deleting backend resources");
            let backend = backend_for_instance(&ctx, &profile)?;
            match backend.delete(&name, &ns).await {
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

async fn provision_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    profile: &ClusterPool,
    name: &str,
    namespace: &str,
) -> Result<(), InstanceError> {
    let backend = backend_for_instance(ctx, profile)?;
    let is_k3s = matches!(profile.spec.backend.backend_type, BackendType::K3s);

    if !is_k3s {
        if let (Some(velero), Some(snapshot)) = (&ctx.velero, &profile.spec.snapshot) {
            if snapshot.enabled {
                let generation = profile.metadata.generation.unwrap_or(1);
                if let Ok(Some(backup_name)) = velero
                    .get_golden_backup(&profile.name_any(), snapshot, generation)
                    .await
                {
                    info!(
                        instance = %name,
                        pool = %profile.name_any(),
                        backup = %backup_name,
                        "Restoring instance from golden backup"
                    );
                    if velero
                        .restore_from_golden(&backup_name, snapshot, &profile.name_any(), namespace)
                        .await
                        .is_ok()
                    {
                        crate::metrics::PROVISION_METHOD
                            .with_label_values(&[profile.name_any().as_str(), "restore"])
                            .inc();
                        return Ok(());
                    }
                    warn!(instance = %name, backup = %backup_name, "Golden restore failed, falling back to fresh create");
                }
            }
        }
    }

    backend
        .create(name, namespace, &profile.spec.cluster, &profile.spec.addons)
        .await?;
    crate::metrics::PROVISION_METHOD
        .with_label_values(&[profile.name_any().as_str(), "fresh"])
        .inc();
    Ok(())
}

async fn evaluate_instance_readiness<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    profile: &ClusterPool,
    name: &str,
    namespace: &str,
) -> Result<bool, InstanceError> {
    let backend = backend_for_instance(ctx, profile)?;
    for gate in &profile.spec.readiness_gates {
        match backend.check_readiness_gate(name, namespace, gate).await {
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

    match backend.check_health(name, namespace).await {
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
    profile: &ClusterPool,
    name: &str,
    namespace: &str,
    status: &ClusterInstanceStatus,
) -> Result<Action, InstanceError> {
    let backend = backend_for_instance(ctx, profile)?;
    let (interval_secs, threshold) = profile
        .spec
        .health_check
        .as_ref()
        .map(|hc| (hc.interval_seconds, hc.failure_threshold))
        .unwrap_or((30, 3));

    match backend.check_health(name, namespace).await {
        Ok(true) => {
            if status.health_failures != 0 {
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), namespace);
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
            Ok(Action::requeue(std::time::Duration::from_secs(interval_secs.into())))
        }
        Ok(false) => {
            let failures = status.health_failures + 1;
            let next_phase = if failures >= threshold {
                ClusterInstancePhase::Recycling
            } else {
                ClusterInstancePhase::Ready
            };
            let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), namespace);
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
            Ok(Action::requeue(std::time::Duration::from_secs(interval_secs.into())))
        }
        Err(e) => {
            warn!(instance = %name, error = %e, "Health probe errored for ready instance");
            Ok(Action::requeue(std::time::Duration::from_secs(interval_secs.into())))
        }
    }
}

fn backend_for_instance<B: ClusterBackend + Clone>(
    ctx: &InstanceContext<B>,
    profile: &ClusterPool,
) -> Result<crate::backend::BackendDispatch, InstanceError> {
    if let Some(factory) = &ctx.factory {
        Ok(factory.backend_for(profile)?)
    } else {
        match profile.spec.backend.backend_type {
            crate::crd::BackendType::K3s => Ok(crate::backend::BackendDispatch::K3s(
                crate::backend::K3sBackend::new(ctx.client.clone(), None, None),
            )),
            crate::crd::BackendType::K0s => Ok(crate::backend::BackendDispatch::K0s(
                crate::backend::K0sBackend::new(ctx.client.clone(), None, None),
            )),
            crate::crd::BackendType::Capi => {
                let capi = profile
                    .spec
                    .backend
                    .capi
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Pool missing capi backend config"))?;
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
