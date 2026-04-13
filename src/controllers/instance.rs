use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{ClusterInstance, ClusterInstancePhase, ClusterInstanceStatus, ClusterPool};

pub struct InstanceContext<B: ClusterBackend> {
    pub client: Client,
    #[allow(dead_code)]
    pub backend: B,
    pub namespace: String,
    pub factory: Option<BackendFactory>,
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
    shutdown: CancellationToken,
) {
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let ctx = Arc::new(InstanceContext {
        client: client.clone(),
        backend,
        namespace: namespace.to_string(),
        factory,
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
            let backend = backend_for_instance(&ctx, &profile)?;
            match backend
                .create(&name, &ns, &profile.spec.cluster, &profile.spec.addons)
                .await
            {
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
