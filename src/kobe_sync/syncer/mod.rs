pub mod traits;
pub mod translator;

pub mod configmaps;
pub mod endpoints;
pub mod fake_nodes;
pub mod ingresses;
pub mod network_policies;
pub mod pods;
pub mod pvcs;
pub mod secrets;
pub mod services;
pub mod status;

pub use traits::{ResourceSyncer, SyncerContextV2};
pub use translator::NameTranslator;

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// v2 start function
// ---------------------------------------------------------------------------

/// Start all enabled v2 syncer controllers.
///
/// Each string in `enabled` selects a syncer by name. Unknown names are logged
/// and skipped. The actual syncer implementations (PodSyncerV2, etc.) will be
/// registered here as they are added in Tasks 5-7.
///
/// Returns `JoinHandle`s for each spawned controller task.
pub fn start_syncers_v2(
    ctx: Arc<SyncerContextV2>,
    enabled: &[String],
    shutdown: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for name in enabled {
        // Match syncer names to implementations.
        // Actual syncer structs (PodSyncerV2, etc.) will be added in Tasks 5-7.
        let syncer: Option<Box<dyn ResourceSyncer>> = match name.as_str() {
            "pods" => Some(Box::new(pods::PodSyncerV2)),
            "configmaps" => Some(Box::new(configmaps::ConfigMapSyncerV2)),
            "secrets" => Some(Box::new(secrets::SecretSyncerV2)),
            "services" => Some(Box::new(services::ServiceSyncerV2)),
            "endpoints" => Some(Box::new(endpoints::EndpointSyncerV2)),
            "ingresses" => Some(Box::new(ingresses::IngressSyncerV2)),
            "pvcs" => Some(Box::new(pvcs::PvcSyncerV2)),
            "network_policies" => Some(Box::new(network_policies::NetworkPolicySyncerV2)),
            "fake_nodes" => Some(Box::new(fake_nodes::FakeNodeSyncerV2::new())),
            "status" => Some(Box::new(status::StatusSyncerV2)),
            other => {
                warn!(syncer = %other, "Unknown v2 syncer name, skipping");
                None
            }
        };

        if let Some(s) = syncer {
            let syncer_name = s.name().to_string();
            info!(syncer = %syncer_name, "Starting v2 syncer");
            let ctx = ctx.clone();
            let shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                s.run(ctx, shutdown).await;
                info!(syncer = %syncer_name, "v2 syncer exited");
            }));
        }
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that start_syncers_v2 handles unknown syncer names gracefully
    /// (logs a warning and returns no handles).
    #[tokio::test]
    async fn start_syncers_v2_unknown_names_returns_empty() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Build a minimal kubeconfig for constructing dummy clients.
        let kubeconfig = kube::config::Kubeconfig {
            clusters: vec![kube::config::NamedCluster {
                name: "dummy".to_string(),
                cluster: Some(kube::config::Cluster {
                    server: Some("https://127.0.0.1:6443".to_string()),
                    ..Default::default()
                }),
            }],
            auth_infos: vec![kube::config::NamedAuthInfo {
                name: "dummy".to_string(),
                auth_info: Some(kube::config::AuthInfo {
                    token: Some("fake-token".into()),
                    ..Default::default()
                }),
            }],
            contexts: vec![kube::config::NamedContext {
                name: "dummy".to_string(),
                context: Some(kube::config::Context {
                    cluster: "dummy".to_string(),
                    user: Some("dummy".to_string()),
                    ..Default::default()
                }),
            }],
            current_context: Some("dummy".to_string()),
            ..Default::default()
        };

        let config = kube::Config::from_custom_kubeconfig(kubeconfig.clone(), &Default::default())
            .await
            .expect("kubeconfig should parse");
        let virtual_client = kube::Client::try_from(config).expect("should create client");

        let config2 = kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default())
            .await
            .expect("kubeconfig should parse");
        let host_client = kube::Client::try_from(config2).expect("should create client");

        let translator = Arc::new(NameTranslator::new("test-ns".to_string()));

        let ctx = Arc::new(SyncerContextV2 {
            virtual_client,
            host_client,
            translator,
            host_namespace: "test-ns".to_string(),
            skip_namespaces: vec![],
        });

        let shutdown = CancellationToken::new();
        let enabled = vec![
            "nonexistent_syncer".to_string(),
            "also_not_real".to_string(),
        ];

        let handles = start_syncers_v2(ctx, &enabled, shutdown);

        // No syncers are registered yet, so all names are unknown.
        assert!(handles.is_empty());
    }
}
