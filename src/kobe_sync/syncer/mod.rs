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
pub mod service_accounts;
pub mod services;
pub mod status;

pub use traits::{ResourceSyncer, SyncerContext};
pub use translator::NameTranslator;

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Start all enabled syncer controllers.
///
/// Each string in `enabled` selects a syncer by name. Unknown names are logged
/// and skipped. The actual syncer implementations (PodSyncer, etc.) will be
/// registered here as they are added in Tasks 5-7.
///
/// Returns `JoinHandle`s for each spawned controller task.
pub fn start_syncers(
    ctx: Arc<SyncerContext>,
    enabled: &[String],
    shutdown: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for name in enabled {
        // Match syncer names to implementations.
        // Actual syncer structs (PodSyncer, etc.) will be added in Tasks 5-7.
        let syncer: Option<Box<dyn ResourceSyncer>> = match name.as_str() {
            "pods" => Some(Box::new(pods::PodSyncer)),
            "configmaps" => Some(Box::new(configmaps::ConfigMapSyncer)),
            "secrets" => Some(Box::new(secrets::SecretSyncer)),
            "services" => Some(Box::new(services::ServiceSyncer)),
            "endpoints" => Some(Box::new(endpoints::EndpointSyncer)),
            "ingresses" => Some(Box::new(ingresses::IngressSyncer)),
            "pvcs" => Some(Box::new(pvcs::PvcSyncer)),
            "network_policies" => Some(Box::new(network_policies::NetworkPolicySyncer)),
            "service_accounts" => Some(Box::new(service_accounts::ServiceAccountSyncer)),
            "fake_nodes" => Some(Box::new(fake_nodes::FakeNodeSyncer::new())),
            "status" => Some(Box::new(status::StatusSyncer)),
            other => {
                warn!(syncer = %other, "Unknown syncer name, skipping");
                None
            }
        };

        if let Some(s) = syncer {
            let syncer_name = s.name().to_string();
            info!(syncer = %syncer_name, "Starting syncer");
            let ctx = ctx.clone();
            let shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                s.run(ctx, shutdown).await;
                info!(syncer = %syncer_name, "syncer exited");
            }));
        }
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that start_syncers handles unknown syncer names gracefully
    /// (logs a warning and returns no handles).
    #[tokio::test]
    async fn start_syncers_unknown_names_returns_empty() {
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

        let ctx = Arc::new(SyncerContext {
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

        let handles = start_syncers(ctx, &enabled, shutdown);

        // No syncers are registered yet, so all names are unknown.
        assert!(handles.is_empty());
    }
}
