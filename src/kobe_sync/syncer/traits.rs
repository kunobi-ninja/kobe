use std::sync::Arc;

use kube::Client;
use tokio_util::sync::CancellationToken;

use super::translator::NameTranslator;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Shared context for syncer controllers.
///
/// Syncer controllers have **two**
/// clients -- one pointed at the virtual kube-apiserver (where workloads are
/// watched) and one pointed at the host cluster (where translated resources
/// are created).
pub struct SyncerContext {
    /// kube client pointed at the virtual kube-apiserver (localhost).
    pub virtual_client: Client,
    /// kube client pointed at the host cluster (in-cluster).
    pub host_client: Client,
    /// Name/namespace translator.
    pub translator: Arc<NameTranslator>,
    /// The host namespace where translated resources live.
    pub host_namespace: String,
    /// Namespaces to skip when syncing (empty = sync all).
    pub skip_namespaces: Vec<String>,
}

/// Trait that all resource syncers implement.
///
/// Each syncer watches a specific resource kind on the virtual kube-apiserver
/// and creates/updates/deletes the corresponding translated resource on the
/// host cluster.
#[async_trait::async_trait]
pub trait ResourceSyncer: Send + Sync + 'static {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Run the syncer until the cancellation token fires.
    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify SyncerContext can be constructed.
    ///
    /// We cannot easily create real `kube::Client` instances without a running
    /// cluster, so we use `kube::Client::try_default()` in a way that will
    /// fail gracefully. Instead we test that the struct layout compiles and
    /// can be instantiated with the correct field types by using
    /// `Client::try_from` with a dummy kubeconfig.
    #[tokio::test]
    async fn syncer_context_compiles_and_can_be_constructed() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Build a minimal kubeconfig that points to a dummy server.
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
        let virtual_client = Client::try_from(config).expect("should create client from config");

        let config2 = kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default())
            .await
            .expect("kubeconfig should parse");
        let host_client = Client::try_from(config2).expect("should create client from config");

        let translator = Arc::new(NameTranslator::new("test-host-ns".to_string()));

        let ctx = SyncerContext {
            virtual_client,
            host_client,
            translator: translator.clone(),
            host_namespace: "test-host-ns".to_string(),
            skip_namespaces: vec![],
        };

        // Verify fields are accessible.
        assert_eq!(ctx.host_namespace, "test-host-ns");
        assert_eq!(ctx.translator.host_namespace(), "test-host-ns");
        assert!(ctx.skip_namespaces.is_empty());
    }

    /// Verify the ResourceSyncer trait can be implemented and used as a trait object.
    #[tokio::test]
    async fn resource_syncer_trait_object() {
        struct DummySyncer;

        #[async_trait::async_trait]
        impl ResourceSyncer for DummySyncer {
            fn name(&self) -> &str {
                "dummy"
            }

            async fn run(&self, _ctx: Arc<SyncerContext>, _shutdown: CancellationToken) {
                // no-op for testing
            }
        }

        let syncer: Box<dyn ResourceSyncer> = Box::new(DummySyncer);
        assert_eq!(syncer.name(), "dummy");
    }
}
