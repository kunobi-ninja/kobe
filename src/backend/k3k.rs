use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, ReadinessGate};

use super::{
    apply_addon_impl, check_readiness_gate_impl, check_virtual_health, read_kubeconfig_secret,
    virtual_client_from_kubeconfig, ClusterBackend,
};

/// k3k CRD group and version constants.
const K3K_API_VERSION: &str = "k3k.io/v1beta1";
const K3K_KIND: &str = "Cluster";

/// k3k Cluster CRD spec — matches the `k3k.io/v1beta1/Cluster` schema.
///
/// We define this manually rather than using `kube::CustomResource` derive
/// because we don't own the CRD and don't want to generate it — we only
/// need to create/read instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K3kClusterSpec {
    /// k3k mode: "shared" or "virtual"
    #[serde(default = "default_mode")]
    mode: String,

    /// Number of control plane servers.
    #[serde(default = "default_servers")]
    servers: i32,

    /// k3s version (e.g., "v1.31.3+k3s1").
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,

    /// Extra k3s server args.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    server_args: Vec<String>,

    /// Persistence configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    persistence: Option<K3kPersistence>,

    /// Expose configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    expose: Option<K3kExpose>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K3kPersistence {
    #[serde(rename = "type")]
    storage_type: String,
    storage_class_name: Option<String>,
    storage_request_size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K3kExpose {
    #[serde(rename = "type")]
    expose_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<K3kIngress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_port: Option<K3kNodePort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K3kIngress {
    ingress_class_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K3kNodePort {
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i32>,
}

fn default_mode() -> String {
    "shared".to_string()
}

fn default_servers() -> i32 {
    1
}

/// k3k backend — manages virtual clusters via `k3k.io/v1beta1/Cluster` CRDs.
///
/// All operations go through the Kubernetes API (kube-rs). No subprocesses,
/// no CLI tools, no Helm — just CRD CRUD operations.
#[derive(Clone)]
pub struct K3kBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
}

impl K3kBackend {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Build a kube Client that targets the virtual cluster's API server
    /// using the kubeconfig stored in the k3k Secret.
    async fn virtual_client(&self, name: &str, namespace: &str) -> Result<Client> {
        let kubeconfig_yaml = read_kubeconfig_secret(&self.client, name, namespace).await?;
        virtual_client_from_kubeconfig(&kubeconfig_yaml).await
    }

    /// Build the k3k Cluster CRD object from our ClusterConfig.
    fn build_cluster_object(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
    ) -> serde_json::Value {
        let persistence = config.persistence.as_ref().map(|p| K3kPersistence {
            storage_type: p
                .storage_type
                .clone()
                .unwrap_or_else(|| "emptyDir".to_string()),
            storage_class_name: p.storage_class_name.clone(),
            storage_request_size: p.storage_request_size.clone(),
        });

        let expose = config.expose.as_ref().map(|e| K3kExpose {
            expose_type: e.expose_type.clone(),
            ingress: e.ingress_class_name.as_ref().map(|class| K3kIngress {
                ingress_class_name: Some(class.clone()),
            }),
            node_port: e.node_port.map(|port| K3kNodePort { port: Some(port) }),
        });

        let spec = K3kClusterSpec {
            mode: config.mode.clone(),
            servers: i32::try_from(config.servers).unwrap_or(i32::MAX),
            version: Some(config.version.clone()),
            server_args: config.server_args.clone(),
            persistence,
            expose,
        };

        serde_json::json!({
            "apiVersion": K3K_API_VERSION,
            "kind": K3K_KIND,
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "kunobi-pool-operator"
                }
            },
            "spec": spec
        })
    }
}

impl ClusterBackend for K3kBackend {
    #[tracing::instrument(skip(self, config, addons), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        info!(cluster = name, "Creating k3k cluster");

        let cluster_obj = Self::build_cluster_object(name, namespace, config);

        let clusters: Api<kube::api::DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &kube::discovery::ApiResource {
                group: "k3k.io".into(),
                version: "v1beta1".into(),
                api_version: K3K_API_VERSION.into(),
                kind: K3K_KIND.into(),
                plural: "clusters".into(),
            },
        );

        let data: kube::api::DynamicObject = serde_json::from_value(cluster_obj)?;
        clusters
            .create(&PostParams::default(), &data)
            .await
            .with_context(|| format!("Failed to create k3k Cluster {name}"))?;

        info!(cluster = name, "k3k Cluster CRD created");

        // Wait for the cluster to become ready by polling the kubeconfig secret
        self.wait_ready(name, namespace).await?;

        // Apply addons after cluster is ready
        for addon in addons {
            self.apply_addon(name, namespace, addon).await?;
        }

        info!(cluster = name, "k3k cluster fully ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Deleting k3k cluster");

        let clusters: Api<kube::api::DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &kube::discovery::ApiResource {
                group: "k3k.io".into(),
                version: "v1beta1".into(),
                api_version: K3K_API_VERSION.into(),
                kind: K3K_KIND.into(),
                plural: "clusters".into(),
            },
        );

        match clusters.delete(name, &DeleteParams::default()).await {
            Ok(_) => {
                info!(cluster = name, "k3k cluster deleted");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                warn!(cluster = name, "k3k cluster already deleted");
            }
            Err(e) => {
                return Err(e).context(format!("Failed to delete k3k Cluster {name}"));
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        info!(cluster = name, "Extracting kubeconfig from k3k secret");
        read_kubeconfig_secret(&self.client, name, namespace).await
    }

    async fn check_readiness_gate(
        &self,
        name: &str,
        namespace: &str,
        gate: &ReadinessGate,
    ) -> Result<bool> {
        let vc_client = self.virtual_client(name, namespace).await?;
        check_readiness_gate_impl(&vc_client, gate).await
    }

    async fn apply_addon(&self, name: &str, namespace: &str, addon: &Addon) -> Result<()> {
        info!(
            cluster = name,
            addon = addon.name,
            "Applying addon via kube-rs SSA"
        );
        let vc_client = self.virtual_client(name, namespace).await?;
        apply_addon_impl(&vc_client, addon).await
    }
}

impl K3kBackend {
    /// Wait for a k3k cluster to become ready by polling for the kubeconfig secret.
    async fn wait_ready(&self, name: &str, namespace: &str) -> Result<()> {
        debug!(cluster = name, "Waiting for k3k cluster to become ready");

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        // Poll every 5s for up to 5 minutes
        for attempt in 0..60 {
            match secrets.get(&secret_name).await {
                Ok(_) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "k3k cluster kubeconfig secret found"
                    );
                    return Ok(());
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    if attempt % 6 == 0 {
                        debug!(
                            cluster = name,
                            attempt = attempt + 1,
                            "Waiting for k3k cluster kubeconfig..."
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    return Err(e).context(format!("Error checking k3k cluster {name} readiness"));
                }
            }
        }

        anyhow::bail!("k3k cluster {name} not ready after 5 minutes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ClusterConfig, ExposeConfig, PersistenceConfig};

    // -----------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------

    fn base_config() -> ClusterConfig {
        ClusterConfig {
            mode: "shared".to_string(),
            version: "v1.31.3+k3s1".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
        }
    }

    #[test]
    fn test_build_cluster_object_basic() {
        let config = ClusterConfig {
            mode: "shared".to_string(),
            version: "v1.31.3+k3s1".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
        };

        let obj = K3kBackend::build_cluster_object("pool-test-0", "kunobi-pool", &config);

        assert_eq!(obj["apiVersion"], K3K_API_VERSION);
        assert_eq!(obj["kind"], K3K_KIND);
        assert_eq!(obj["metadata"]["name"], "pool-test-0");
        assert_eq!(obj["metadata"]["namespace"], "kunobi-pool");
        assert_eq!(obj["spec"]["mode"], "shared");
        assert_eq!(obj["spec"]["servers"], 1);
        assert_eq!(obj["spec"]["version"], "v1.31.3+k3s1");
    }

    #[test]
    fn test_build_cluster_object_with_persistence() {
        let config = ClusterConfig {
            mode: "virtual".to_string(),
            version: "v1.31.3+k3s1".to_string(),
            servers: 3,
            agents: None,
            server_args: vec!["--disable=traefik".to_string()],
            persistence: Some(crate::crd::PersistenceConfig {
                storage_type: Some("dynamic".to_string()),
                storage_class_name: Some("local-path".to_string()),
                storage_request_size: Some("10Gi".to_string()),
            }),
            expose: None,
        };

        let obj = K3kBackend::build_cluster_object("pool-e2e-0", "kunobi-pool", &config);

        assert_eq!(obj["spec"]["servers"], 3);
        assert_eq!(obj["spec"]["serverArgs"][0], "--disable=traefik");
        assert_eq!(obj["spec"]["persistence"]["type"], "dynamic");
        assert_eq!(obj["spec"]["persistence"]["storageClassName"], "local-path");
    }

    // =================================================================
    // Pure function tests for build_cluster_object
    // =================================================================

    #[test]
    fn test_build_cluster_object_with_expose_nodeport() {
        let mut config = base_config();
        config.expose = Some(ExposeConfig {
            expose_type: "NodePort".to_string(),
            ingress_class_name: None,
            node_port: Some(31234),
        });

        let obj = K3kBackend::build_cluster_object("np-cluster", "ns", &config);

        assert_eq!(obj["spec"]["expose"]["type"], "NodePort");
        assert_eq!(obj["spec"]["expose"]["nodePort"]["port"], 31234);
        // No ingress section when expose is NodePort
        assert!(obj["spec"]["expose"]["ingress"].is_null());
    }

    #[test]
    fn test_build_cluster_object_with_expose_loadbalancer() {
        let mut config = base_config();
        config.expose = Some(ExposeConfig {
            expose_type: "LoadBalancer".to_string(),
            ingress_class_name: None,
            node_port: None,
        });

        let obj = K3kBackend::build_cluster_object("lb-cluster", "ns", &config);

        assert_eq!(obj["spec"]["expose"]["type"], "LoadBalancer");
        assert!(obj["spec"]["expose"]["ingress"].is_null());
        assert!(obj["spec"]["expose"]["nodePort"].is_null());
    }

    #[test]
    fn test_build_cluster_object_with_expose_ingress() {
        let mut config = base_config();
        config.expose = Some(ExposeConfig {
            expose_type: "ingress".to_string(),
            ingress_class_name: Some("nginx".to_string()),
            node_port: None,
        });

        let obj = K3kBackend::build_cluster_object("ing-cluster", "ns", &config);

        assert_eq!(obj["spec"]["expose"]["type"], "ingress");
        assert_eq!(
            obj["spec"]["expose"]["ingress"]["ingressClassName"],
            "nginx"
        );
        assert!(obj["spec"]["expose"]["nodePort"].is_null());
    }

    #[test]
    fn test_build_cluster_object_ephemeral_storage() {
        let mut config = base_config();
        // Persistence with no storage_type => defaults to "emptyDir"
        config.persistence = Some(PersistenceConfig {
            storage_type: None,
            storage_class_name: None,
            storage_request_size: None,
        });

        let obj = K3kBackend::build_cluster_object("eph-cluster", "ns", &config);

        assert_eq!(obj["spec"]["persistence"]["type"], "emptyDir");
        // No storageClassName or storageRequestSize when ephemeral
        assert!(obj["spec"]["persistence"]["storageClassName"].is_null());
        assert!(obj["spec"]["persistence"]["storageRequestSize"].is_null());
    }

    #[test]
    fn test_build_cluster_object_with_addons() {
        // build_cluster_object does not embed addons in the CRD object—
        // addons are applied separately after cluster creation.
        // Verify the object is well-formed regardless of addon presence.
        let config = base_config();
        let obj = K3kBackend::build_cluster_object("addon-cluster", "ns", &config);

        // The CRD object should always have apiVersion, kind, metadata, spec
        assert_eq!(obj["apiVersion"], K3K_API_VERSION);
        assert_eq!(obj["kind"], K3K_KIND);
        assert!(obj["metadata"].is_object());
        assert!(obj["spec"].is_object());
        assert_eq!(
            obj["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kunobi-pool-operator"
        );
    }

    #[test]
    fn test_build_cluster_object_default_mode() {
        // Default mode is "shared" per ClusterConfig defaults; verify that
        // build_cluster_object passes it through correctly.
        let config = base_config();
        let obj = K3kBackend::build_cluster_object("def-mode", "ns", &config);
        assert_eq!(obj["spec"]["mode"], "shared");
    }

    #[test]
    fn test_build_cluster_object_agent_count() {
        let mut config = base_config();
        config.servers = 5;

        let obj = K3kBackend::build_cluster_object("multi-server", "ns", &config);

        assert_eq!(obj["spec"]["servers"], 5);
    }

    // =================================================================
    // wiremock-based tests for K3kBackend trait methods
    // =================================================================

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a kube::Client backed by a wiremock MockServer.
    fn mock_client(server: &MockServer) -> kube::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    /// Build a K3k Cluster CRD JSON response for wiremock.
    fn k3k_cluster_json(name: &str, namespace: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": K3K_API_VERSION,
            "kind": K3K_KIND,
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "kunobi-pool-operator"
                }
            },
            "spec": {
                "mode": "shared",
                "servers": 1,
                "version": "v1.31.3+k3s1"
            }
        })
    }

    #[tokio::test]
    async fn test_create_cluster() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        // POST to create cluster returns 201
        Mock::given(method("POST"))
            .and(path("/apis/k3k.io/v1beta1/namespaces/test-ns/clusters"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(k3k_cluster_json("my-cluster", "test-ns")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // After creation, wait_ready polls for kubeconfig secret — return it immediately
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/my-cluster-kubeconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "my-cluster-kubeconfig",
                    "namespace": "test-ns"
                },
                "data": {
                    "kubeconfig": base64_encode("fake-kubeconfig-yaml")
                }
            })))
            .mount(&server)
            .await;

        let config = base_config();
        let result = backend.create("my-cluster", "test-ns", &config, &[]).await;
        assert!(result.is_ok(), "create should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        // DELETE returns 200
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/k3k.io/v1beta1/namespaces/test-ns/clusters/my-cluster",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(k3k_cluster_json("my-cluster", "test-ns")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.delete("my-cluster", "test-ns").await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster_not_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        // DELETE returns 404 — cluster already gone
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/k3k.io/v1beta1/namespaces/test-ns/clusters/gone-cluster",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("clusters", "gone-cluster")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // 404 on delete is treated as success (cluster already deleted)
        let result = backend.delete("gone-cluster", "test-ns").await;
        assert!(
            result.is_ok(),
            "delete of non-existent cluster should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_extract_kubeconfig() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        let kubeconfig_content = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: default\n";

        // GET the kubeconfig secret
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/my-cluster-kubeconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "my-cluster-kubeconfig",
                    "namespace": "test-ns"
                },
                "data": {
                    "kubeconfig": base64_encode(kubeconfig_content)
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.extract_kubeconfig("my-cluster", "test-ns").await;
        assert!(
            result.is_ok(),
            "extract_kubeconfig should succeed: {result:?}"
        );
        assert_eq!(result.unwrap(), kubeconfig_content);
    }

    #[tokio::test]
    async fn test_extract_kubeconfig_with_value_key() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        let kubeconfig_content = "apiVersion: v1\nkind: Config\n";

        // Some k3k versions store under "value" instead of "kubeconfig"
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/alt-cluster-kubeconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "alt-cluster-kubeconfig",
                    "namespace": "test-ns"
                },
                "data": {
                    "value": base64_encode(kubeconfig_content)
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.extract_kubeconfig("alt-cluster", "test-ns").await;
        assert!(
            result.is_ok(),
            "extract_kubeconfig should succeed with 'value' key: {result:?}"
        );
        assert_eq!(result.unwrap(), kubeconfig_content);
    }

    #[tokio::test]
    async fn test_check_health_secret_not_found_returns_false() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3kBackend::new(client);

        // GET returns 404 — kubeconfig secret doesn't exist yet
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/new-cluster-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "new-cluster-kubeconfig",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.check_health("new-cluster", "test-ns").await;
        assert!(result.is_ok(), "check_health should succeed: {result:?}");
        assert!(
            !result.unwrap(),
            "check_health should return false when kubeconfig secret is not found"
        );
    }

    // -----------------------------------------------------------------
    // Base64 helper for building Secret data
    // -----------------------------------------------------------------

    use base64::Engine as _;

    fn base64_encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }
}
