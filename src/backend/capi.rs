//! CAPI backend — creates clusters via Cluster API CRDs.
//!
//! This backend is provider-agnostic. It creates:
//! - A `cluster.x-k8s.io/v1beta1/Cluster` resource
//! - A provider-specific infrastructure resource (kind and apiVersion from CapiConfig)
//!
//! Any CAPI provider installed on the host cluster (vcluster, k0smotron, Kamaji,
//! Docker, AWS, etc.) will reconcile these resources and produce a kubeconfig Secret.

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, DeleteParams, DynamicObject, ObjectMeta, Patch, PatchParams, TypeMeta};
use kube::discovery::ApiResource;
use tracing::{debug, info, warn};

use crate::crd::{Addon, CapiConfig, ClusterConfig, ReadinessGate};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health,
    read_kubeconfig_secret, virtual_client_from_kubeconfig,
};

/// CAPI Cluster API group/version constants.
const CAPI_GROUP: &str = "cluster.x-k8s.io";
const CAPI_VERSION: &str = "v1beta1";
const CAPI_API_VERSION: &str = "cluster.x-k8s.io/v1beta1";
const CAPI_CLUSTER_KIND: &str = "Cluster";
const CAPI_CLUSTER_PLURAL: &str = "clusters";

/// Label applied to all operator-managed resources.
const MANAGED_BY: &str = "kobe-operator";

/// CAPI backend — manages virtual clusters via Cluster API CRDs.
///
/// This backend creates two resources per cluster:
/// 1. A `cluster.x-k8s.io/v1beta1/Cluster` with an `infrastructureRef`
/// 2. A provider-specific infrastructure resource (e.g., VCluster, K0smotronCluster)
///
/// The CAPI provider controller reconciles these resources and produces a
/// `{name}-kubeconfig` Secret following CAPI conventions.
#[derive(Clone)]
pub struct CapiBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
    /// CAPI configuration specifying the infrastructure provider.
    capi_config: CapiConfig,
}

impl CapiBackend {
    pub fn new(client: Client, capi_config: CapiConfig) -> Self {
        Self {
            client,
            capi_config,
        }
    }

    /// Build a `kube::Client` targeting the virtual cluster's API server
    /// using the kubeconfig stored in the CAPI-managed Secret.
    async fn virtual_client(&self, name: &str, namespace: &str) -> Result<Client> {
        let kubeconfig_yaml = read_kubeconfig_secret(&self.client, name, namespace).await?;
        virtual_client_from_kubeconfig(&kubeconfig_yaml).await
    }

    /// Build the CAPI `Cluster` DynamicObject.
    ///
    /// Creates a `cluster.x-k8s.io/v1beta1/Cluster` resource with an
    /// `infrastructureRef` pointing to the provider-specific infrastructure resource.
    pub fn build_cluster_object(name: &str, namespace: &str, capi: &CapiConfig) -> DynamicObject {
        let data = serde_json::json!({
            "spec": {
                "infrastructureRef": {
                    "apiVersion": capi.infrastructure_api_version,
                    "kind": capi.infrastructure_kind,
                    "name": name,
                    "namespace": namespace,
                }
            }
        });

        DynamicObject {
            types: Some(TypeMeta {
                api_version: CAPI_API_VERSION.to_string(),
                kind: CAPI_CLUSTER_KIND.to_string(),
            }),
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(
                    [(
                        "app.kubernetes.io/managed-by".to_string(),
                        MANAGED_BY.to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            data,
        }
    }

    /// Build the provider-specific infrastructure DynamicObject.
    ///
    /// Creates an infrastructure resource (e.g., VCluster, K0smotronCluster)
    /// with the apiVersion, kind, and spec from the CapiConfig.
    pub fn build_infrastructure_object(
        name: &str,
        namespace: &str,
        capi: &CapiConfig,
    ) -> DynamicObject {
        let data = if let Some(spec) = &capi.infrastructure_spec {
            serde_json::json!({ "spec": spec })
        } else {
            serde_json::json!({ "spec": {} })
        };

        DynamicObject {
            types: Some(TypeMeta {
                api_version: capi.infrastructure_api_version.clone(),
                kind: capi.infrastructure_kind.clone(),
            }),
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(
                    [(
                        "app.kubernetes.io/managed-by".to_string(),
                        MANAGED_BY.to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            data,
        }
    }

    /// Return the `ApiResource` descriptor for `cluster.x-k8s.io/v1beta1/Cluster`.
    fn cluster_api_resource() -> ApiResource {
        ApiResource {
            group: CAPI_GROUP.into(),
            version: CAPI_VERSION.into(),
            api_version: CAPI_API_VERSION.into(),
            kind: CAPI_CLUSTER_KIND.into(),
            plural: CAPI_CLUSTER_PLURAL.into(),
        }
    }

    /// Return the `ApiResource` descriptor for the provider-specific infrastructure CRD.
    ///
    /// Parses the apiVersion from the CapiConfig to extract group and version,
    /// and derives the plural form by lowercasing the kind and appending "s".
    fn infra_api_resource(capi: &CapiConfig) -> ApiResource {
        let (group, version) = parse_api_version(&capi.infrastructure_api_version);
        let plural = capi
            .infrastructure_plural
            .clone()
            .unwrap_or_else(|| pluralize_kind(&capi.infrastructure_kind));

        ApiResource {
            group: group.into(),
            version: version.into(),
            api_version: capi.infrastructure_api_version.clone(),
            kind: capi.infrastructure_kind.clone(),
            plural,
        }
    }

    /// Wait for the CAPI-managed kubeconfig Secret to appear.
    ///
    /// CAPI convention: the kubeconfig is stored in a Secret named `{name}-kubeconfig`.
    async fn wait_ready(&self, name: &str, namespace: &str) -> Result<()> {
        debug!(cluster = name, "Waiting for CAPI cluster to become ready");

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        // Poll every 5s for up to 5 minutes.
        for attempt in 0..60 {
            match secrets.get(&secret_name).await {
                Ok(_) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "CAPI cluster kubeconfig secret found"
                    );
                    return Ok(());
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    if attempt % 6 == 0 {
                        debug!(
                            cluster = name,
                            attempt = attempt + 1,
                            "Waiting for CAPI cluster kubeconfig..."
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    return Err(e).context(format!("Error checking CAPI cluster {name} readiness"));
                }
            }
        }

        anyhow::bail!("CAPI cluster {name} not ready after 5 minutes");
    }
}

impl ClusterBackend for CapiBackend {
    #[tracing::instrument(skip(self, config, addons), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        info!(
            cluster = name,
            infra_kind = self.capi_config.infrastructure_kind,
            "Creating CAPI cluster"
        );

        let _ = config; // CAPI does not use ClusterConfig — configuration is in CapiConfig.

        // 1. Create the infrastructure resource first.
        let infra_obj = Self::build_infrastructure_object(name, namespace, &self.capi_config);
        let infra_ar = Self::infra_api_resource(&self.capi_config);
        let infra_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &infra_ar);

        infra_api
            .patch(
                name,
                &PatchParams::apply(MANAGED_BY),
                &Patch::Apply(&infra_obj),
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to create CAPI infrastructure resource {}/{}",
                    self.capi_config.infrastructure_kind, name
                )
            })?;

        info!(
            cluster = name,
            kind = self.capi_config.infrastructure_kind,
            "CAPI infrastructure resource created"
        );

        // 2. Create the Cluster resource with infrastructureRef.
        let cluster_obj = Self::build_cluster_object(name, namespace, &self.capi_config);
        let cluster_ar = Self::cluster_api_resource();
        let cluster_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &cluster_ar);

        cluster_api
            .patch(
                name,
                &PatchParams::apply(MANAGED_BY),
                &Patch::Apply(&cluster_obj),
            )
            .await
            .with_context(|| format!("Failed to create CAPI Cluster {name}"))?;

        info!(cluster = name, "CAPI Cluster resource created");

        // 3. Wait for the kubeconfig Secret (CAPI convention: {name}-kubeconfig).
        self.wait_ready(name, namespace).await?;

        // 4. Apply addons after cluster is ready.
        for addon in addons {
            self.apply_addon(name, namespace, addon).await?;
        }

        info!(cluster = name, "CAPI cluster fully ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Deleting CAPI cluster");

        // Delete the Cluster resource — CAPI cascades to infrastructure.
        let cluster_ar = Self::cluster_api_resource();
        let cluster_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &cluster_ar);

        match cluster_api.delete(name, &DeleteParams::default()).await {
            Ok(_) => {
                info!(cluster = name, "CAPI Cluster deleted");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                warn!(cluster = name, "CAPI Cluster already deleted");
            }
            Err(e) => {
                return Err(e).context(format!("Failed to delete CAPI Cluster {name}"));
            }
        }

        // Also delete the infrastructure resource in case cascade didn't clean it up.
        let infra_ar = Self::infra_api_resource(&self.capi_config);
        let infra_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &infra_ar);

        match infra_api.delete(name, &DeleteParams::default()).await {
            Ok(_) => {
                debug!(cluster = name, "CAPI infrastructure resource deleted");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(
                    cluster = name,
                    "CAPI infrastructure resource already deleted (expected via cascade)"
                );
            }
            Err(e) => {
                warn!(
                    cluster = name,
                    error = %e,
                    "Failed to delete CAPI infrastructure resource"
                );
            }
        }

        // Clean up the kubeconfig Secret.
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");
        match secrets.delete(&secret_name, &DeleteParams::default()).await {
            Ok(_) => {
                debug!(cluster = name, "Kubeconfig secret deleted");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = name, "Kubeconfig secret already deleted");
            }
            Err(e) => {
                warn!(
                    cluster = name,
                    error = %e,
                    "Failed to delete kubeconfig secret"
                );
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        info!(cluster = name, "Extracting kubeconfig from CAPI secret");
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

/// Parse an apiVersion string like "infrastructure.cluster.x-k8s.io/v1alpha1"
/// into (group, version) = ("infrastructure.cluster.x-k8s.io", "v1alpha1").
///
/// For core API group (no slash), returns ("", apiVersion).
fn parse_api_version(api_version: &str) -> (&str, &str) {
    match api_version.rsplit_once('/') {
        Some((group, version)) => (group, version),
        None => ("", api_version),
    }
}

/// Derive a plural resource name from a CRD kind.
///
/// Uses a simple lowercasing + "s" suffix heuristic, which covers most CAPI
/// provider conventions (VCluster -> vclusters, K0smotronCluster -> k0smotronclusters).
fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with('s') {
        lower
    } else {
        format!("{lower}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_capi_config() -> CapiConfig {
        CapiConfig {
            infrastructure_api_version: "infrastructure.cluster.x-k8s.io/v1alpha1".to_string(),
            infrastructure_kind: "VCluster".to_string(),
            infrastructure_spec: Some(serde_json::json!({
                "helmRelease": {
                    "chart": { "version": "0.24.1" }
                }
            })),
            infrastructure_plural: None,
        }
    }

    // =================================================================
    // Pure function tests for resource builders
    // =================================================================

    #[test]
    fn test_build_cluster_object() {
        let capi = base_capi_config();
        let obj = CapiBackend::build_cluster_object("my-vc", "ns", &capi);
        let types = obj.types.as_ref().unwrap();
        assert_eq!(types.api_version, "cluster.x-k8s.io/v1beta1");
        assert_eq!(types.kind, "Cluster");
        assert_eq!(obj.metadata.name.as_deref(), Some("my-vc"));
        assert_eq!(obj.metadata.namespace.as_deref(), Some("ns"));

        // Check managed-by label
        let labels = obj.metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by").unwrap(),
            MANAGED_BY
        );

        // Check infrastructureRef is set
        let spec = obj.data.get("spec").unwrap();
        let infra_ref = spec.get("infrastructureRef").unwrap();
        assert_eq!(infra_ref["kind"], "VCluster");
        assert_eq!(
            infra_ref["apiVersion"],
            "infrastructure.cluster.x-k8s.io/v1alpha1"
        );
        assert_eq!(infra_ref["name"], "my-vc");
        assert_eq!(infra_ref["namespace"], "ns");
    }

    #[test]
    fn test_build_infrastructure_object() {
        let capi = base_capi_config();
        let obj = CapiBackend::build_infrastructure_object("my-vc", "ns", &capi);
        let types = obj.types.as_ref().unwrap();
        assert_eq!(
            types.api_version,
            "infrastructure.cluster.x-k8s.io/v1alpha1"
        );
        assert_eq!(types.kind, "VCluster");
        assert_eq!(obj.metadata.name.as_deref(), Some("my-vc"));
        assert_eq!(obj.metadata.namespace.as_deref(), Some("ns"));

        // Check spec is embedded from CapiConfig
        let spec = obj.data.get("spec").unwrap();
        assert!(spec.get("helmRelease").is_some());
        assert_eq!(spec["helmRelease"]["chart"]["version"], "0.24.1");
    }

    #[test]
    fn test_build_infrastructure_object_no_spec() {
        let capi = CapiConfig {
            infrastructure_api_version: "infrastructure.cluster.x-k8s.io/v1alpha1".to_string(),
            infrastructure_kind: "VCluster".to_string(),
            infrastructure_spec: None,
            infrastructure_plural: None,
        };
        let obj = CapiBackend::build_infrastructure_object("my-vc", "ns", &capi);

        // spec should be an empty object
        let spec = obj.data.get("spec").unwrap();
        assert!(spec.is_object());
        assert_eq!(spec.as_object().unwrap().len(), 0);
    }

    #[test]
    fn test_build_cluster_object_different_provider() {
        let capi = CapiConfig {
            infrastructure_api_version: "controlplane.cluster.x-k8s.io/v1beta1".to_string(),
            infrastructure_kind: "K0smotronCluster".to_string(),
            infrastructure_spec: Some(serde_json::json!({
                "version": "v1.30.1+k0s.0"
            })),
            infrastructure_plural: None,
        };
        let obj = CapiBackend::build_cluster_object("my-k0s", "ns", &capi);
        let spec = obj.data.get("spec").unwrap();
        let infra_ref = spec.get("infrastructureRef").unwrap();
        assert_eq!(infra_ref["kind"], "K0smotronCluster");
        assert_eq!(
            infra_ref["apiVersion"],
            "controlplane.cluster.x-k8s.io/v1beta1"
        );
    }

    // =================================================================
    // ApiResource helper tests
    // =================================================================

    #[test]
    fn test_cluster_api_resource() {
        let ar = CapiBackend::cluster_api_resource();
        assert_eq!(ar.group, "cluster.x-k8s.io");
        assert_eq!(ar.version, "v1beta1");
        assert_eq!(ar.api_version, "cluster.x-k8s.io/v1beta1");
        assert_eq!(ar.kind, "Cluster");
        assert_eq!(ar.plural, "clusters");
    }

    #[test]
    fn test_infra_api_resource() {
        let capi = base_capi_config();
        let ar = CapiBackend::infra_api_resource(&capi);
        assert_eq!(ar.group, "infrastructure.cluster.x-k8s.io");
        assert_eq!(ar.version, "v1alpha1");
        assert_eq!(ar.api_version, "infrastructure.cluster.x-k8s.io/v1alpha1");
        assert_eq!(ar.kind, "VCluster");
        assert_eq!(ar.plural, "vclusters");
    }

    // =================================================================
    // Utility function tests
    // =================================================================

    #[test]
    fn test_parse_api_version_with_group() {
        let (group, version) = parse_api_version("infrastructure.cluster.x-k8s.io/v1alpha1");
        assert_eq!(group, "infrastructure.cluster.x-k8s.io");
        assert_eq!(version, "v1alpha1");
    }

    #[test]
    fn test_parse_api_version_core() {
        let (group, version) = parse_api_version("v1");
        assert_eq!(group, "");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_pluralize_kind_vcluster() {
        assert_eq!(pluralize_kind("VCluster"), "vclusters");
    }

    #[test]
    fn test_pluralize_kind_already_plural() {
        assert_eq!(pluralize_kind("Ingress"), "ingress");
    }

    #[test]
    fn test_pluralize_kind_k0smotron() {
        assert_eq!(pluralize_kind("K0smotronCluster"), "k0smotronclusters");
    }

    // =================================================================
    // wiremock-based tests for CapiBackend trait methods
    // =================================================================

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_client(server: &MockServer) -> kube::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    #[tokio::test]
    async fn test_create_cluster() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = CapiBackend::new(client, base_capi_config());

        // PATCH infrastructure resource (server-side apply)
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/infrastructure.cluster.x-k8s.io/v1alpha1/namespaces/test-ns/vclusters/my-vc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "infrastructure.cluster.x-k8s.io/v1alpha1",
                "kind": "VCluster",
                "metadata": { "name": "my-vc", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // PATCH Cluster resource (server-side apply)
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/cluster.x-k8s.io/v1beta1/namespaces/test-ns/clusters/my-vc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "cluster.x-k8s.io/v1beta1",
                "kind": "Cluster",
                "metadata": { "name": "my-vc", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // GET kubeconfig secret — available immediately
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/secrets/my-vc-kubeconfig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "my-vc-kubeconfig", "namespace": "test-ns" },
                "data": {
                    "kubeconfig": base64_encode("fake-kubeconfig")
                }
            })))
            .mount(&server)
            .await;

        let config = ClusterConfig {
            version: "v1.31.3+k3s1".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
        };

        let result = backend.create("my-vc", "test-ns", &config, &[]).await;
        assert!(result.is_ok(), "create should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = CapiBackend::new(client, base_capi_config());

        // DELETE Cluster
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/cluster.x-k8s.io/v1beta1/namespaces/test-ns/clusters/my-vc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "cluster.x-k8s.io/v1beta1",
                "kind": "Cluster",
                "metadata": { "name": "my-vc", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // DELETE infrastructure resource
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/infrastructure.cluster.x-k8s.io/v1alpha1/namespaces/test-ns/vclusters/my-vc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "infrastructure.cluster.x-k8s.io/v1alpha1",
                "kind": "VCluster",
                "metadata": { "name": "my-vc", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // DELETE kubeconfig secret
        Mock::given(method("DELETE"))
            .and(path("/api/v1/namespaces/test-ns/secrets/my-vc-kubeconfig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "my-vc-kubeconfig", "namespace": "test-ns" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.delete("my-vc", "test-ns").await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster_not_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = CapiBackend::new(client, base_capi_config());

        // DELETE Cluster returns 404
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/cluster.x-k8s.io/v1beta1/namespaces/test-ns/clusters/gone",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("clusters", "gone")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // DELETE infrastructure resource returns 404
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/infrastructure.cluster.x-k8s.io/v1alpha1/namespaces/test-ns/vclusters/gone",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("vclusters", "gone")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // DELETE kubeconfig secret returns 404
        Mock::given(method("DELETE"))
            .and(path("/api/v1/namespaces/test-ns/secrets/gone-kubeconfig"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("secrets", "gone-kubeconfig")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // 404 on delete is treated as success
        let result = backend.delete("gone", "test-ns").await;
        assert!(
            result.is_ok(),
            "delete of non-existent cluster should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_check_health_secret_not_found_returns_false() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = CapiBackend::new(client, base_capi_config());

        // GET returns 404 — kubeconfig secret doesn't exist yet
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/secrets/new-vc-kubeconfig"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "new-vc-kubeconfig",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.check_health("new-vc", "test-ns").await;
        assert!(result.is_ok(), "check_health should succeed: {result:?}");
        assert!(
            !result.unwrap(),
            "check_health should return false when kubeconfig secret is not found"
        );
    }

    #[tokio::test]
    async fn test_extract_kubeconfig() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = CapiBackend::new(client, base_capi_config());

        let kubeconfig_content = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: default\n";

        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/secrets/my-vc-kubeconfig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "my-vc-kubeconfig", "namespace": "test-ns" },
                "data": {
                    "kubeconfig": base64_encode(kubeconfig_content)
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = backend.extract_kubeconfig("my-vc", "test-ns").await;
        assert!(
            result.is_ok(),
            "extract_kubeconfig should succeed: {result:?}"
        );
        assert_eq!(result.unwrap(), kubeconfig_content);
    }

    // -----------------------------------------------------------------
    // Base64 helper for building Secret data
    // -----------------------------------------------------------------

    use base64::Engine as _;

    fn base64_encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }
}
