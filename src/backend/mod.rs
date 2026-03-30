pub mod capi;
pub mod datastore;
pub mod k0s;
pub mod k3s;
pub mod vkobe;

use std::net::{IpAddr, ToSocketAddrs};

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, Config, ResourceExt};
use tracing::{debug, info, warn};

use crate::crd::{Addon, BackendType, ClusterConfig, ClusterPool, ReadinessGate};

pub use capi::CapiBackend;
pub use k0s::K0sBackend;
pub use k3s::K3sBackend;
pub use vkobe::VkobeBackend;

/// Allowed URL schemes for addon manifests and readiness probes.
const ALLOWED_SCHEMES: &[&str] = &["https"];

// ---------------------------------------------------------------------------
// BackendDispatch — enum dispatch for ClusterBackend implementations
// ---------------------------------------------------------------------------

/// Runtime dispatch wrapper for different backend implementations.
///
/// The `ClusterBackend` trait uses RPITIT (return-position impl Trait in trait),
/// which is not object-safe. This enum provides dispatch without `dyn`.
#[derive(Clone)]
pub enum BackendDispatch {
    K3s(K3sBackend),
    K0s(K0sBackend),
    Capi(CapiBackend),
    Vkobe(VkobeBackend),
}

impl ClusterBackend for BackendDispatch {
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        match self {
            Self::K3s(b) => b.create(name, namespace, config, addons).await,
            Self::K0s(b) => b.create(name, namespace, config, addons).await,
            Self::Capi(b) => b.create(name, namespace, config, addons).await,
            Self::Vkobe(b) => b.create(name, namespace, config, addons).await,
        }
    }

    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        match self {
            Self::K3s(b) => b.delete(name, namespace).await,
            Self::K0s(b) => b.delete(name, namespace).await,
            Self::Capi(b) => b.delete(name, namespace).await,
            Self::Vkobe(b) => b.delete(name, namespace).await,
        }
    }

    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        match self {
            Self::K3s(b) => b.check_health(name, namespace).await,
            Self::K0s(b) => b.check_health(name, namespace).await,
            Self::Capi(b) => b.check_health(name, namespace).await,
            Self::Vkobe(b) => b.check_health(name, namespace).await,
        }
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        match self {
            Self::K3s(b) => b.extract_kubeconfig(name, namespace).await,
            Self::K0s(b) => b.extract_kubeconfig(name, namespace).await,
            Self::Capi(b) => b.extract_kubeconfig(name, namespace).await,
            Self::Vkobe(b) => b.extract_kubeconfig(name, namespace).await,
        }
    }

    async fn check_readiness_gate(
        &self,
        name: &str,
        namespace: &str,
        gate: &ReadinessGate,
    ) -> Result<bool> {
        match self {
            Self::K3s(b) => b.check_readiness_gate(name, namespace, gate).await,
            Self::K0s(b) => b.check_readiness_gate(name, namespace, gate).await,
            Self::Capi(b) => b.check_readiness_gate(name, namespace, gate).await,
            Self::Vkobe(b) => b.check_readiness_gate(name, namespace, gate).await,
        }
    }

    async fn apply_addon(&self, name: &str, namespace: &str, addon: &Addon) -> Result<()> {
        match self {
            Self::K3s(b) => b.apply_addon(name, namespace, addon).await,
            Self::K0s(b) => b.apply_addon(name, namespace, addon).await,
            Self::Capi(b) => b.apply_addon(name, namespace, addon).await,
            Self::Vkobe(b) => b.apply_addon(name, namespace, addon).await,
        }
    }
}

// ---------------------------------------------------------------------------
// BackendFactory — produces the right backend per profile
// ---------------------------------------------------------------------------

/// Factory that produces the appropriate `BackendDispatch` for a given profile.
///
/// Controllers hold a `BackendFactory` instead of a single backend. When
/// handling a pool action, they call `factory.backend_for(&profile)` to get
/// the backend matching that profile's `spec.backend` field.
#[derive(Clone)]
pub struct BackendFactory {
    client: Client,
    pg_pool: Option<sqlx::PgPool>,
    pg_base_url: Option<String>,
}

impl BackendFactory {
    pub fn new(client: Client, pg_pool: Option<sqlx::PgPool>, pg_base_url: Option<String>) -> Self {
        Self {
            client,
            pg_pool,
            pg_base_url,
        }
    }

    /// Produce the right backend for a pool based on its `spec.backend.backend_type`.
    pub fn backend_for(&self, profile: &ClusterPool) -> Result<BackendDispatch> {
        match profile.spec.backend.backend_type {
            BackendType::K3s => Ok(BackendDispatch::K3s(K3sBackend::new(
                self.client.clone(),
                self.pg_pool.clone(),
                self.pg_base_url.clone(),
            ))),
            BackendType::K0s => Ok(BackendDispatch::K0s(K0sBackend::new(
                self.client.clone(),
                self.pg_pool.clone(),
                self.pg_base_url.clone(),
            ))),
            BackendType::Capi => {
                let capi_config = profile.spec.backend.capi.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Pool {} has backend type=capi but no capi config",
                        profile.metadata.name.as_deref().unwrap_or("unknown")
                    )
                })?;
                Ok(BackendDispatch::Capi(CapiBackend::new(
                    self.client.clone(),
                    capi_config,
                )))
            }
            BackendType::Vkobe => Ok(BackendDispatch::Vkobe(VkobeBackend::new(
                self.client.clone(),
            ))),
        }
    }

    /// Get the underlying Kubernetes client.
    #[allow(dead_code)]
    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Backend-agnostic interface for managing virtual cluster lifecycles.
///
/// Implementations handle the actual cluster provisioning. The profile and
/// claim controllers interact only through this trait, keeping them decoupled
/// from the underlying technology.
pub trait ClusterBackend: Send + Sync {
    /// Create a virtual cluster with the given name and config.
    fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Delete a virtual cluster.
    fn delete(
        &self,
        name: &str,
        namespace: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Check if a virtual cluster's API server is healthy.
    fn check_health(
        &self,
        name: &str,
        namespace: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    /// Extract a kubeconfig for connecting to the virtual cluster.
    fn extract_kubeconfig(
        &self,
        name: &str,
        namespace: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Check a readiness gate against the virtual cluster.
    fn check_readiness_gate(
        &self,
        name: &str,
        namespace: &str,
        gate: &ReadinessGate,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    /// Apply an addon manifest inside the virtual cluster.
    fn apply_addon(
        &self,
        name: &str,
        namespace: &str,
        addon: &Addon,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

// ---------------------------------------------------------------------------
// Shared backend utilities
//
// These functions encapsulate common logic (kubeconfig reading, health checks,
// readiness gate evaluation, addon application) that is identical across all
// backends. Each backend delegates to these rather than duplicating the logic.
// ---------------------------------------------------------------------------

/// Read the `{name}-kubeconfig` Secret from the host cluster.
pub async fn read_kubeconfig_secret(
    client: &Client,
    name: &str,
    namespace: &str,
) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = format!("{name}-kubeconfig");

    let secret = secrets
        .get(&secret_name)
        .await
        .with_context(|| format!("Kubeconfig secret {secret_name} not found"))?;

    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Kubeconfig secret has no data"))?;

    let kubeconfig_bytes = data
        .get("kubeconfig")
        .or_else(|| data.get("value"))
        .ok_or_else(|| anyhow::anyhow!("Kubeconfig secret has no 'kubeconfig' or 'value' key"))?;

    let kubeconfig =
        String::from_utf8(kubeconfig_bytes.0.clone()).context("Kubeconfig is not valid UTF-8")?;

    debug!(
        cluster = name,
        kubeconfig_len = kubeconfig.len(),
        "Kubeconfig extracted from secret"
    );

    Ok(kubeconfig)
}

/// Build a `kube::Client` targeting a virtual cluster from its kubeconfig YAML.
pub async fn virtual_client_from_kubeconfig(kubeconfig_yaml: &str) -> Result<Client> {
    let kubeconfig = kube::config::Kubeconfig::from_yaml(kubeconfig_yaml)?;
    let mut config = Config::from_custom_kubeconfig(kubeconfig, &Default::default())
        .await
        .context("Failed to build config from kubeconfig")?;
    // Virtual clusters use self-signed CAs; we trust them because we created them
    // and we're connecting cluster-internal (pod-to-service DNS).
    config.accept_invalid_certs = true;
    Client::try_from(config).context("Failed to create client from kubeconfig")
}

/// Check the health of a virtual cluster by hitting its `/healthz` endpoint.
///
/// Returns `Ok(false)` if the kubeconfig Secret does not exist yet (cluster
/// still provisioning). Returns `Ok(true)` if the API server responds "ok".
pub async fn check_virtual_health(client: &Client, name: &str, namespace: &str) -> Result<bool> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = format!("{name}-kubeconfig");

    match secrets.get(&secret_name).await {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            debug!(
                cluster = name,
                "Kubeconfig secret not found, cluster not ready"
            );
            return Ok(false);
        }
        Err(e) => {
            return Err(e).context("Failed to check kubeconfig secret");
        }
    }

    let kubeconfig_yaml = read_kubeconfig_secret(client, name, namespace).await?;
    let vc_client = virtual_client_from_kubeconfig(&kubeconfig_yaml)
        .await
        .context("Failed to build virtual client for health check")?;

    let req = ::http::Request::builder()
        .uri("/healthz")
        .body(vec![])
        .unwrap();

    // 5 second timeout — virtual cluster health checks should be fast
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        vc_client.request_text(req),
    )
    .await;

    match result {
        Ok(Ok(body)) => Ok(body.trim() == "ok"),
        Ok(Err(e)) => Err(e).context("Health probe request failed"),
        Err(_) => {
            debug!(cluster = name, "Health probe timed out after 5s");
            Ok(false)
        }
    }
}

/// Evaluate a readiness gate against a virtual cluster.
pub async fn check_readiness_gate_impl(vc_client: &Client, gate: &ReadinessGate) -> Result<bool> {
    match gate {
        ReadinessGate::CrdExists { name: crd_name, .. } => {
            let crds: Api<k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition> =
                Api::all(vc_client.clone());
            match crds.get(crd_name).await {
                Ok(_) => Ok(true),
                Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        ReadinessGate::DeploymentReady {
            name: deploy_name,
            namespace: deploy_ns,
        } => {
            let deploys: Api<k8s_openapi::api::apps::v1::Deployment> =
                Api::namespaced(vc_client.clone(), deploy_ns);
            match deploys.get(deploy_name).await {
                Ok(deploy) => {
                    let ready = deploy
                        .status
                        .as_ref()
                        .and_then(|s| s.ready_replicas)
                        .unwrap_or(0);
                    Ok(ready > 0)
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        ReadinessGate::DaemonSetReady {
            name: ds_name,
            namespace: ds_ns,
        } => {
            let daemonsets: Api<k8s_openapi::api::apps::v1::DaemonSet> =
                Api::namespaced(vc_client.clone(), ds_ns);
            match daemonsets.get(ds_name).await {
                Ok(ds) => {
                    let ready = ds.status.as_ref().map(|s| s.number_ready).unwrap_or(0);
                    let desired = ds
                        .status
                        .as_ref()
                        .map(|s| s.desired_number_scheduled)
                        .unwrap_or(1);
                    Ok(ready >= desired && desired > 0)
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        ReadinessGate::UrlHealthy { url, .. } => {
            validate_url(url)?;
            let resp = reqwest::get(url)
                .await
                .with_context(|| format!("URL health check failed for {url}"))?;
            Ok(resp.status().is_success())
        }
    }
}

/// Apply an addon manifest inside a virtual cluster using server-side apply.
pub async fn apply_addon_impl(vc_client: &Client, addon: &Addon) -> Result<()> {
    let manifest = match (&addon.manifest, &addon.url) {
        (Some(m), _) => m.clone(),
        (_, Some(url)) => {
            validate_url(url)
                .with_context(|| format!("Addon {} URL validation failed", addon.name))?;
            let resp = reqwest::get(url)
                .await
                .with_context(|| format!("Failed to fetch addon {} from {}", addon.name, url))?;
            resp.text()
                .await
                .with_context(|| format!("Failed to read addon {} body", addon.name))?
        }
        _ => {
            warn!(addon = addon.name, "Addon has no manifest or URL, skipping");
            return Ok(());
        }
    };

    const MAX_MANIFEST_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if manifest.len() > MAX_MANIFEST_SIZE {
        anyhow::bail!(
            "Addon {} manifest exceeds maximum size of {} bytes (actual: {} bytes)",
            addon.name,
            MAX_MANIFEST_SIZE,
            manifest.len()
        );
    }

    info!(addon = addon.name, "Applying addon via kube-rs SSA");

    for doc in manifest.split("\n---") {
        let doc = doc.trim();
        if doc.is_empty() || doc == "---" {
            continue;
        }

        let obj: kube::api::DynamicObject = match serde_yaml_ng::from_str(doc) {
            Ok(o) => o,
            Err(e) => {
                warn!(
                    addon = addon.name,
                    error = %e,
                    "Skipping unparseable YAML document in addon"
                );
                continue;
            }
        };

        let types = obj.types.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Addon {} contains resource without apiVersion/kind",
                addon.name
            )
        })?;

        let gvk = kube::api::GroupVersionKind::try_from(types)
            .map_err(|e| anyhow::anyhow!("Failed to parse GVK: {e}"))?;
        let ar = kube::discovery::ApiResource::from_gvk(&gvk);

        let api: Api<kube::api::DynamicObject> = if let Some(ns) = obj.metadata.namespace.as_deref()
        {
            Api::namespaced_with(vc_client.clone(), ns, &ar)
        } else {
            Api::all_with(vc_client.clone(), &ar)
        };

        let obj_name = obj.name_any();
        api.patch(
            &obj_name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Apply(&obj),
        )
        .await
        .with_context(|| {
            format!(
                "Failed to apply addon {} resource {}/{}",
                addon.name, types.kind, obj_name
            )
        })?;
    }

    Ok(())
}

/// Validate that a URL is safe to fetch (not an SSRF target).
///
/// Rejects:
/// - Non-HTTPS schemes (file://, ftp://, gopher://, http://)
/// - URLs resolving to private/loopback/link-local IP ranges
/// - Hostnames that look like internal Kubernetes services
pub fn validate_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("Invalid URL: {url}"))?;

    let scheme = parsed.scheme();
    if !ALLOWED_SCHEMES.contains(&scheme) {
        anyhow::bail!("URL scheme '{scheme}' not allowed, must be HTTPS: {url}");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?;

    if host.ends_with(".svc")
        || host.ends_with(".svc.cluster.local")
        || host == "localhost"
        || host == "kubernetes"
        || host == "kubernetes.default"
        || host.starts_with("169.254.")
        || host == "metadata.google.internal"
    {
        anyhow::bail!("URL targets an internal service, blocked for SSRF protection: {url}");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            anyhow::bail!("URL targets a private IP range, blocked for SSRF protection: {url}");
        }
    } else {
        // Host is a DNS name — resolve and validate all IPs to prevent DNS rebinding
        if let Ok(addrs) = format!("{host}:443").to_socket_addrs() {
            for addr in addrs {
                if is_private_ip(addr.ip()) {
                    anyhow::bail!(
                        "URL resolves to a private IP, blocked for SSRF protection: {url}"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Check if an IP address is in a private/reserved range.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()           // 127.0.0.0/8
                || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()  // 169.254.0.0/16
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_allows_https() {
        assert!(
            validate_url("https://raw.githubusercontent.com/org/repo/main/manifest.yaml").is_ok()
        );
    }

    #[test]
    fn test_validate_url_rejects_http() {
        assert!(validate_url("http://example.com/manifest.yaml").is_err());
    }

    #[test]
    fn test_validate_url_rejects_file_scheme() {
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_url_rejects_private_ips() {
        assert!(validate_url("https://10.0.0.1/manifest.yaml").is_err());
        assert!(validate_url("https://172.16.0.1/manifest.yaml").is_err());
        assert!(validate_url("https://192.168.1.1/manifest.yaml").is_err());
        assert!(validate_url("https://127.0.0.1/manifest.yaml").is_err());
    }

    #[test]
    fn test_validate_url_rejects_k8s_internal() {
        assert!(validate_url("https://kubernetes.default.svc/api").is_err());
        assert!(validate_url("https://my-service.namespace.svc.cluster.local/path").is_err());
        assert!(validate_url("https://metadata.google.internal/computeMetadata/v1/").is_err());
    }

    #[test]
    fn test_validate_url_rejects_link_local() {
        assert!(validate_url("https://169.254.169.254/latest/meta-data/").is_err());
    }
}
