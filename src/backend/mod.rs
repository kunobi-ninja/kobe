pub mod capi;
pub mod datastore;
pub mod k0s;
pub mod k3s;
pub mod vkobe;

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, Config, ResourceExt};
use tracing::{debug, info, warn};

use crate::crd::{
    Addon, BackendType, BootstrapConfig, BootstrapJobSpec, BootstrapRef, ClusterConfig,
    ClusterPool, ReadinessGate,
};

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
                profile.spec.backend.vkobe.clone(),
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

/// Check whether a virtual cluster is actually usable for Kubernetes discovery.
///
/// Returns `Ok(false)` if the kubeconfig Secret does not exist yet (cluster
/// still provisioning), if the API server times out, or if either `/api` or
/// `/apis` is not yet serving successfully.
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

    for path in ["/api", "/apis"] {
        if !probe_virtual_path(&vc_client, path, name).await? {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn probe_virtual_path(vc_client: &Client, path: &str, cluster_name: &str) -> Result<bool> {
    let req = ::http::Request::builder().uri(path).body(vec![]).unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        vc_client.request_text(req),
    )
    .await;

    match result {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(kube::Error::Api(ae))) if matches!(ae.code, 404 | 429 | 500 | 502 | 503 | 504) => {
            debug!(
                cluster = cluster_name,
                probe = path,
                status = ae.code,
                "Virtual cluster discovery probe not yet ready"
            );
            Ok(false)
        }
        Ok(Err(e)) => Err(e).with_context(|| format!("Discovery probe {path} failed")),
        Err(_) => {
            debug!(
                cluster = cluster_name,
                probe = path,
                "Virtual cluster discovery probe timed out after 5s"
            );
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

/// Resolve a pool/bootstrap list into additive manifest addons.
pub async fn resolve_bootstrap_addons(
    client: &Client,
    namespace: &str,
    bootstraps: &[BootstrapRef],
) -> Result<Vec<Addon>> {
    if bootstraps.is_empty() {
        return Ok(Vec::new());
    }

    let bootstrap_configs: Api<BootstrapConfig> = Api::namespaced(client.clone(), namespace);
    let mut resolved = Vec::with_capacity(bootstraps.len());

    for bootstrap in bootstraps {
        let config = bootstrap_configs
            .get(&bootstrap.name)
            .await
            .with_context(|| format!("BootstrapConfig {} not found", bootstrap.name))?;
        if let Some(manifest) = render_bootstrap_config(&config)? {
            resolved.push(Addon {
                name: bootstrap.name.clone(),
                manifest: Some(manifest),
                url: None,
            });
        }
    }

    Ok(resolved)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapJobPlan {
    pub name: String,
    pub image: String,
    pub image_pull_policy: Option<String>,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

pub async fn resolve_bootstrap_jobs(
    client: &Client,
    namespace: &str,
    bootstraps: &[BootstrapRef],
) -> Result<Vec<BootstrapJobPlan>> {
    if bootstraps.is_empty() {
        return Ok(Vec::new());
    }

    let bootstrap_configs: Api<BootstrapConfig> = Api::namespaced(client.clone(), namespace);
    let mut resolved = Vec::new();

    for bootstrap in bootstraps {
        let config = bootstrap_configs
            .get(&bootstrap.name)
            .await
            .with_context(|| format!("BootstrapConfig {} not found", bootstrap.name))?;

        if let Some(job) = config.spec.job.as_ref() {
            resolved.push(render_bootstrap_job_plan(
                &bootstrap.name,
                job,
                &bootstrap.params,
            )?);
        }
    }

    Ok(resolved)
}

fn render_bootstrap_config(config: &BootstrapConfig) -> Result<Option<String>> {
    let mut yaml_entries: Vec<(&String, &String)> = config
        .spec
        .files
        .iter()
        .filter(|(name, _)| name.ends_with(".yaml") || name.ends_with(".yml"))
        .collect();
    yaml_entries.sort_by(|(left, _), (right, _)| left.cmp(right));

    if yaml_entries.is_empty() {
        return Ok(None);
    }

    let manifests = yaml_entries
        .into_iter()
        .map(|(_, body)| body.trim())
        .filter(|body| !body.is_empty())
        .collect::<Vec<_>>();

    if manifests.is_empty() {
        anyhow::bail!(
            "BootstrapConfig {} has only empty manifest files",
            config.name_any()
        );
    }

    Ok(Some(manifests.join("\n---\n")))
}

fn render_bootstrap_job_plan(
    name: &str,
    job: &BootstrapJobSpec,
    params: &BTreeMap<String, String>,
) -> Result<BootstrapJobPlan> {
    if job.image.trim().is_empty() {
        anyhow::bail!("BootstrapConfig {} job.image must not be empty", name);
    }

    let command = job
        .command
        .iter()
        .map(|value| render_param_template(value, params))
        .collect::<Vec<_>>();
    let args = job
        .args
        .iter()
        .map(|value| render_param_template(value, params))
        .collect::<Vec<_>>();
    let env = job
        .env
        .iter()
        .map(|(key, value)| (key.clone(), render_param_template(value, params)))
        .collect::<BTreeMap<_, _>>();

    Ok(BootstrapJobPlan {
        name: name.to_string(),
        image: render_param_template(&job.image, params),
        image_pull_policy: job.image_pull_policy.clone(),
        command,
        args,
        env,
    })
}

fn render_param_template(input: &str, params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .fold(input.to_string(), |rendered, (key, value)| {
            rendered.replace(&format!("{{{{{key}}}}}"), value)
        })
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
    use base64::Engine;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn kubeconfig_secret_response(
        cluster_name: &str,
        namespace: &str,
        kubeconfig: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": format!("{cluster_name}-kubeconfig"),
                "namespace": namespace,
            },
            "data": {
                "kubeconfig": base64::engine::general_purpose::STANDARD.encode(kubeconfig),
            }
        })
    }

    fn backend_kubeconfig(server_url: &str) -> String {
        format!(
            r#"apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: {server_url}
users:
- name: default
  user:
    token: test-token
contexts:
- name: default
  context:
    cluster: default
    user: default
current-context: default
"#
        )
    }

    fn bootstrap_config_response(
        name: &str,
        namespace: &str,
        files: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "BootstrapConfig",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": {
                "files": files,
            }
        })
    }

    #[test]
    fn test_validate_url_allows_https() {
        assert!(
            validate_url("https://raw.githubusercontent.com/org/repo/main/manifest.yaml").is_ok()
        );
    }

    #[test]
    fn render_bootstrap_config_concatenates_yaml_files_in_lexical_order() {
        let config: BootstrapConfig = serde_json::from_value(bootstrap_config_response(
            "test-bundle",
            "test-ns",
            serde_json::json!({
                "20-second.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: second",
                "10-first.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: first",
                "README.md": "# ignored"
            }),
        ))
        .unwrap();

        let rendered = render_bootstrap_config(&config).unwrap().unwrap();
        assert!(rendered.contains("name: first"));
        assert!(rendered.contains("name: second"));
        assert!(rendered.find("name: first") < rendered.find("name: second"));
        assert!(!rendered.contains("# ignored"));
    }

    #[tokio::test]
    async fn resolve_bootstrap_addons_loads_bootstrap_configs_as_manifest_addons() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/bootstrapconfigs/flux",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(bootstrap_config_response(
                "flux",
                "test-ns",
                serde_json::json!({
                    "install.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system"
                }),
            )))
            .mount(&server)
            .await;

        let addons = resolve_bootstrap_addons(
            &client,
            "test-ns",
            &[BootstrapRef {
                name: "flux".to_string(),
                params: Default::default(),
            }],
        )
        .await
        .unwrap();

        assert_eq!(addons.len(), 1);
        assert_eq!(addons[0].name, "flux");
        assert!(
            addons[0]
                .manifest
                .as_deref()
                .unwrap()
                .contains("flux-system")
        );
        assert!(addons[0].url.is_none());
    }

    #[tokio::test]
    async fn resolve_bootstrap_jobs_loads_job_configs_and_renders_params() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/bootstrapconfigs/flux",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "BootstrapConfig",
                "metadata": {
                    "name": "flux",
                    "namespace": "test-ns",
                },
                "spec": {
                    "job": {
                        "image": "ghcr.io/example/{{channel}}:latest",
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["flux"],
                        "args": ["install", "--namespace={{namespace}}"],
                        "env": {
                            "FLUX_NAMESPACE": "{{namespace}}"
                        }
                    }
                }
            })))
            .mount(&server)
            .await;

        let jobs = resolve_bootstrap_jobs(
            &client,
            "test-ns",
            &[BootstrapRef {
                name: "flux".to_string(),
                params: BTreeMap::from([
                    ("channel".to_string(), "fluxcd".to_string()),
                    ("namespace".to_string(), "flux-system".to_string()),
                ]),
            }],
        )
        .await
        .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].name, "flux");
        assert_eq!(jobs[0].image, "ghcr.io/example/fluxcd:latest");
        assert_eq!(jobs[0].command, vec!["flux".to_string()]);
        assert_eq!(
            jobs[0].args,
            vec!["install".to_string(), "--namespace=flux-system".to_string()]
        );
        assert_eq!(
            jobs[0].env.get("FLUX_NAMESPACE").map(String::as_str),
            Some("flux-system")
        );
    }

    #[tokio::test]
    async fn check_virtual_health_requires_discovery() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let kubeconfig = backend_kubeconfig(&server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/test-cluster-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(kubeconfig_secret_response(
                    "test-cluster",
                    "test-ns",
                    &kubeconfig,
                )),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/apis"))
            .respond_with(ResponseTemplate::new(503).set_body_string("not ready"))
            .mount(&server)
            .await;

        let result = check_virtual_health(&client, "test-cluster", "test-ns")
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn check_virtual_health_succeeds_when_discovery_is_serving() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let kubeconfig = backend_kubeconfig(&server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/test-cluster-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(kubeconfig_secret_response(
                    "test-cluster",
                    "test-ns",
                    &kubeconfig,
                )),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/apis"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        let result = check_virtual_health(&client, "test-cluster", "test-ns")
            .await
            .unwrap();
        assert!(result);
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
