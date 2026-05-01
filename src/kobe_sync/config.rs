use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KobeSyncRuntimeConfig {
    /// Host namespace where all translated resources live.
    pub host_namespace: String,
    /// Unique cluster identifier (used in name suffix).
    pub cluster_name: String,
    /// Name suffix for translated resources (default: "vc").
    #[serde(default = "default_suffix")]
    pub name_suffix: String,
    /// Enabled syncer names (e.g., ["pods", "services", "configmaps"]).
    #[serde(default)]
    pub enabled_syncers: Vec<String>,
    /// Port for the HTTPS proxy (default: 8443).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Port for health/metrics (default: 9090).
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Virtual namespaces to create by default.
    #[serde(default = "default_virtual_namespaces")]
    pub default_namespaces: Vec<String>,
    /// URL of the local virtual kube-apiserver (default: "https://localhost:6443").
    #[serde(default = "default_virtual_api_url")]
    pub virtual_api_url: String,
    /// etcd key prefix for this cluster (e.g. "/kobe/cluster-1/").
    #[serde(default)]
    pub etcd_prefix: String,
    /// Namespaces to skip during syncing (e.g. ["kube-system"]).
    #[serde(default)]
    pub skip_namespaces: Vec<String>,
}

fn default_suffix() -> String {
    "vc".to_string()
}

fn default_proxy_port() -> u16 {
    8443
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_virtual_namespaces() -> Vec<String> {
    vec![
        "default".to_string(),
        "kube-system".to_string(),
        "kube-public".to_string(),
        "kube-node-lease".to_string(),
    ]
}

fn default_virtual_api_url() -> String {
    "https://localhost:6443".to_string()
}

/// Default user-configurable syncer list — workload-shaped resources
/// the user could reasonably opt out of for a stripped-down pool.
///
/// **Does NOT include the always-on syncers** (`fake_nodes`,
/// `status`, `service_accounts`). Those are unconditionally started
/// by `kobe_sync_bin::main` regardless of this list because vkobe
/// is structurally non-functional without them — see the always-on
/// block in `kobe_sync_bin.rs` for the rationale per syncer.
fn default_syncers() -> Vec<String> {
    vec![
        "pods".into(),
        "services".into(),
        "configmaps".into(),
        "secrets".into(),
        "endpoints".into(),
        "ingresses".into(),
    ]
}

impl Default for KobeSyncRuntimeConfig {
    fn default() -> Self {
        Self {
            host_namespace: String::new(),
            cluster_name: String::new(),
            name_suffix: default_suffix(),
            enabled_syncers: default_syncers(),
            proxy_port: default_proxy_port(),
            metrics_port: default_metrics_port(),
            default_namespaces: default_virtual_namespaces(),
            virtual_api_url: default_virtual_api_url(),
            etcd_prefix: String::new(),
            skip_namespaces: Vec::new(),
        }
    }
}

impl KobeSyncRuntimeConfig {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `KOBE_SYNC_HOST_NAMESPACE`
    /// - `KOBE_SYNC_CLUSTER_NAME`
    ///
    /// Optional:
    /// - `KOBE_SYNC_PROXY_PORT` (default: 8443)
    /// - `KOBE_SYNC_METRICS_PORT` (default: 9090)
    /// - `KOBE_SYNC_SYNCERS` (comma-separated, default: "pods,services,configmaps,secrets,endpoints,ingresses")
    /// - `KOBE_SYNC_VIRTUAL_API_URL` (default: "https://localhost:6443")
    /// - `KOBE_SYNC_ETCD_PREFIX` (default: derived from cluster name as "/kobe/{cluster_name}/")
    pub fn load_from_env() -> Result<Self> {
        let host_namespace = std::env::var("KOBE_SYNC_HOST_NAMESPACE")
            .context("KOBE_SYNC_HOST_NAMESPACE is required")?;
        let cluster_name = std::env::var("KOBE_SYNC_CLUSTER_NAME")
            .context("KOBE_SYNC_CLUSTER_NAME is required")?;

        let proxy_port = match std::env::var("KOBE_SYNC_PROXY_PORT") {
            Ok(val) => val
                .parse::<u16>()
                .context("KOBE_SYNC_PROXY_PORT must be a valid u16")?,
            Err(_) => default_proxy_port(),
        };

        let metrics_port = match std::env::var("KOBE_SYNC_METRICS_PORT") {
            Ok(val) => val
                .parse::<u16>()
                .context("KOBE_SYNC_METRICS_PORT must be a valid u16")?,
            Err(_) => default_metrics_port(),
        };

        let enabled_syncers = match std::env::var("KOBE_SYNC_SYNCERS") {
            Ok(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
            Err(_) => default_syncers(),
        };

        let virtual_api_url = std::env::var("KOBE_SYNC_VIRTUAL_API_URL")
            .unwrap_or_else(|_| default_virtual_api_url());

        let etcd_prefix = std::env::var("KOBE_SYNC_ETCD_PREFIX")
            .unwrap_or_else(|_| format!("/kobe/{cluster_name}/"));

        let skip_namespaces = match std::env::var("KOBE_SYNC_SKIP_NAMESPACES") {
            Ok(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
            Err(_) => Vec::new(),
        };

        Ok(Self {
            host_namespace,
            cluster_name,
            name_suffix: default_suffix(),
            enabled_syncers,
            proxy_port,
            metrics_port,
            default_namespaces: default_virtual_namespaces(),
            virtual_api_url,
            etcd_prefix,
            skip_namespaces,
        })
    }

    /// Load configuration from a Kubernetes ConfigMap.
    ///
    /// Reads the ConfigMap named `name` in `namespace` and expects keys
    /// that map to the struct fields. The ConfigMap should contain a key
    /// called `config.json` with the JSON-serialized configuration.
    pub async fn load_from_configmap(
        client: &kube::Client,
        name: &str,
        namespace: &str,
    ) -> Result<Self> {
        use kube::api::Api;

        let api: Api<k8s_openapi::api::core::v1::ConfigMap> =
            Api::namespaced(client.clone(), namespace);
        let cm = api
            .get(name)
            .await
            .with_context(|| format!("Failed to get ConfigMap {name} in namespace {namespace}"))?;

        let data = cm.data.unwrap_or_default();

        // Try to load from a single "config.json" key first.
        if let Some(json_str) = data.get("config.json") {
            let config: KobeSyncRuntimeConfig = serde_json::from_str(json_str)
                .context("Failed to parse config.json from ConfigMap")?;
            return Ok(config);
        }

        // Fall back to loading individual keys from the ConfigMap data.
        let host_namespace = data
            .get("host_namespace")
            .or_else(|| data.get("hostNamespace"))
            .cloned()
            .context("ConfigMap missing 'host_namespace' or 'hostNamespace' key")?;

        let cluster_name = data
            .get("cluster_name")
            .or_else(|| data.get("clusterName"))
            .cloned()
            .context("ConfigMap missing 'cluster_name' or 'clusterName' key")?;

        let proxy_port = data
            .get("proxy_port")
            .or_else(|| data.get("proxyPort"))
            .map(|v| v.parse::<u16>())
            .transpose()
            .context("Invalid proxy_port in ConfigMap")?
            .unwrap_or_else(default_proxy_port);

        let metrics_port = data
            .get("metrics_port")
            .or_else(|| data.get("metricsPort"))
            .map(|v| v.parse::<u16>())
            .transpose()
            .context("Invalid metrics_port in ConfigMap")?
            .unwrap_or_else(default_metrics_port);

        let enabled_syncers = data
            .get("syncers")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(default_syncers);

        let name_suffix = data
            .get("name_suffix")
            .or_else(|| data.get("nameSuffix"))
            .cloned()
            .unwrap_or_else(default_suffix);

        let virtual_api_url = data
            .get("virtual_api_url")
            .or_else(|| data.get("virtualApiUrl"))
            .cloned()
            .unwrap_or_else(default_virtual_api_url);

        let etcd_prefix = data
            .get("etcd_prefix")
            .or_else(|| data.get("etcdPrefix"))
            .cloned()
            .unwrap_or_else(|| format!("/kobe/{cluster_name}/"));

        let skip_namespaces = data
            .get("skip_namespaces")
            .or_else(|| data.get("skipNamespaces"))
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        Ok(Self {
            host_namespace,
            cluster_name,
            name_suffix,
            enabled_syncers,
            proxy_port,
            metrics_port,
            default_namespaces: default_virtual_namespaces(),
            virtual_api_url,
            etcd_prefix,
            skip_namespaces,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KobeSyncRuntimeConfig::default();
        assert_eq!(config.name_suffix, "vc");
        assert_eq!(config.proxy_port, 8443);
        assert_eq!(config.metrics_port, 9090);
        assert!(!config.enabled_syncers.is_empty());
        assert!(config.default_namespaces.contains(&"default".to_string()));
        assert!(
            config
                .default_namespaces
                .contains(&"kube-system".to_string())
        );
    }

    #[test]
    fn test_default_syncers() {
        let syncers = default_syncers();
        assert!(syncers.contains(&"pods".to_string()));
        assert!(syncers.contains(&"services".to_string()));
        assert!(syncers.contains(&"configmaps".to_string()));
        assert!(syncers.contains(&"secrets".to_string()));
        assert!(syncers.contains(&"endpoints".to_string()));
        assert!(syncers.contains(&"ingresses".to_string()));
    }

    /// The runtime sidecar default must match exactly the same list
    /// as the operator-side `crd::default_vkobe_syncers`. The two
    /// modules live in separate binaries (`kobe-sync` and
    /// `kobe-operator`), so they can't share a constant directly;
    /// instead, both pin against this hardcoded canonical list.
    ///
    /// **`service_accounts`, `fake_nodes`, and `status` are
    /// deliberately absent** from this list — they are infrastructural
    /// always-on syncers started unconditionally by
    /// `kobe_sync_bin::main` regardless of the user's
    /// `enabled_syncers`. Including them here would cause double-spawn
    /// (the always-on path AND the configurable path would each
    /// register the syncer), which the dedup in `kobe_sync_bin`
    /// catches and logs but is cleaner to avoid by keeping them out
    /// of the configurable default in the first place.
    ///
    /// The mirror assertion lives at
    /// `crd::profile::tests::default_vkobe_syncers_matches_canonical_list`.
    /// Update both lists together when adding a syncer to the
    /// configurable default set.
    #[test]
    fn runtime_default_syncers_match_canonical() {
        const CANONICAL: &[&str] = &[
            "pods",
            "services",
            "configmaps",
            "secrets",
            "endpoints",
            "ingresses",
        ];
        let actual = default_syncers();
        let expected: Vec<String> = CANONICAL.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            actual, expected,
            "runtime default_syncers drifted from the canonical list. \
             Update both kobe_sync/config.rs and crd/profile.rs's \
             default_vkobe_syncers — drift silently disables or \
             double-spawns a syncer."
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = KobeSyncRuntimeConfig {
            host_namespace: "pool-e2e-basic-0".to_string(),
            cluster_name: "test-cluster".to_string(),
            name_suffix: "vc".to_string(),
            enabled_syncers: vec!["pods".into(), "services".into()],
            proxy_port: 8443,
            metrics_port: 9090,
            default_namespaces: vec!["default".into()],
            virtual_api_url: "https://localhost:6443".to_string(),
            etcd_prefix: "/kobe/test-cluster/".to_string(),
            skip_namespaces: vec!["kube-system".into()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KobeSyncRuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host_namespace, "pool-e2e-basic-0");
        assert_eq!(parsed.cluster_name, "test-cluster");
        assert_eq!(parsed.proxy_port, 8443);
        assert_eq!(parsed.enabled_syncers.len(), 2);
    }

    #[test]
    fn test_serde_defaults_applied() {
        let json = r#"{"host_namespace":"ns","cluster_name":"c"}"#;
        let config: KobeSyncRuntimeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name_suffix, "vc");
        assert_eq!(config.proxy_port, 8443);
        assert_eq!(config.metrics_port, 9090);
        assert!(config.enabled_syncers.is_empty()); // serde default for Vec is empty
        assert!(config.default_namespaces.contains(&"default".to_string()));
    }

    /// All env-var-dependent tests run sequentially within a single test
    /// to avoid races from `set_var`/`remove_var` on process-global state.
    #[test]
    fn test_load_from_env_all_scenarios() {
        // SAFETY: test-only, single-threaded
        unsafe {
            // --- Scenario 1: missing required vars → error ---
            std::env::remove_var("KOBE_SYNC_HOST_NAMESPACE");
            std::env::remove_var("KOBE_SYNC_CLUSTER_NAME");
            std::env::remove_var("KOBE_SYNC_VIRTUAL_API_URL");
            std::env::remove_var("KOBE_SYNC_ETCD_PREFIX");
            std::env::remove_var("KOBE_SYNC_PROXY_PORT");
            std::env::remove_var("KOBE_SYNC_METRICS_PORT");
            std::env::remove_var("KOBE_SYNC_SYNCERS");
        }

        let result = KobeSyncRuntimeConfig::load_from_env();
        assert!(
            result.is_err(),
            "should fail when required vars are missing"
        );

        // SAFETY: test-only, single-threaded
        unsafe {
            // --- Scenario 2: explicit fields ---
            std::env::set_var("KOBE_SYNC_HOST_NAMESPACE", "pool-ns");
            std::env::set_var("KOBE_SYNC_CLUSTER_NAME", "cluster-1");
            std::env::set_var("KOBE_SYNC_VIRTUAL_API_URL", "https://10.0.0.1:6443");
            std::env::set_var("KOBE_SYNC_ETCD_PREFIX", "/kobe/cluster-1/");
        }

        let config = KobeSyncRuntimeConfig::load_from_env().unwrap();
        assert_eq!(config.virtual_api_url, "https://10.0.0.1:6443");
        assert_eq!(config.etcd_prefix, "/kobe/cluster-1/");

        // SAFETY: test-only, single-threaded
        unsafe {
            // --- Scenario 3: defaults ---
            std::env::set_var("KOBE_SYNC_HOST_NAMESPACE", "pool-defaults");
            std::env::set_var("KOBE_SYNC_CLUSTER_NAME", "defaults-test-cluster");
            std::env::remove_var("KOBE_SYNC_VIRTUAL_API_URL");
            std::env::remove_var("KOBE_SYNC_ETCD_PREFIX");
        }

        let config = KobeSyncRuntimeConfig::load_from_env().unwrap();
        assert_eq!(config.virtual_api_url, "https://localhost:6443");
        assert_eq!(
            config.etcd_prefix,
            format!("/kobe/{}/", config.cluster_name)
        );

        // Also verify the Default trait implementation.
        let default_config = KobeSyncRuntimeConfig::default();
        assert_eq!(default_config.virtual_api_url, "https://localhost:6443");
        assert_eq!(default_config.etcd_prefix, "");

        // SAFETY: test-only, single-threaded
        unsafe {
            // --- Clean up ---
            std::env::remove_var("KOBE_SYNC_HOST_NAMESPACE");
            std::env::remove_var("KOBE_SYNC_CLUSTER_NAME");
        }
    }
}
