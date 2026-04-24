use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// --- Backend Selection ---

/// Which backend to use for cluster provisioning.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub enum BackendType {
    /// Manage k3s StatefulSets directly, optionally with a shared PostgreSQL datastore.
    #[default]
    #[serde(rename = "k3s")]
    K3s,
    /// Manage k0s clusters directly.
    #[serde(rename = "k0s")]
    K0s,
    /// Use Cluster API (CAPI) with a pluggable infrastructure provider.
    #[serde(rename = "capi")]
    Capi,
    /// Use vkobe virtual cluster runtime (lightweight proxy-based).
    #[serde(rename = "vkobe")]
    Vkobe,
}

/// Reference to a KobeStore CRD by name (same namespace).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreRef {
    /// Name of the KobeStore resource in the same namespace.
    pub name: String,
}

/// Kube-controller-manager configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KcmConfig {
    /// Which controllers to enable in the virtual KCM.
    #[serde(default = "default_kcm_controllers")]
    pub controllers: Vec<String>,
}

/// vkobe backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VkobeConfig {
    /// Reference to the KobeStore CRD that this cluster connects to.
    pub data_store_ref: KobeStoreRef,

    /// Kubernetes version for the virtual kube-apiserver (e.g. "1.32").
    #[serde(default = "default_k8s_version")]
    pub version: String,

    /// Optional KCM (kube-controller-manager) configuration.
    #[serde(default)]
    pub kcm: Option<KcmConfig>,

    /// Which resource syncers to enable. Defaults to core set.
    #[serde(default = "default_vkobe_syncers")]
    pub syncers: Vec<String>,

    /// Port for the virtual API server proxy (default: 8443).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,

    /// Port for health/metrics endpoints (default: 9090).
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

pub fn default_k8s_version() -> String {
    "1.32".to_string()
}

pub fn default_kcm_controllers() -> Vec<String> {
    vec![
        "deployment".into(),
        "replicaset".into(),
        "statefulset".into(),
        "daemonset".into(),
        "job".into(),
        "cronjob".into(),
        "namespace".into(),
        "serviceaccount".into(),
        "garbagecollector".into(),
    ]
}

pub fn default_vkobe_syncers() -> Vec<String> {
    vec![
        "pods".into(),
        "services".into(),
        "configmaps".into(),
        "secrets".into(),
        "endpoints".into(),
        "ingresses".into(),
    ]
}

fn default_proxy_port() -> u16 {
    8443
}

fn default_metrics_port() -> u16 {
    9090
}

/// Configuration for a shared PostgreSQL datastore (k3s backend only).
///
/// When configured, k3s clusters use `--datastore-endpoint=postgres://...` instead
/// of the embedded SQLite, enabling golden image creation via `CREATE DATABASE ... TEMPLATE`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatastoreConfig {
    /// Name of the Secret containing the PostgreSQL connection URL.
    pub secret_ref: String,
    /// Key in the Secret (default: "connection-url").
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
    /// Enable golden images via PostgreSQL template databases.
    #[serde(default)]
    pub golden_templates: bool,
}

fn default_secret_key() -> String {
    "connection-url".to_string()
}

/// CAPI (Cluster API) backend configuration.
/// Specifies the infrastructure provider CRD to use.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapiConfig {
    /// API version of the infrastructure CRD (e.g. "infrastructure.cluster.x-k8s.io/v1alpha1").
    pub infrastructure_api_version: String,
    /// Kind of the infrastructure CRD (e.g. "VCluster", "K0smotronCluster").
    pub infrastructure_kind: String,
    /// Raw JSON/YAML spec to embed in the infrastructure resource.
    /// This is provider-specific and passed through as-is.
    #[serde(default)]
    #[schemars(schema_with = "crate::crd::json_object_schema")]
    pub infrastructure_spec: Option<serde_json::Value>,
    /// Optional explicit plural form for the infrastructure CRD resource name.
    /// If not set, derived automatically by lowercasing the kind and appending "s".
    /// Use this for kinds with irregular plurals (e.g. "ingresses" for "Ingress").
    #[serde(default)]
    pub infrastructure_plural: Option<String>,
}

/// ClusterPool defines a pool of pre-warmed virtual clusters.
///
/// Each pool specifies cluster configuration, addons to install,
/// resource limits, health checks, readiness gates, scaling behavior,
/// and optional diagnostic capture settings.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterPool",
    plural = "clusterpools",
    shortname = "cp",
    status = "ClusterPoolStatus",
    namespaced,
    printcolumn = r#"{"name":"Phase",    "type":"string",  "jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready",    "type":"integer", "jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Leased",   "type":"integer", "jsonPath":".status.leased"}"#,
    printcolumn = r#"{"name":"Creating", "type":"integer", "jsonPath":".status.creating"}"#,
    printcolumn = r#"{"name":"Failures", "type":"integer", "jsonPath":".status.consecutiveFailures"}"#,
    printcolumn = r#"{"name":"Age",      "type":"date",    "jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPoolSpec {
    /// Desired number of warm (idle + creating) clusters in the pool.
    /// Ignored when `scaling` is set — use `scaling.min_ready` instead.
    #[serde(default = "default_size")]
    pub size: u32,

    /// Default TTL for claims against this pool (e.g. "2h", "30m").
    #[serde(default = "default_ttl")]
    pub ttl: String,

    /// Backend configuration for provisioning clusters.
    #[serde(default)]
    pub backend: BackendConfig,

    /// Cluster configuration.
    pub cluster: ClusterConfig,

    /// Addons to install after cluster is running.
    #[serde(default)]
    pub addons: Vec<Addon>,

    /// Reusable host-cluster bootstrap bundles to apply into each cluster.
    #[serde(default)]
    pub bootstraps: Vec<BootstrapRef>,

    /// Resource limits per cluster.
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,

    /// Health check configuration for warm clusters.
    /// Unhealthy clusters are automatically recycled.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Readiness gates that must pass before a cluster enters the warm pool.
    /// Clusters stay in Creating phase until all gates are satisfied.
    #[serde(default)]
    pub readiness_gates: Vec<ReadinessGate>,

    /// Autoscaling configuration. When set, overrides fixed `size`.
    #[serde(default)]
    pub scaling: Option<ScalingConfig>,

    /// Diagnostic bundle capture on claim release/expiry.
    #[serde(default)]
    pub diagnostics: Option<DiagnosticsConfig>,

    /// Velero golden image snapshot configuration.
    /// When enabled, the operator maintains a Velero backup of a golden cluster
    /// and restores new pool members from it for faster provisioning.
    #[serde(default)]
    pub snapshot: Option<SnapshotConfig>,
}

/// Nested backend configuration.
///
/// Groups the backend type selector and all backend-specific config
/// into a single struct, replacing the previous flat fields on the spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendConfig {
    /// Backend type.
    #[serde(rename = "type", default)]
    pub backend_type: BackendType,

    /// Shared PostgreSQL datastore configuration (k3s/k0s backends only).
    #[serde(default)]
    pub datastore: Option<DatastoreConfig>,

    /// CAPI backend configuration (capi backend only).
    #[serde(default)]
    pub capi: Option<CapiConfig>,

    /// vkobe backend configuration (vkobe backend only).
    #[serde(default)]
    pub vkobe: Option<VkobeConfig>,
}

/// Backend-agnostic cluster configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterConfig {
    /// k3s version (e.g., "v1.31.3+k3s1").
    pub version: String,

    /// Number of control plane servers.
    #[serde(default = "default_servers")]
    pub servers: u32,

    /// Number of k3s agent replicas (k3s backend only).
    /// When set, creates a separate agent Deployment that joins the server.
    #[serde(default)]
    pub agents: Option<u32>,

    /// Extra k3s server args.
    #[serde(default)]
    pub server_args: Vec<String>,

    /// Persistence config.
    #[serde(default)]
    pub persistence: Option<PersistenceConfig>,

    /// Expose config (ingress/LoadBalancer/NodePort).
    #[serde(default)]
    pub expose: Option<ExposeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PersistenceConfig {
    /// Storage type: "emptyDir", "dynamic", etc.
    #[serde(default)]
    pub storage_type: Option<String>,
    /// Storage class name for dynamic provisioning.
    #[serde(default)]
    pub storage_class_name: Option<String>,
    /// Storage request size (e.g., "10Gi").
    #[serde(default)]
    pub storage_request_size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExposeConfig {
    /// Expose type: "ingress", "NodePort", "LoadBalancer".
    pub expose_type: String,
    /// Ingress class name (when expose_type="ingress").
    #[serde(default)]
    pub ingress_class_name: Option<String>,
    /// NodePort number (when expose_type="NodePort").
    #[serde(default)]
    pub node_port: Option<i32>,
}

fn default_servers() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Addon {
    /// Human-readable name for the addon.
    pub name: String,

    /// Inline Kubernetes manifest YAML to apply after vcluster is ready.
    #[serde(default)]
    pub manifest: Option<String>,

    /// URL to fetch manifest from (alternative to inline).
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapRef {
    /// Name of the BootstrapConfig resource in the same namespace.
    pub name: String,

    /// Optional renderer-specific parameters for this bootstrap.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceRequirements {
    #[serde(default)]
    pub limits: BTreeMap<String, String>,

    #[serde(default)]
    pub requests: BTreeMap<String, String>,
}

// --- Enhancement: Health Probes ---

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckConfig {
    /// How often to probe warm clusters, in seconds.
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u32,

    /// Consecutive failures before recycling a cluster.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

// --- Enhancement: Readiness Gates ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ReadinessGate {
    /// Check that a CRD is registered in the cluster.
    #[serde(rename = "CRDExists")]
    CrdExists { name: String },

    /// Check that a Deployment is available (ready replicas > 0).
    #[serde(rename = "DeploymentReady")]
    DeploymentReady { name: String, namespace: String },

    /// Check that a DaemonSet has all pods ready.
    #[serde(rename = "DaemonSetReady")]
    DaemonSetReady { name: String, namespace: String },

    /// HTTP GET returns 2xx.
    #[serde(rename = "URLHealthy")]
    UrlHealthy { url: String },
}

// Manual JsonSchema impl — Kubernetes CRD structural schemas require that
// properties appearing in multiple oneOf branches have identical schemas.
// Internally-tagged enums violate this, so we flatten to a single object.
impl JsonSchema for ReadinessGate {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ReadinessGate".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "required": ["type"],
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["CRDExists", "DeploymentReady", "DaemonSetReady", "URLHealthy"]
                },
                "name": { "type": "string" },
                "namespace": { "type": "string" },
                "url": { "type": "string" }
            }
        }))
        .unwrap()
    }
}

// --- Enhancement: Autoscaling ---

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScalingConfig {
    /// Minimum number of warm (ready) clusters to maintain.
    #[serde(default = "default_min_ready")]
    pub min_ready: u32,

    /// Hard ceiling on total clusters (warm + leased + creating).
    #[serde(default = "default_max_clusters")]
    pub max_clusters: u32,

    /// Scale up when ready clusters fall to this threshold.
    #[serde(default)]
    pub scale_up_threshold: u32,

    /// Delete idle clusters after this duration if above `min_ready`.
    /// Format: "30m", "1h", etc.
    #[serde(default = "default_scale_down_after")]
    pub scale_down_after: String,

    /// Queue timeout for claims waiting when at max capacity.
    /// Claims pending longer than this get 503. Format: "5m".
    #[serde(default = "default_queue_timeout")]
    pub queue_timeout: String,

    /// Exponential backoff policy on consecutive provision failures.
    /// When unset, sensible defaults apply (base 5s, multiplier 2, max 2m).
    /// A broken pool that never reaches `Ready` caps at ~30 retries/hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_backoff: Option<FailureBackoffConfig>,
}

/// Per-pool exponential backoff configuration for consecutive provision
/// failures. All fields optional — unset fields inherit defaults.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FailureBackoffConfig {
    /// Base delay before retrying after the first failure. Format: "5s", "30s", "2m".
    /// Defaults to "5s" when unset.
    #[serde(default = "default_backoff_base")]
    pub base: String,

    /// Exponential multiplier applied to the delay on each consecutive failure.
    /// Defaults to 2 (binary exponential).
    #[serde(default = "default_backoff_multiplier")]
    pub multiplier: u32,

    /// Upper bound on the backoff delay. Prevents the retry interval from
    /// growing unbounded on sustained failure. Format: "2m", "10m".
    /// Defaults to "2m" when unset.
    #[serde(default = "default_backoff_max")]
    pub max: String,
}

// --- Enhancement: Diagnostics ---

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsConfig {
    /// Enable diagnostic capture on claim release/expiry.
    #[serde(default)]
    pub enabled: bool,

    /// S3 bucket URI (e.g. "s3://kunobi-diagnostics/").
    pub storage: String,

    /// How long to keep diagnostic bundles.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Number of log lines to capture per container.
    #[serde(default = "default_log_lines")]
    pub log_lines: u32,

    /// Never capture secrets by default.
    #[serde(default)]
    pub include_secrets: bool,
}

// --- Status ---

/// High-level human-readable summary of a pool's current state.
///
/// Derived from the other status counts + backoff fields each reconcile.
/// Serves as the primary at-a-glance health indicator in `kubectl get
/// clusterpools` and in dashboards — prefer parsing specific fields (like
/// `ready`, `consecutiveFailures`) for programmatic decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ClusterPoolPhase {
    /// At-or-above `minReady` ready clusters, or actively serving leases.
    Healthy,
    /// Creating clusters to reach `minReady` — either on first arrival
    /// (no prior instances) or refilling after a scale-down / lease churn.
    /// No consecutive failures.
    ScalingUp,
    /// Above `minReady` and shrinking toward it. Happens after
    /// `scaleDownAfter` reaps idle clusters, or while leases recycle and
    /// no refill is needed.
    ScalingDown,
    /// Consecutive provision failures, currently inside the backoff window.
    Backoff,
    /// Three or more consecutive failures sustained — requires operator
    /// attention (misconfiguration, missing dependency, etc.).
    Failing,
    /// Pool scaled to zero by design — no demand, `minReady == 0`, nothing
    /// in flight. Healthy steady state for a fully-idle pool.
    Idle,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPoolStatus {
    /// High-level phase summary. Derived from counts + backoff state each
    /// reconcile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ClusterPoolPhase>,

    /// Number of idle clusters ready for claims.
    #[serde(default)]
    pub ready: u32,

    /// Number of clusters currently leased.
    #[serde(default, alias = "claimed")]
    pub leased: u32,

    /// Number of clusters being created.
    #[serde(default)]
    pub creating: u32,

    /// Number of clusters currently being recycled.
    #[serde(default)]
    pub recycling: u32,

    /// Number of clusters currently unhealthy and being recycled.
    #[serde(default)]
    pub unhealthy: u32,

    /// Current queue depth (claims waiting for clusters).
    #[serde(default)]
    pub queue_depth: u32,

    /// Name of the current golden Velero backup (e.g. "golden-myprofile-3").
    #[serde(default)]
    pub golden_backup: Option<String>,

    /// The profile generation that the golden backup was created from.
    /// Used to detect when a new snapshot is needed after spec changes.
    #[serde(default)]
    pub golden_generation: Option<i64>,

    /// Name of the PostgreSQL template database for golden images (k3s backend).
    #[serde(default)]
    pub golden_template_db: Option<String>,

    /// Number of consecutive provision attempts that failed before any
    /// instance reached `Ready`. Resets to 0 when any instance reaches `Ready`.
    /// Drives the exponential backoff that slows down broken-pool create loops
    /// so one misconfigured pool cannot hammer the API at full speed.
    #[serde(default)]
    pub consecutive_failures: u32,

    /// Earliest time the pool manager may emit another `Create` action for
    /// this pool (RFC3339). Set when `consecutive_failures > 0`. Cleared on
    /// success or by explicit operator reset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,

    /// Short description of the last provision failure, for operator
    /// observability. Typically the first line of the error chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_reason: Option<String>,

    /// High-water mark of the highest cluster index this pool has ever
    /// attempted to provision. Sticky across reconciles. Used together with
    /// `last_ready_max_index` to detect rapid create→recycle churn that
    /// would otherwise hide failures from `consecutive_failures` (which
    /// only increments on a stable "all recycling, none creating" state —
    /// a state that fast churn never produces because the next attempt
    /// has already started).
    #[serde(default)]
    pub max_attempted_index: u32,

    /// Highest cluster index that has ever reached `Ready` in this pool's
    /// lifetime. Sticky across reconciles. `consecutive_failures` is then
    /// derived as `max_attempted_index - last_ready_max_index`, which
    /// correctly counts failed attempts even during rapid churn.
    #[serde(default)]
    pub last_ready_max_index: u32,
}

// --- Defaults ---

fn default_size() -> u32 {
    3
}
fn default_ttl() -> String {
    "2h".to_string()
}
fn default_health_interval() -> u32 {
    30
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_min_ready() -> u32 {
    1
}
fn default_max_clusters() -> u32 {
    8
}
fn default_scale_down_after() -> String {
    "5m".to_string()
}
fn default_queue_timeout() -> String {
    "5m".to_string()
}
fn default_backoff_base() -> String {
    "5s".to_string()
}
fn default_backoff_multiplier() -> u32 {
    2
}
fn default_backoff_max() -> String {
    "2m".to_string()
}
fn default_retention_days() -> u32 {
    7
}
fn default_log_lines() -> u32 {
    1000
}

// --- Enhancement: Velero Golden Image Snapshots ---

/// Configuration for Velero-based golden image snapshots.
///
/// When enabled, the operator creates and maintains a Velero backup of a
/// "golden" cluster for this profile. New pool members can be restored from
/// the snapshot instead of being provisioned from scratch.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotConfig {
    /// Enable golden image snapshotting via Velero.
    #[serde(default)]
    pub enabled: bool,

    /// Namespace where the Velero server is installed.
    #[serde(default = "default_velero_ns")]
    pub velero_namespace: String,

    /// Velero BackupStorageLocation name to use.
    #[serde(default = "default_storage_location")]
    pub storage_location: String,

    /// Prefix for the golden backup name (e.g. "golden-<profile>").
    #[serde(default = "default_golden_prefix")]
    pub golden_prefix: String,

    /// How long the Velero backup should be retained (e.g. "720h").
    #[serde(default = "default_backup_ttl")]
    pub ttl: String,

    /// When to refresh the golden image.
    #[serde(default)]
    pub refresh_on: SnapshotRefreshTrigger,
}

/// Trigger condition for refreshing the golden image.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub enum SnapshotRefreshTrigger {
    /// Re-snapshot whenever the profile spec changes (generation bump).
    #[default]
    ProfileChange,
    /// Only re-snapshot when explicitly requested via annotation.
    Manual,
}

fn default_velero_ns() -> String {
    "velero".to_string()
}
fn default_storage_location() -> String {
    "default".to_string()
}
fn default_golden_prefix() -> String {
    "golden".to_string()
}
fn default_backup_ttl() -> String {
    "720h".to_string()
}
