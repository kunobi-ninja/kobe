use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// --- Backend Selection ---

/// Which backend to use for cluster provisioning.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
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
    /// Use the in-house vkobe virtual cluster runtime (deprecated — see
    /// `docs/architecture/virtual-cluster-strategy.md` for migration path
    /// to the `vcluster` backend).
    #[serde(rename = "vkobe")]
    Vkobe,
    /// Use upstream loft-sh/vcluster (Apache 2.0) as the virtual cluster
    /// runtime. Replaces the in-house vkobe backend. The operator deploys
    /// a vcluster instance per `ClusterInstance` via the official Helm
    /// chart, into a dedicated per-instance namespace.
    #[serde(rename = "vcluster")]
    Vcluster,
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

/// Default user-configurable syncer list — workload-shaped resources
/// the user could reasonably opt out of for a stripped-down pool.
///
/// **Does NOT include the always-on syncers** (`fake_nodes`,
/// `status`, `service_accounts`). Those are unconditionally started
/// by `kobe_sync_bin::main` regardless of this list because vkobe
/// is structurally non-functional without them — see the always-on
/// block in `kobe_sync_bin.rs`. Including them here would cause
/// double-spawn (caught by the kobe-sync dedup but cleaner to avoid).
///
/// **Must match `crate::kobe_sync::config::default_syncers`** — the
/// operator writes this list into the per-cluster ConfigMap, and the
/// sidecar reads from there first. The two lists encode the same
/// intent but live in separate binaries, so they can't share a
/// constant directly. Pinned by
/// `default_vkobe_syncers_matches_canonical_list` in this module's
/// tests; the mirror lives in `kobe_sync::config::tests`.
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

    /// Rolling-upgrade policy for drift recycling. When unset, a
    /// conservative default applies: `maxRecycling=1, maxSurge=1`,
    /// floor on `ready_clean` is `min_ready` (or `spec.size` for fixed
    /// pools). See [`crate::pool::manager::compute_pool_actions`] for
    /// the algorithm and `docs/guides/upgrade-policy.md` for the
    /// operator-facing tuning guide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_policy: Option<UpgradePolicy>,

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

    /// vcluster backend configuration (vcluster backend only).
    #[serde(default)]
    pub vcluster: Option<VclusterConfig>,
}

/// vcluster backend configuration.
///
/// The kobe operator deploys vcluster instances via the upstream Helm
/// chart (https://charts.loft.sh / `loft-sh/vcluster`). Each
/// `ClusterInstance` gets its own dedicated host namespace named after
/// the instance, isolating projection scope per instance and making
/// teardown trivially correct (`helm uninstall` + `kubectl delete ns`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct VclusterConfig {
    /// Helm chart version of `loft-sh/vcluster` to deploy. If unset, the
    /// operator's pinned default applies.
    #[serde(default)]
    pub chart_version: Option<String>,

    /// Inline Helm values (YAML) merged on top of the operator's defaults.
    /// Use this to enable / disable features per pool (sync targets,
    /// expose mode, resource limits, etc).
    ///
    /// Schema: free-form YAML matching vcluster's chart values
    /// (see https://www.vcluster.com/docs/configure/vcluster-yaml).
    #[serde(default)]
    pub values: Option<String>,
}

/// Backend-agnostic cluster configuration.
///
/// `Default` is derived so `..Default::default()` can be used to fill
/// runtime-only fields like `allocated_network` without re-listing every
/// CRD-spec field at construction sites; it is not intended to produce a
/// usable cluster configuration on its own (`version` becomes empty).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
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

    /// Node taints applied to the cluster's control-plane node(s).
    ///
    /// Semantics:
    /// - **Field omitted** — backend default applies (e.g. k0s adds
    ///   `node-role.kubernetes.io/master:NoSchedule` when running
    ///   `controller --enable-worker`). Backward compatible.
    /// - **Empty list `[]`** — no taints applied; any backend default is
    ///   suppressed. Useful for single-node CI/dev clusters where pods
    ///   need to schedule on the control-plane node.
    /// - **Non-empty list** — exactly these taints are applied; backend
    ///   defaults are suppressed.
    ///
    /// Currently honored by the k0s backend; other backends will gain
    /// support over time.
    #[serde(default)]
    pub taints: Option<Vec<NodeTaint>>,

    /// Node placement strategy for the cluster's pods. When omitted, the
    /// scheduler picks any eligible node independently for each pod.
    ///
    /// Currently meaningful for the k3s backend, which has split server
    /// and agent pods. For single-pod backends (vkobe) this is a no-op.
    #[serde(default)]
    pub node_placement: Option<NodePlacement>,

    /// Kubernetes cluster DNS domain (defaults to `cluster.local`).
    /// Used to build the FQDN of the cluster's API Service for the
    /// agent's `--server` URL, the apiserver TLS SANs, and the
    /// published kubeconfig.
    ///
    /// Why this matters: the short name `{svc}.{ns}.svc` has 2 dots,
    /// matching the typical `ndots:2` in resolv.conf. Resolvers then
    /// query it as absolute first; Alpine/musl-based k3s and k0s
    /// images don't fall back to `search` domains after that returns
    /// NXDOMAIN and the agent's join silently fails. Using the FQDN
    /// (4 dots) sidesteps the search-domain dance entirely.
    #[serde(default)]
    pub cluster_domain: Option<String>,

    /// Container registry mirrors for the leased cluster's container
    /// runtime. Maps source registry hostname (e.g. `docker.io`,
    /// `quay.io`) to a list of mirror endpoint URLs the runtime should
    /// try before the source.
    ///
    /// Currently honored by the k3s backend, which writes the map into
    /// `/etc/rancher/k3s/registries.yaml` on every node — k3s reads it
    /// at startup and configures containerd accordingly.
    /// (https://docs.k3s.io/installation/private-registry).
    ///
    /// Why this matters: leased clusters running inside a host cluster
    /// with restricted egress can't reach upstream registries directly.
    /// Without a mirror config, every Pod that pulls e.g. `busybox:1.36`
    /// hits `ImagePullBackOff` because the leased cluster's containerd
    /// goes straight to `docker.io`. Setting a mirror redirects the
    /// pull through an in-network proxy (Harbor, Sonatype, an Artifact
    /// Registry mirror, etc.) that the host cluster CAN reach.
    ///
    /// Example:
    ///   registryMirrors:
    ///     docker.io:
    ///       - https://registry.example.com
    ///       - https://docker-mirror.example.com
    #[serde(default)]
    pub registry_mirrors: Option<std::collections::BTreeMap<String, Vec<String>>>,

    /// Network ranges allocated for this cluster instance. **Operator-
    /// internal**: not part of the CRD spec users write — populated by
    /// the instance reconciler from `ClusterInstance.status.network`
    /// before invoking `ClusterBackend::create`. Backends that own
    /// their own network plane (k3s, k0s) consume this for their
    /// `--service-cidr` / `--cluster-cidr` flags; backends that reuse
    /// the host's network (vkobe) ignore it.
    ///
    /// `#[serde(skip)]` keeps the field out of every wire format
    /// (CRD spec round-trip, `kobe config import/export`, the
    /// operator's reconciliation Patch) — it lives only inside an
    /// in-memory `ResolvedInstanceConfig`.
    // `#[allow(dead_code)]` keeps the `crdgen` binary happy: it imports
    // this struct purely to walk the JSON schema and never reads
    // runtime-only fields, so clippy flags this as dead from crdgen's
    // perspective. The operator binary DOES read the field, so the
    // attribute is just shielding the cross-binary visibility quirk.
    #[serde(skip)]
    #[allow(dead_code)]
    pub allocated_network: Option<crate::crd::ClusterInstanceNetwork>,

    /// Resource requirements applied to each container the backend creates
    /// for this cluster (k3s server + agent today). **Operator-internal**:
    /// not part of the CRD spec users write — populated by the instance
    /// reconciler from `ClusterPool.spec.resources` before invoking
    /// `ClusterBackend::create`.
    ///
    /// Why this lives on `ClusterConfig` and not on a backend trait param:
    /// the existing precedent (`allocated_network`) already uses this
    /// pattern for pool-level inputs the backend needs at provisioning
    /// time, and threading it here avoids touching the
    /// [`crate::backend::ClusterBackend`] signature and every backend
    /// implementation.
    ///
    /// `#[serde(skip)]` keeps it out of the CRD schema — users still set
    /// limits via the pool-level [`ClusterPoolSpec::resources`] field.
    #[serde(skip)]
    #[allow(dead_code)]
    pub resources: Option<ResourceRequirements>,
}

/// A single taint applied to cluster nodes. Mirrors `core/v1.Taint`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeTaint {
    /// Taint key (e.g. `dedicated`).
    pub key: String,
    /// Optional taint value (e.g. `gpu`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Taint effect.
    pub effect: TaintEffect,
}

/// Allowed taint effects, matching `core/v1.TaintEffect`.
///
/// `PascalCase` is the wire form expected by Kubernetes; the explicit
/// rename pins it so a future contributor copying the camelCase parent
/// attribute (`NodeTaint`) onto this enum cannot silently break the CRD.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

impl std::fmt::Display for TaintEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintEffect::NoSchedule => f.write_str("NoSchedule"),
            TaintEffect::PreferNoSchedule => f.write_str("PreferNoSchedule"),
            TaintEffect::NoExecute => f.write_str("NoExecute"),
        }
    }
}

impl NodeTaint {
    /// Render the taint in the form accepted by `kubelet --register-with-taints`,
    /// `k0s --taints`, and `k3s --node-taint`. The upstream parser
    /// (`k8s.io/kubernetes/pkg/util/taints.parseTaint`) requires either
    /// `key=value:effect` or `key:effect`. The `key=:effect` form (empty
    /// explicit value) is implementation-dependent and at minimum produces
    /// a taint whose `Value` is `""` rather than absent — asymmetric with
    /// what a user typed and breaks `kubectl taint` removal matching.
    // crdgen binary only consumes the CRD schema, never the impl — without this
    // it warns dead_code in that build target while the operator does use it.
    #[allow(dead_code)]
    pub fn to_kubelet_arg(&self) -> String {
        match &self.value {
            Some(v) => format!("{}={}:{}", self.key, v, self.effect),
            None => format!("{}:{}", self.key, self.effect),
        }
    }
}

/// Node placement strategy for cluster pods (server + agents).
///
/// Wrapped in a struct so future extensions (custom topology key,
/// additional knobs) can be added next to `mode` without breaking
/// existing manifests.
///
/// `mode` and `spread` are orthogonal:
/// - `mode` controls **intra-instance** placement (server ↔ agent of the
///   same cluster), used to side-step broken cross-host pod routing.
/// - `spread` controls **inter-instance** placement (pool members of
///   different ClusterInstances relative to each other), used to keep
///   one busy host from collecting every pool member.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodePlacement {
    /// Placement mode.
    pub mode: NodePlacementMode,

    /// Inter-instance spread across physical hosts. Controls the
    /// `podAntiAffinity` rendered on the server StatefulSet so multiple
    /// pool members don't pile onto the same node.
    ///
    /// When omitted, no anti-affinity is emitted — manifests stay
    /// byte-identical to clusters created before this field existed.
    ///
    /// Selector matches sibling kobe-operator-managed k3s servers on the
    /// host (label `app.kubernetes.io/managed-by=kobe-operator` AND
    /// `kobe.kunobi.ninja/role=server`). On a multi-pool host cluster
    /// this spreads across *all* k3s server pods — usually still the
    /// desired effect; if you ever need pool-scoped spread, the agent's
    /// existing `SameHost` co-location keeps each pool member's
    /// server+agent paired regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spread: Option<InstanceSpread>,
}

/// Placement mode for `NodePlacement`. New variants can be added without
/// changing the parent struct's shape on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum NodePlacementMode {
    /// Scheduler picks any eligible node independently for each pod.
    #[default]
    Any,
    /// Force agent pods to schedule on the same physical host as the
    /// server, using a required `kubernetes.io/hostname` podAffinity.
    /// Useful when cross-host pod routing on the underlying cluster is
    /// unreliable.
    SameHost,
}

/// Strength of the inter-instance spread constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum InstanceSpread {
    /// `preferredDuringSchedulingIgnoredDuringExecution` with weight=100.
    /// Soft hint — the scheduler tries to spread but falls back to
    /// co-location when no other host has capacity. Safe on single-host
    /// clusters (still schedules).
    Preferred,
    /// `requiredDuringSchedulingIgnoredDuringExecution`. Hard constraint:
    /// at most one pool member per host. Pods stay Pending when the
    /// number of eligible hosts is less than the pool size — only set
    /// this when `hosts >= maxClusters`.
    Required,
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

impl ResourceRequirements {
    /// Convert to the `k8s_openapi` shape expected by Container specs.
    ///
    /// `None` is returned when both maps are empty — that lets the
    /// caller use `..Default::default()` semantics (no `resources:` field
    /// emitted) instead of producing `{limits: {}, requests: {}}`.
    // `#[allow(dead_code)]` keeps the `crdgen` binary happy: it imports
    // this module purely to walk the JSON schema and never invokes
    // runtime-only methods (same reason `allocated_network` carries the
    // attribute one struct up).
    #[allow(dead_code)]
    pub fn to_k8s(&self) -> Option<k8s_openapi::api::core::v1::ResourceRequirements> {
        use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

        if self.limits.is_empty() && self.requests.is_empty() {
            return None;
        }
        let to_map = |m: &BTreeMap<String, String>| -> Option<BTreeMap<String, Quantity>> {
            if m.is_empty() {
                None
            } else {
                Some(
                    m.iter()
                        .map(|(k, v)| (k.clone(), Quantity(v.clone())))
                        .collect(),
                )
            }
        };
        Some(k8s_openapi::api::core::v1::ResourceRequirements {
            limits: to_map(&self.limits),
            requests: to_map(&self.requests),
            ..Default::default()
        })
    }
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

    /// End-to-end scheduling probe: lands a tiny pause Pod into the
    /// virtual cluster, waits for it to reach Running, then deletes
    /// it. Verifies the cluster is *usable* — not just that the
    /// apiserver responds — by exercising the full chain that any
    /// realistic workload depends on (scheduler → fake-node syncer
    /// → projected pod → host scheduler → host kubelet → status
    /// syncer). Catches the silent failure mode where a vkobe
    /// virtual cluster reports Healthy with zero schedulable nodes.
    ///
    /// `namespace` defaults to `kube-system` if unset — chosen because
    /// it's guaranteed to exist on every kube cluster and has its own
    /// `default` SA that pause needs to bind to.
    #[serde(rename = "SchedulingProbe")]
    SchedulingProbe {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
    },
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
                    "enum": [
                        "CRDExists",
                        "DeploymentReady",
                        "DaemonSetReady",
                        "URLHealthy",
                        "SchedulingProbe"
                    ]
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

// --- Enhancement: Rolling-upgrade policy ---

/// Rolling-upgrade policy for replacing pool members whose `spec_hash`
/// no longer matches the current profile hash (drift).
///
/// Drift comes from one of three places (see
/// [`crate::pool::profile_spec_hash`]): the user-visible ClusterPool
/// spec, an operator-level `RenderContext` bump (e.g.
/// `KOBE_SYNC_IMAGE`), or the resolved CONTENT of a referenced
/// `BootstrapConfig`. On each reconcile, instances whose recorded hash
/// differs are eligible for recycle; this policy bounds HOW MANY may
/// be recycled at once (`max_recycling`) and HOW MUCH temporary
/// surge above `min_ready` is acceptable (`max_surge`) so that even a
/// size-1 pool can upgrade with zero downtime.
///
/// Defaults preserve "rolling" semantics for any pool that did not
/// previously declare an explicit policy:
/// `max_recycling = 1`, `max_surge = 1`, `min_ready_during_upgrade =
/// min_ready` (or `spec.size`).
///
/// Unhealthy instances are NOT bounded by this policy — they are
/// always recycled immediately because they contribute zero capacity.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpgradePolicy {
    /// Maximum number of drifted instances to recycle in a single
    /// reconcile pass. Recycle order is oldest-first
    /// (`state_since` ascending) so the longest-lived stale instances
    /// rotate out first. Set to **0 to pause** drift recycling
    /// entirely — drift is still detected and surfaced in metrics
    /// but no `Delete` actions are emitted. Useful as a kill switch
    /// when a bad upgrade is in progress and you want to stop the
    /// rollout without redeploying the operator. Default 1.
    #[schemars(
        description = "Maximum drifted instances to recycle per reconcile. Set to 0 to pause drift recycling. Default 1."
    )]
    #[serde(default = "default_max_recycling")]
    pub max_recycling: u32,

    /// Temporary capacity surge allowed above `min_ready` (or
    /// `spec.size`) while a rolling upgrade is in progress. The
    /// scale-up branch will overshoot the warm target by up to this
    /// many extra clusters when at least one drifted Ready candidate
    /// is in flight, so a size-1 pool can stand up the replacement
    /// BEFORE deleting the old member. Default 1.
    #[schemars(
        description = "Extra clusters allowed above min_ready during rolling upgrade. Enables zero-downtime upgrade for size-1 pools. Default 1."
    )]
    #[serde(default = "default_max_surge")]
    pub max_surge: u32,

    /// Floor on **total Ready** (instances accepting claims, regardless
    /// of whether they're on the current or stale `spec_hash`)
    /// maintained during drift recycling. The recycle step refuses
    /// to emit a `Delete` when doing so would drop total Ready below
    /// this floor.
    ///
    /// "Total Ready" matches k8s `Deployment.maxUnavailable`
    /// semantics — a drifted Ready still serves claims, so the
    /// metric the operator should preserve during an upgrade is
    /// "clusters available right now," not "clusters on the latest
    /// version." Counting against current-hash-only would deadlock
    /// size-2 pools where `max_surge=1` only lands 1 clean
    /// replacement per cycle.
    ///
    /// When unset, defaults to `min_ready` (from `scaling.min_ready`,
    /// or `spec.size` for fixed pools): "never drop available
    /// capacity below the warm target."
    ///
    /// Set to `0` to recycle as fast as `max_recycling` allows
    /// regardless of available capacity — appropriate for pools that
    /// can tolerate brief downtime, or for emergency upgrades where
    /// speed matters more than capacity preservation.
    ///
    /// Setting this **higher** than `min_ready` is allowed but
    /// achieves nothing useful: the recycler will simply never act
    /// because the floor cannot be satisfied with the existing pool.
    #[schemars(
        description = "Floor on total Ready instances during upgrade. Defaults to min_ready (or spec.size). Set to 0 to recycle without a floor."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ready_during_upgrade: Option<u32>,
}

fn default_max_recycling() -> u32 {
    1
}
fn default_max_surge() -> u32 {
    1
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical user-configurable syncer list. Both
    /// `default_vkobe_syncers` (this module — operator writes it into
    /// the per-cluster ConfigMap) and
    /// `kobe_sync::config::default_syncers` (runtime sidecar fallback)
    /// must produce exactly this list. The two live in separate
    /// binaries (`kobe-operator` and `kobe-sync`) so they can't share
    /// a constant directly; instead, both modules independently
    /// assert against this hardcoded source-of-truth in their own
    /// tests.
    ///
    /// **`fake_nodes`, `status`, and `service_accounts` are NOT in
    /// this list** — they're infrastructural always-on syncers
    /// started unconditionally by `kobe_sync_bin::main`. Including
    /// them here would cause double-spawn (caught by the dedup in
    /// kobe-sync but cleaner to avoid).
    ///
    /// This pinning exists because of v0.22.0/v0.22.1 incidents
    /// where defaults drifted between the two modules and the
    /// operator silently shipped ConfigMaps missing `service_accounts`.
    /// Promoting `service_accounts` to always-on (PR #73) made the
    /// configurable default smaller again, and these tests were
    /// updated to match.
    pub(super) const CANONICAL_DEFAULT_VKOBE_SYNCERS: &[&str] = &[
        "pods",
        "services",
        "configmaps",
        "secrets",
        "endpoints",
        "ingresses",
    ];

    /// CRD-side default matches the canonical list. Mirror in
    /// `kobe_sync::config::tests::runtime_default_syncers_match_canonical`.
    #[test]
    fn default_vkobe_syncers_matches_canonical_list() {
        let actual = default_vkobe_syncers();
        let expected: Vec<String> = CANONICAL_DEFAULT_VKOBE_SYNCERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            actual, expected,
            "default_vkobe_syncers drifted from the canonical list. \
             Update both this module and kobe_sync::config to match \
             — they're written by the operator and read by the \
             sidecar respectively, drift silently disables a syncer."
        );
    }
}
