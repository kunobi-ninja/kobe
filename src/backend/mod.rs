pub mod capi;
pub mod datastore;
pub mod k0s;
pub mod k3s;
pub mod vcluster;
pub mod vkobe;

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{
    NodeAffinity, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, PodAffinityTerm, PodAntiAffinity, Secret,
    VolumeResourceRequirements, WeightedPodAffinityTerm,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, Config, ResourceExt};
use tracing::{debug, info, warn};

use crate::crd::{
    Addon, BackendType, BootstrapConfig, BootstrapJobSpec, BootstrapRef, ClusterConfig,
    ClusterPool, InterInstanceSpread, PersistenceConfig, ReadinessGate, SpreadStrength,
};

pub use capi::CapiBackend;
pub use k0s::K0sBackend;
pub use k3s::K3sBackend;
pub use vcluster::VclusterBackend;
pub use vkobe::VkobeBackend;

/// Allowed URL schemes for addon manifests and readiness probes.
const ALLOWED_SCHEMES: &[&str] = &["https"];

/// Label value identifying resources managed by the kobe-operator.
/// Mirrored in the per-backend modules; kept here so the
/// inter-instance anti-affinity selector below is consistent across
/// backends.
const MANAGED_BY: &str = "kobe-operator";

// ─────────────────────────────────────────────────────────────────────
// Placement rendering helpers shared by k3s and k0s backends.
// ─────────────────────────────────────────────────────────────────────

/// Convert a [`LabelSelector`] from `placement.node.selector` into the
/// equivalent `nodeAffinity.required` block.
///
/// `matchLabels` entries become `In`-operator [`NodeSelectorRequirement`]s
/// and merge with `matchExpressions` into a single [`NodeSelectorTerm`]
/// (logical AND across all requirements). Returns `None` for an
/// empty/absent selector so callers don't emit an empty
/// `nodeAffinity:` block.
pub(crate) fn node_affinity_from_selector(
    selector: Option<&LabelSelector>,
) -> Option<NodeAffinity> {
    let sel = selector?;
    let mut requirements: Vec<NodeSelectorRequirement> = Vec::new();
    if let Some(labels) = sel.match_labels.as_ref() {
        for (k, v) in labels {
            requirements.push(NodeSelectorRequirement {
                key: k.clone(),
                operator: "In".to_string(),
                values: Some(vec![v.clone()]),
            });
        }
    }
    if let Some(exprs) = sel.match_expressions.as_ref() {
        for e in exprs {
            requirements.push(NodeSelectorRequirement {
                key: e.key.clone(),
                operator: e.operator.clone(),
                values: e.values.clone(),
            });
        }
    }
    if requirements.is_empty() {
        return None;
    }
    Some(NodeAffinity {
        required_during_scheduling_ignored_during_execution: Some(NodeSelector {
            node_selector_terms: vec![NodeSelectorTerm {
                match_expressions: Some(requirements),
                ..Default::default()
            }],
        }),
        ..Default::default()
    })
}

/// Build the `podAntiAffinity` used for inter-instance pool-member
/// spread. The selector scopes to siblings of the SAME pool when
/// `pool_name` is provided (the normal pool-managed case), and falls
/// back to all kobe-operator-managed server pods when `None` (standalone
/// instances that opt into spread — there's no pool to anti-affine
/// against, so the soft fallback is the only sensible behavior).
///
/// Pool-scoping matters for `SpreadStrength::Required`: without it,
/// setting `Required` on two pools sharing a host cluster causes
/// cross-pool anti-affinity that can deadlock scheduling.
///
/// Rendering is identical for k3s and k0s backends, which is why this
/// lives in the shared module.
pub(crate) fn server_anti_affinity_terms(
    spread: Option<&InterInstanceSpread>,
    pool_name: Option<&str>,
) -> Option<PodAntiAffinity> {
    let s = spread?;
    let mut selector_labels = std::collections::BTreeMap::new();
    selector_labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        MANAGED_BY.to_string(),
    );
    selector_labels.insert("kobe.kunobi.ninja/role".to_string(), "server".to_string());
    if let Some(p) = pool_name {
        selector_labels.insert("kobe.kunobi.ninja/pool".to_string(), p.to_string());
    }

    let term = PodAffinityTerm {
        label_selector: Some(LabelSelector {
            match_labels: Some(selector_labels),
            ..Default::default()
        }),
        topology_key: s.topology_key.clone(),
        ..Default::default()
    };

    Some(match s.strength {
        SpreadStrength::Preferred => PodAntiAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![
                WeightedPodAffinityTerm {
                    weight: 100,
                    pod_affinity_term: term,
                },
            ]),
            ..Default::default()
        },
        SpreadStrength::Required => PodAntiAffinity {
            required_during_scheduling_ignored_during_execution: Some(vec![term]),
            ..Default::default()
        },
    })
}

// ─────────────────────────────────────────────────────────────────────
// Persistence helper shared by k3s and k0s backends.
// ─────────────────────────────────────────────────────────────────────

/// Default size for the control-plane data PVC when
/// [`PersistenceConfig::storage_request_size`] is omitted.
pub(crate) const DEFAULT_PERSISTENCE_SIZE: &str = "10Gi";

/// Build the StatefulSet `volumeClaimTemplates` entry that backs the named
/// control-plane data volume with a real PVC.
///
/// Maps [`PersistenceConfig`] onto a `ReadWriteOnce` PVC:
/// - `storage_class_name` → `spec.storageClassName` (omitted ⇒ cluster default)
/// - `storage_request_size` → `spec.resources.requests.storage`
///   (omitted ⇒ [`DEFAULT_PERSISTENCE_SIZE`])
///
/// The template's `metadata.name` MUST match the pod's `VolumeMount.name` so
/// the StatefulSet controller wires the per-replica PVC into the mount that
/// sits at the distro's real data dir (`/var/lib/rancher/k3s` for k3s,
/// `/var/lib/k0s` for k0s). Without this the data volume was an `emptyDir`
/// and control-plane state was lost on every reschedule.
pub(crate) fn data_volume_claim_template(
    volume_name: &str,
    persistence: &PersistenceConfig,
) -> PersistentVolumeClaim {
    let size = persistence
        .storage_request_size
        .clone()
        .unwrap_or_else(|| DEFAULT_PERSISTENCE_SIZE.to_string());

    let mut requests = BTreeMap::new();
    requests.insert("storage".to_string(), Quantity(size));

    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(volume_name.to_string()),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            storage_class_name: persistence.storage_class_name.clone(),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

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
    Vcluster(VclusterBackend),
}

impl ClusterBackend for BackendDispatch {
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        owner_ref: Option<&OwnerReference>,
    ) -> Result<()> {
        match self {
            Self::K3s(b) => b.create(name, namespace, config, addons, owner_ref).await,
            Self::K0s(b) => b.create(name, namespace, config, addons, owner_ref).await,
            Self::Capi(b) => b.create(name, namespace, config, addons, owner_ref).await,
            Self::Vkobe(b) => b.create(name, namespace, config, addons, owner_ref).await,
            Self::Vcluster(b) => b.create(name, namespace, config, addons, owner_ref).await,
        }
    }

    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        match self {
            Self::K3s(b) => b.delete(name, namespace).await,
            Self::K0s(b) => b.delete(name, namespace).await,
            Self::Capi(b) => b.delete(name, namespace).await,
            Self::Vkobe(b) => b.delete(name, namespace).await,
            Self::Vcluster(b) => b.delete(name, namespace).await,
        }
    }

    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        match self {
            Self::K3s(b) => b.check_health(name, namespace).await,
            Self::K0s(b) => b.check_health(name, namespace).await,
            Self::Capi(b) => b.check_health(name, namespace).await,
            Self::Vkobe(b) => b.check_health(name, namespace).await,
            Self::Vcluster(b) => b.check_health(name, namespace).await,
        }
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        match self {
            Self::K3s(b) => b.extract_kubeconfig(name, namespace).await,
            Self::K0s(b) => b.extract_kubeconfig(name, namespace).await,
            Self::Capi(b) => b.extract_kubeconfig(name, namespace).await,
            Self::Vkobe(b) => b.extract_kubeconfig(name, namespace).await,
            Self::Vcluster(b) => b.extract_kubeconfig(name, namespace).await,
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
            Self::Vcluster(b) => b.check_readiness_gate(name, namespace, gate).await,
        }
    }

    async fn apply_addon(&self, name: &str, namespace: &str, addon: &Addon) -> Result<()> {
        match self {
            Self::K3s(b) => b.apply_addon(name, namespace, addon).await,
            Self::K0s(b) => b.apply_addon(name, namespace, addon).await,
            Self::Capi(b) => b.apply_addon(name, namespace, addon).await,
            Self::Vkobe(b) => b.apply_addon(name, namespace, addon).await,
            Self::Vcluster(b) => b.apply_addon(name, namespace, addon).await,
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
    datastore: datastore::SharedDatastore,
}

impl BackendFactory {
    pub fn new(client: Client, datastore: datastore::SharedDatastore) -> Self {
        Self { client, datastore }
    }

    /// Produce the right backend for a pool based on its `spec.backend.backend_type`.
    pub fn backend_for(&self, profile: &ClusterPool) -> Result<BackendDispatch> {
        match profile.spec.backend.backend_type {
            BackendType::K3s => Ok(BackendDispatch::K3s(K3sBackend::new(
                self.client.clone(),
                self.datastore.clone(),
            ))),
            BackendType::K0s => Ok(BackendDispatch::K0s(K0sBackend::new(
                self.client.clone(),
                self.datastore.clone(),
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
            BackendType::Vcluster => Ok(BackendDispatch::Vcluster(VclusterBackend::new(
                self.client.clone(),
                profile.spec.backend.vcluster.clone(),
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
    ///
    /// `owner_ref` should be the parent `ClusterInstance`'s
    /// [`OwnerReference`]. When supplied, backends MUST stamp it on
    /// every namespaced child resource they create so that k8s
    /// garbage collection reaps the children if the parent CR is
    /// deleted out-of-band — defense in depth on top of the
    /// explicit `delete` path. Cluster-scoped resources cannot have
    /// a namespaced owner; backends fall back to the explicit
    /// delete path for those.
    ///
    /// Pass `None` from contexts where the parent CR isn't
    /// available (test mocks, ad-hoc tools). Backends that consult
    /// the field treat `None` as "skip the OwnerRef" — no GC fallback,
    /// but the explicit delete still works.
    fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        owner_ref: Option<&OwnerReference>,
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
///
/// `instance_name` is the parent ClusterInstance's name (e.g.
/// `pool-ci-vkobe-flux-409`). Currently used only by the
/// [`ReadinessGate::SchedulingProbe`] branch to scope the probe Pod
/// name per-instance — a fixed pod name collides on the host
/// namespace when multiple vkobe instances each project their own
/// `kube-system/kobe-readiness-probe` to the shared host pool
/// namespace under the standard `<name>-x-<vns>-x-vc` translation.
pub async fn check_readiness_gate_impl(
    vc_client: &Client,
    gate: &ReadinessGate,
    instance_name: &str,
) -> Result<bool> {
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
        ReadinessGate::SchedulingProbe { namespace } => {
            check_scheduling_probe(vc_client, namespace.as_deref(), instance_name).await
        }
    }
}

/// Default namespace for the scheduling-probe pod.
const PROBE_NAMESPACE_DEFAULT: &str = "kube-system";

/// Probe pod name prefix. The full name is
/// `kobe-readiness-probe-<instance_name>` so each ClusterInstance's
/// virtual probe projects to a unique host-side name under the
/// standard `<name>-x-<vns>-x-vc` translation. A fixed name collides
/// on the host namespace when multiple instances project the same
/// `kube-system/kobe-readiness-probe` virtual pod, leaving an orphan
/// host pod indefinitely (observed live on an internal cluster: a
/// `kobe-readiness-probe-x-kube-system-x-vc` host pod alive 2.5h
/// while the source virtual instance had been recycled long ago).
const PROBE_POD_NAME_PREFIX: &str = "kobe-readiness-probe";

/// Probe image: a tiny, versioned pause that any kube cluster can
/// pull (registry.k8s.io is built into the kubelet's default
/// allowlist; pause is ~700KB).
const PROBE_IMAGE: &str = "registry.k8s.io/pause:3.10";

/// Field manager attribution for SSA on the probe pod.
const PROBE_FIELD_MANAGER: &str = "kobe-operator/scheduling-probe";

/// Run the [`ReadinessGate::SchedulingProbe`] check against a
/// virtual cluster.
///
/// Returns `true` once the probe pod has been observed `Running`,
/// which proves the cluster is end-to-end usable: scheduler can
/// place the pod, a (fake or real) node accepts it, the kubelet
/// pulls + starts pause, and the apiserver flows status back. A
/// vkobe pool with `service_accounts` syncing broken or no fake
/// nodes can never satisfy this gate, so it stays `Creating` until
/// the existing stuck-Creating timeout recycles it.
///
/// Lifecycle, called once per reconcile while the instance is in
/// `Creating` phase:
/// - probe pod absent → create it, return `false` (controller
///   requeues). On the next call we observe the pod's status.
/// - probe pod exists, phase != `Running` → return `false`.
/// - probe pod exists, phase == `Running` → delete it (best
///   effort), return `true`. The instance flips to `Ready`; the
///   gate is no longer evaluated until the next recycle.
///
/// Idempotent: repeated calls with the pod absent re-create it
/// (the previous run's delete completed). Repeated calls with the
/// pod present and not-yet-Running just re-poll status.
async fn check_scheduling_probe(
    vc_client: &Client,
    namespace: Option<&str>,
    instance_name: &str,
) -> Result<bool> {
    use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::api::{DeleteParams, PatchParams};

    let ns = namespace.unwrap_or(PROBE_NAMESPACE_DEFAULT);
    // Per-instance probe name. The standard host-side translation
    // `<name>-x-<vns>-x-vc` (see kobe_sync's PodSyncer) takes the
    // virtual pod name verbatim, so a fixed virtual name produces a
    // shared host name across every vkobe instance in the same pool
    // namespace. Embedding the cluster instance gives unique host
    // pods like `kobe-readiness-probe-<instance>-x-kube-system-x-vc`,
    // avoiding the orphan-pod accumulation observed live (a host
    // probe pod alive 2.5h while its source virtual instance had
    // long since been recycled, blocking any new instance's probe
    // from projecting cleanly).
    let probe_pod_name = format!("{PROBE_POD_NAME_PREFIX}-{instance_name}");
    let pods: Api<Pod> = Api::namespaced(vc_client.clone(), ns);

    match pods.get(&probe_pod_name).await {
        Ok(pod) => {
            let phase = pod
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("");
            if phase == "Running" {
                debug!(
                    namespace = ns,
                    probe = %probe_pod_name,
                    "scheduling probe Running — gate satisfied, cleaning up"
                );
                // Best-effort delete: failure here doesn't break the
                // gate (the pod is harmless once we've observed
                // Running, and the next recycle of the cluster
                // tears the whole virtual apiserver down anyway).
                if let Err(e) = pods.delete(&probe_pod_name, &DeleteParams::default()).await {
                    debug!(
                        error = %e,
                        "scheduling probe cleanup failed; non-fatal"
                    );
                }
                Ok(true)
            } else {
                debug!(
                    namespace = ns,
                    probe = %probe_pod_name,
                    phase = phase,
                    "scheduling probe not yet Running"
                );
                Ok(false)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // Create the probe pod via SSA so concurrent reconciles
            // don't 409 on each other.
            let probe = Pod {
                metadata: ObjectMeta {
                    name: Some(probe_pod_name.clone()),
                    namespace: Some(ns.to_string()),
                    labels: Some(BTreeMap::from_iter([(
                        "app.kubernetes.io/managed-by".to_string(),
                        "kobe-operator".to_string(),
                    )])),
                    ..Default::default()
                },
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "pause".to_string(),
                        image: Some(PROBE_IMAGE.to_string()),
                        ..Default::default()
                    }],
                    // Tolerations / nodeSelector / SA all default.
                    // The probe is meant to be the simplest pod the
                    // cluster could possibly schedule — any of those
                    // knobs would risk this passing while a slightly
                    // less default workload still failed.
                    ..Default::default()
                }),
                status: None,
            };
            match pods
                .patch(
                    &probe_pod_name,
                    &PatchParams::apply(PROBE_FIELD_MANAGER).force(),
                    &kube::api::Patch::Apply(&probe),
                )
                .await
            {
                Ok(_) => {
                    debug!(
                        namespace = ns,
                        probe = %probe_pod_name,
                        "scheduling probe pod created — re-check on next reconcile"
                    );
                    Ok(false)
                }
                Err(kube::Error::Api(ae))
                    if ae.code == 403
                        && ae.message.contains("serviceaccount")
                        && ae.message.contains("not found") =>
                {
                    // Race: the virtual KCM hasn't yet created the
                    // namespace's `default` ServiceAccount that pod
                    // admission validates. KCM's serviceaccount
                    // controller runs ~30-60s after a fresh apiserver
                    // comes up; the operator's gate evaluation can fire
                    // before then. Treat as transient — the next
                    // reconcile retries and eventually succeeds once
                    // the SA exists. Error chain captured live on
                    // an internal cluster: every fresh ci-vkobe-flux
                    // instance hit this for the first ~30s of its
                    // lifetime, blocking the gate even though it would
                    // pass naturally a moment later.
                    debug!(
                        namespace = ns,
                        probe = %probe_pod_name,
                        message = %ae.message,
                        "scheduling probe waiting for default SA — retry next reconcile"
                    );
                    Ok(false)
                }
                Err(e) => Err(anyhow::Error::from(e)).with_context(|| {
                    format!("Failed to create scheduling-probe pod in namespace {ns}")
                }),
            }
        }
        Err(e) => Err(e.into()),
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
    yaml_entries.sort_by_key(|(left, _)| *left);

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

    // === SchedulingProbe gate ===

    /// First call: probe pod absent → operator creates it via SSA
    /// (PATCH with field-manager) and returns `false` so the
    /// controller requeues.
    #[tokio::test]
    async fn scheduling_probe_creates_pod_and_returns_false_when_absent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        // GET /api/v1/namespaces/<ns>/pods/<probe> → 404
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status",
                "code": 404,
                "message": "pods \"kobe-readiness-probe\" not found"
            })))
            .mount(&server)
            .await;

        // PATCH (apply) creates the pod
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "kobe-readiness-probe-test-instance",
                    "namespace": "kube-system"
                },
                "spec": { "containers": [] }
            })))
            .mount(&server)
            .await;

        let result = check_scheduling_probe(&client, None, "test-instance")
            .await
            .unwrap();
        assert!(
            !result,
            "first call must return false — pod created, status not yet observable"
        );
    }

    /// Pod exists but phase != "Running" → return false. The
    /// controller will keep requeueing while the pod boots.
    #[tokio::test]
    async fn scheduling_probe_returns_false_when_pod_pending() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": { "name": "kobe-readiness-probe-test-instance", "namespace": "kube-system" },
                "spec": { "containers": [{ "name": "pause", "image": "registry.k8s.io/pause:3.10" }] },
                "status": { "phase": "Pending" }
            })))
            .mount(&server)
            .await;

        let result = check_scheduling_probe(&client, None, "test-instance")
            .await
            .unwrap();
        assert!(
            !result,
            "Pending pod must not satisfy the gate — only Running counts as proof of scheduling"
        );
    }

    /// Pod has reached Running → gate returns `true` and the
    /// operator best-effort-deletes the probe so it doesn't sit
    /// idle in the cluster forever.
    #[tokio::test]
    async fn scheduling_probe_returns_true_and_cleans_up_when_running() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": { "name": "kobe-readiness-probe-test-instance", "namespace": "kube-system" },
                "spec": { "containers": [{ "name": "pause", "image": "registry.k8s.io/pause:3.10" }] },
                "status": { "phase": "Running" }
            })))
            .mount(&server)
            .await;

        // DELETE — must be called as part of cleanup. We assert via
        // the wiremock expectations check below.
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "Status",
                "status": "Success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = check_scheduling_probe(&client, None, "test-instance")
            .await
            .unwrap();
        assert!(
            result,
            "Running pod proves the cluster is scheduling end-to-end → gate satisfied"
        );
    }

    /// Custom namespace flows through to the apiserver path. The
    /// default is `kube-system`, but the user can override per gate.
    #[tokio::test]
    async fn scheduling_probe_honors_custom_namespace() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/probe-ns/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/probe-ns/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": { "name": "kobe-readiness-probe-test-instance", "namespace": "probe-ns" },
                "spec": { "containers": [] }
            })))
            .mount(&server)
            .await;

        // Wiremock will fail the test if the operator hits a
        // different path (e.g. kube-system instead of probe-ns).
        let result = check_scheduling_probe(&client, Some("probe-ns"), "test-instance")
            .await
            .unwrap();
        assert!(!result);
    }

    /// When the apiserver rejects probe-pod creation with a 403 +
    /// "serviceaccount ... not found" message, the gate must return
    /// `Ok(false)` (transient — retry next reconcile) rather than
    /// `Err`. The KCM serviceaccount-controller takes 30-60s after a
    /// fresh apiserver to populate every namespace's `default` SA;
    /// the gate evaluating in that window otherwise crashed every
    /// vkobe instance for its first ~30s of life until the eventual
    /// stuck-Creating timeout recycled it.
    #[tokio::test]
    async fn scheduling_probe_tolerates_default_sa_not_yet_created() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        // GET → 404, then PATCH → 403 with the exact message k8s
        // emits when the namespace's default SA hasn't been created
        // by KCM's serviceaccount-controller yet.
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/kube-system/pods/kobe-readiness-probe-test-instance",
            ))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status",
                "status": "Failure",
                "code": 403,
                "reason": "Forbidden",
                "message": "pods \"kobe-readiness-probe-test-instance\" is forbidden: error looking up service account kube-system/default: serviceaccount \"default\" not found"
            })))
            .mount(&server)
            .await;

        let result = check_scheduling_probe(&client, None, "test-instance").await;
        assert!(
            matches!(result, Ok(false)),
            "SA-not-yet-created 403 must return Ok(false) (transient), got {result:?}"
        );
    }
}
