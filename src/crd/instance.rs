use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    Addon, BackendConfig, BootstrapRef, ClusterConfig, HealthCheckConfig, ReadinessGate,
    SnapshotConfig,
};

/// Reference to another Kobe-managed resource in the same namespace.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    pub name: String,
}

/// ClusterInstance is the authoritative inventory record for one provisioned cluster.
///
/// Instances may be pool-managed (`spec.poolRef` present) or standalone
/// (`spec.poolRef` omitted). Backend-specific resources are implementation
/// details owned by the reconciler for this instance.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterInstance",
    plural = "clusterinstances",
    shortname = "ci",
    status = "ClusterInstanceStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInstanceSpec {
    /// Optional owning pool. When absent, this instance is standalone.
    #[serde(default)]
    pub pool_ref: Option<ResourceRef>,

    /// Standalone backend configuration. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub backend: Option<BackendConfig>,

    /// Standalone cluster configuration. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,

    /// Standalone addons. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub addons: Vec<Addon>,

    /// Standalone bootstraps. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub bootstraps: Vec<BootstrapRef>,

    /// Standalone health-check configuration. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Standalone readiness gates. Pool-managed instances derive this from the pool.
    #[serde(default)]
    pub readiness_gates: Vec<ReadinessGate>,

    /// Optional standalone snapshot/restore configuration.
    #[serde(default)]
    pub snapshot: Option<SnapshotConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum ClusterInstancePhase {
    #[default]
    Creating,
    Ready,
    Leased,
    Recycling,
    Unhealthy,
    Failed,
}

/// Network ranges reserved for one ClusterInstance.
///
/// Allocated once at create time by the instance controller and recorded
/// on `status.network` so two pool members never claim the same IP space
/// — the operator picks the next free slot by reading the CIDRs already
/// in use across sibling ClusterInstances. This makes peer-to-peer
/// networking between leased clusters possible without manual CIDR
/// override and prevents the host-cluster routing collision that
/// silently broke CoreDNS in early k3s pools (the `kubernetes` Service
/// IP overlapping with the host's iptables rules → in-cluster
/// `kubernetes.default.svc` resolved to the host apiserver, not the
/// leased one).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInstanceNetwork {
    /// CIDR for in-cluster Service ClusterIPs (`--service-cidr` to k3s,
    /// `serviceCIDR` to k0s, etc.).
    pub service_cidr: String,
    /// CIDR for in-cluster pod IPs (`--cluster-cidr` to k3s,
    /// `podCIDR` to k0s, etc.).
    pub cluster_cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInstanceStatus {
    #[serde(default)]
    pub phase: ClusterInstancePhase,

    /// Whether backend resources have been provisioned for this instance.
    #[serde(default)]
    pub provisioned: bool,

    /// Whether all configured bootstrap steps have completed successfully.
    #[serde(default)]
    pub bootstrapped: bool,

    /// Lease currently attached to this instance.
    #[serde(default)]
    pub lease_ref: Option<ResourceRef>,

    /// Bootstrap currently running for this instance, if any.
    #[serde(default)]
    pub active_bootstrap: Option<String>,

    /// When the instance became idle and eligible for scale-down.
    #[serde(default)]
    pub idle_since: Option<String>,

    /// When the instance entered its current phase.
    #[serde(default)]
    pub state_since: Option<String>,

    /// Consecutive health failures observed for this instance.
    #[serde(default)]
    pub health_failures: u32,

    /// Hash of the pool spec that created this instance, used for drift
    /// detection.
    ///
    /// `String` (not `u64`/`i64`): Kubernetes' OpenAPI structural schema
    /// validator parses numeric values through `float64` and rejects integers
    /// outside JSON's safe range (±2⁵³−1) with
    /// `Invalid value: "number": specHash in body must be of type integer`.
    /// Encoding as a fixed-width hex string sidesteps the precision problem
    /// without throwing away any of the 64 bits of hash entropy. Same pattern
    /// Kubernetes uses for `metadata.resourceVersion`. See
    /// `pool::profile_spec_hash` for the encoding (`{:016x}` of a `u64`).
    /// Equality comparison works directly via `==` on the string form.
    ///
    /// `skip_serializing_if` is critical: this field is owned by the profile
    /// controller (which writes `Some(...)` once at create time and on
    /// subsequent reconciles), but the instance controller carries it through
    /// every status patch via `spec_hash: status.spec_hash`. If the instance
    /// controller's `status` read happens before the profile controller's
    /// write, it holds `None` locally — and a JSON Merge Patch carrying
    /// `"specHash": null` would *remove* the field from disk per RFC 7396.
    /// Skipping serialization on `None` makes the field absent from the JSON
    /// instead, which JSON Merge Patch interprets as "preserve on-disk
    /// value" — closing the race regardless of which controller wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<String>,

    /// Network ranges reserved for this instance (service + cluster CIDRs).
    /// Allocated once before the backend StatefulSet/Deployment is built;
    /// `None` until the instance controller's first reconcile picks a
    /// free slot. Backends that own their own network plane (k3s, k0s)
    /// MUST consume these values rather than hardcoded defaults.
    /// Backends that reuse the host's network (vkobe) ignore this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ClusterInstanceNetwork>,
}
