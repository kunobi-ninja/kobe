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
    ///
    /// Intentionally NO `skip_serializing_if`: unlike the write-once
    /// `spec_hash`/`created_with` fields, `lease_ref` is *actively managed* —
    /// set when a lease binds and written back to `None` to **clear** it when
    /// the lease is released/recycled. `None` is a meaningful "clear" signal,
    /// so it must serialize as `null` (the Merge-Patch delete) rather than be
    /// omitted. Adding `skip_serializing_if` here would make a released
    /// instance keep a stale `lease_ref` forever.
    #[serde(default)]
    pub lease_ref: Option<ResourceRef>,

    /// Bootstrap currently running for this instance, if any.
    // skip_serializing_if: informational only (read just for a failure-metric
    // label; never for control flow), so omitting None protects it from
    // cross-controller Merge-Patch erasure without affecting behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_bootstrap: Option<String>,

    /// When the instance became idle and eligible for scale-down.
    ///
    /// Intentionally NO `skip_serializing_if` (same reasoning as `lease_ref`):
    /// actively managed, not write-once. Set to `Some(now)` when the instance
    /// becomes idle and back to `None` to **clear** it the moment it stops
    /// being idle (leased, recycling, …). The `None`→`null` Merge-Patch delete
    /// is required; omitting it would leave a busy instance carrying a stale
    /// idle timestamp and corrupt the scale-down decision in `pool::manager`.
    #[serde(default)]
    pub idle_since: Option<String>,

    /// When the instance entered its current phase. Written `Some(now)` on
    /// every transition; never deliberately cleared, but kept without
    /// `skip_serializing_if` for consistency with the other actively-managed
    /// timestamp fields above.
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

    /// Provenance: which version of kobe stamped this `ClusterInstance`
    /// at creation time. Set once by the profile controller in
    /// `ensure_cluster_instance` and never overwritten. Future logic
    /// (rolling upgrade, drift detection by version, manual recycle
    /// triggers, …) compares this against the running operator's
    /// version to decide whether the instance is "stale".
    ///
    /// `None` for instances created by kobe < 0.17 — consumers should
    /// treat the absence as "unknown / pre-provenance" and decide
    /// per-policy whether to migrate or leave alone.
    ///
    /// `skip_serializing_if = "Option::is_none"` is critical here, same
    /// pattern as `spec_hash` above: every status patch from the
    /// instance controller constructs a fresh `ClusterInstanceStatus`
    /// where this field defaults to `None`. Without `skip_serializing_if`,
    /// the JSON Merge Patch would carry `"createdWith": null` and wipe
    /// the on-disk value (RFC 7396). Skipping the field on `None`
    /// preserves the original write through every subsequent patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_with: Option<ClusterInstanceProvenance>,

    /// Human-readable detail about the instance's current state — *why*
    /// it is in `phase`. Set fresh on every status write by the instance
    /// controller (each construction site supplies a concise phrase like
    /// `"provisioning backend resources"` or `"running bootstrap 'foo'"`),
    /// so it always describes the most recent transition rather than a
    /// stale value.
    ///
    /// `skip_serializing_if = "Option::is_none"` protects it from
    /// cross-controller Merge-Patch erasure, same pattern as `spec_hash`:
    /// a writer that leaves this `None` (e.g. the profile controller, or
    /// a "ready / no message" instance-controller path) must omit the key
    /// entirely, otherwise a JSON Merge Patch carrying `"message": null`
    /// would wipe the on-disk value (RFC 7396).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Standard Kubernetes-style status conditions, derived centrally by
    /// the instance controller from `phase` / `provisioned` /
    /// `bootstrapped` (see `derive_instance_conditions`). Currently
    /// emitted: `Provisioned`, `Ready`, `Bootstrapped`. These give
    /// `kubectl` and ops tooling a familiar, machine-readable surface for
    /// *why* the instance is where it is.
    ///
    /// `skip_serializing_if = "Vec::is_empty"` protects the list from
    /// cross-controller Merge-Patch erasure, same pattern as `spec_hash`:
    /// the profile controller (a separate status writer) re-emits status
    /// without conditions of its own, so an empty `Vec` must be omitted
    /// from the JSON entirely — otherwise a JSON Merge Patch carrying
    /// `"conditions": []` would replace the on-disk list with an empty
    /// one (RFC 7396 / array-replacement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ClusterInstanceCondition>,
}

/// One status condition on a `ClusterInstance`. Mirrors the core/v1
/// condition shape (type/status/reason/message/lastTransitionTime) — and
/// `KobeStoreCondition` — so kubectl and operators see a familiar
/// surface across all Kobe resources.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInstanceCondition {
    /// Condition name. Emitted values: `Provisioned`, `Ready`,
    /// `Bootstrapped`.
    #[serde(rename = "type")]
    pub condition_type: String,

    /// One of: `True`, `False`, `Unknown`.
    pub status: String,

    /// Machine-readable reason. For the `True` case this is the
    /// condition name (e.g. `Provisioned`); for the `False` case it is
    /// typically the current phase (e.g. `Creating`, `Failed`,
    /// `Recycling`) so operators can see at a glance what is blocking.
    pub reason: String,

    /// Human-readable detail, generally a copy of `status.message` for
    /// the current state (or empty when there is none).
    pub message: String,

    /// RFC3339 of the last status change. Updated only when `status`
    /// flips (True ↔ False ↔ Unknown), not on every reconcile, so tools
    /// tailing `kubectl get -w` see meaningful transitions rather than
    /// churn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

/// Provenance stamp written once at create time on
/// `ClusterInstanceStatus.created_with`. Captures the components of the
/// operator that produced this instance, so future reconcile logic can
/// detect "instance was created by an older kobe" without re-deriving
/// the answer from a complex hash.
///
/// Why not roll this into `spec_hash`?  The spec hash detects drift in
/// the user-facing config (`ClusterPool.spec`, render-context image,
/// referenced `BootstrapConfig` content). Provenance is orthogonal: it
/// captures the *operator* identity at create time, which can change
/// without any spec drift (e.g. `helm upgrade` to a kobe minor that
/// adds a new runtime requirement). Keeping them separate means each
/// can evolve without the other.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInstanceProvenance {
    /// Semver of the kobe-operator binary that created this instance,
    /// taken from `env!("CARGO_PKG_VERSION")` at create time. Example:
    /// `"0.17.0"`.
    pub operator_version: String,

    /// kobe-sync sidecar image used at create time. Recorded for
    /// `Vkobe` backends only (other backends don't run kobe-sync).
    /// Format matches the operator's `KOBE_SYNC_IMAGE` env var, e.g.
    /// `"zondax/kobe-sync:v0.16.0"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kobe_sync_image: Option<String>,

    /// Backend type the instance was provisioned with. Pinned at
    /// create time and never overwritten, so backend operations on the
    /// instance (delete, health probe, kubeconfig extraction, addon
    /// apply) always use the same backend that created the underlying
    /// host resources — even if `ClusterPool.spec.backend.type` drifts
    /// to a different backend mid-lifecycle (e.g., a vkobe→vcluster
    /// migration leaves existing vkobe-style instances with vkobe
    /// resources that must be torn down via the vkobe backend, not
    /// the new pool-level vcluster backend).
    ///
    /// `None` for instances created by kobe < 0.23.1 — consumers
    /// should fall back to `ClusterPool.spec.backend.type` for
    /// backward compatibility (the prior behavior). New instances
    /// always have this field populated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<crate::crd::BackendType>,
}
