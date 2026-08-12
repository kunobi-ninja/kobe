use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crd::{
    Addon, BackendConfig, BackendType, BootstrapRef, CapiConfig, ClusterConfig, HealthCheckConfig,
    ReadinessGate, SnapshotConfig,
};

/// Reference to another Kobe-managed resource in the same namespace.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    /// Resource name. Names are display and lookup handles, never sufficient
    /// authority on their own because Kubernetes permits name reuse.
    pub name: String,

    /// Kubernetes UID of the referenced object. New controller-written
    /// references always set this. `None` is accepted only so pre-UID-fence
    /// objects remain readable; security-sensitive consumers must fail closed
    /// or run the proof-based legacy migration before using the reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

/// Immutable, non-secret data needed to select the backend that created an
/// instance without trusting the owning pool's mutable current spec.
///
/// `config_digest` covers the complete serialized [`BackendConfig`], including
/// backend-specific settings, while this status record stores only the bounded
/// dispatch fields needed after creation. Secret *values* are never copied;
/// configuration may contain Secret names, and the digest reveals no raw
/// credential material.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackendProvenance {
    /// Backend implementation that created the instance.
    #[serde(rename = "type")]
    pub backend_type: BackendType,

    /// SHA-256 of the canonical JSON serialization of the complete backend
    /// configuration at creation/bind time. A changed pool backend therefore
    /// cannot silently redirect access or teardown.
    pub config_digest: String,

    /// CAPI discovery identity required to reconstruct delete dispatch.
    /// Provider `infrastructureSpec` is deliberately excluded because it may
    /// contain sensitive provider data and is not needed for dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capi: Option<CapiBackendProvenance>,
}

/// Non-secret CAPI resource identity needed to find the exact provider object
/// during backend dispatch and teardown.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapiBackendProvenance {
    pub infrastructure_api_version: String,
    pub infrastructure_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infrastructure_plural: Option<String>,
}

// The `crdgen` binary compiles `src/crd` on its own (it only needs the schema
// derives), so these two helpers — used by the controllers, the API, and
// `lease_binding` — look dead in that compilation unit. Scoped to this impl
// rather than the whole module so genuine dead code in `instance.rs` still
// surfaces under `-D warnings`.
#[allow(dead_code)]
impl BackendProvenance {
    /// Build immutable dispatch provenance from a pool backend configuration.
    /// Serialization failure is returned rather than replaced with a default:
    /// provenance is an authorization input, so uncertainty must fail closed.
    pub fn from_config(config: &BackendConfig) -> Result<Self, serde_json::Error> {
        let encoded = serde_json::to_vec(config)?;
        let config_digest = hex::encode(Sha256::digest(encoded));
        let capi = config.capi.as_ref().map(|capi| CapiBackendProvenance {
            infrastructure_api_version: capi.infrastructure_api_version.clone(),
            infrastructure_kind: capi.infrastructure_kind.clone(),
            infrastructure_plural: capi.infrastructure_plural.clone(),
        });

        Ok(Self {
            backend_type: config.backend_type.clone(),
            config_digest,
            capi,
        })
    }

    /// Reconstruct the minimal backend configuration needed for dispatch.
    /// Creation-only values are intentionally absent; this is used only after
    /// the resolver has matched the immutable provenance digest.
    pub fn dispatch_config(&self) -> Result<BackendConfig, &'static str> {
        let capi = match (&self.backend_type, &self.capi) {
            (BackendType::Capi, Some(capi)) => Some(CapiConfig {
                infrastructure_api_version: capi.infrastructure_api_version.clone(),
                infrastructure_kind: capi.infrastructure_kind.clone(),
                infrastructure_spec: None,
                infrastructure_plural: capi.infrastructure_plural.clone(),
            }),
            (BackendType::Capi, None) => return Err("capi_dispatch_missing"),
            (_, Some(_)) => return Err("unexpected_capi_dispatch"),
            (_, None) => None,
        };

        Ok(BackendConfig {
            backend_type: self.backend_type.clone(),
            datastore: None,
            capi,
            vkobe: None,
            vcluster: None,
        })
    }
}

/// Exact immutable identity of one lease-to-instance capability.
///
/// The same value is written to `ClusterLease.status.binding` and
/// `ClusterInstance.status.binding`. Every cross-object access or mutation must
/// validate the complete reciprocal record; `clusterName` and `leaseRef` are
/// compatibility/display fields only.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeaseBinding {
    /// Random immutable identifier unique to this reservation attempt.
    pub binding_id: String,
    pub lease: ResourceRef,
    pub instance: BoundInstanceRef,
    pub pool: ResourceRef,
    pub backend: BackendProvenance,
    /// Instance creation/spec digest observed when the pair was bound.
    pub instance_spec_digest: String,
}

/// UID- and generation-fenced identity of the bound `ClusterInstance`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BoundInstanceRef {
    pub name: String,
    pub uid: String,
    /// `metadata.generation` observed before reservation. Any later spec
    /// substitution invalidates the capability, even when name and UID remain.
    pub observed_generation: i64,
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
    /// Teardown could not be proven complete. Access stays revoked, finalizers
    /// and binding provenance are retained, and the unit is never Ready, never
    /// rebound, and never counted as clean replacement capacity. It may leave
    /// this phase only when the same exact subject produces a fully verified
    /// receipt.
    Quarantined,
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
    /// `spec_hash`/`created_with` fields, `lease_ref` is *actively managed*.
    /// It is set at bind, retained through release/recycling as a teardown
    /// handle, and cleared only when an exact orphan reservation is safely
    /// returned to Ready. `None` is therefore a meaningful clear signal and
    /// must serialize as `null` rather than be omitted.
    #[serde(default)]
    pub lease_ref: Option<ResourceRef>,

    /// Authoritative reciprocal lease binding. New bindings always set this
    /// before an instance enters `Leased`; it is retained through release and
    /// recycling until exact teardown deletes the instance. `None` exists only
    /// for legacy/unbound objects and is omitted from Merge Patches so unrelated
    /// status writers cannot erase a valid binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<LeaseBinding>,

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
    /// `None` for instances created by kobe < 0.23.1. New instances always
    /// populate it; security-sensitive access and teardown must fail closed
    /// when the stronger [`ClusterInstanceProvenance::backend`] is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<crate::crd::BackendType>,

    /// UID of the owning pool at instance creation. Missing on legacy or
    /// standalone instances; pool-managed security-sensitive operations must
    /// not infer it from a same-named current pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_uid: Option<String>,

    /// Immutable non-secret backend dispatch provenance captured at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendProvenance>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::BackendType;
    use kube::CustomResourceExt;
    use serde_json::json;

    /// A status with every field populated, used by the round-trip and
    /// key-shape tests below.
    fn populated_status() -> ClusterInstanceStatus {
        ClusterInstanceStatus {
            phase: ClusterInstancePhase::Leased,
            provisioned: true,
            bootstrapped: true,
            lease_ref: Some(ResourceRef {
                name: "lease-abc".into(),
                uid: None,
            }),
            binding: None,
            active_bootstrap: Some("flux".into()),
            idle_since: Some("2026-01-02T03:04:05Z".into()),
            state_since: Some("2026-01-02T03:04:06Z".into()),
            health_failures: 3,
            spec_hash: Some("0123456789abcdef".into()),
            network: Some(ClusterInstanceNetwork {
                service_cidr: "10.245.32.0/20".into(),
                cluster_cidr: "10.253.32.0/20".into(),
            }),
            created_with: Some(ClusterInstanceProvenance {
                operator_version: "0.37.0".into(),
                kobe_sync_image: Some("zondax/kobe-sync:v0.16.0".into()),
                backend_type: Some(BackendType::K0s),
                pool_uid: None,
                backend: None,
            }),
            message: Some("running bootstrap 'flux'".into()),
            conditions: vec![ClusterInstanceCondition {
                condition_type: "Ready".into(),
                status: "True".into(),
                reason: "Ready".into(),
                message: String::new(),
                last_transition_time: Some("2026-01-02T03:04:06Z".into()),
            }],
        }
    }

    // ── Merge-Patch semantics: actively-managed vs. write-once fields ──
    //
    // These four tests pin the `skip_serializing_if` policy documented on
    // `ClusterInstanceStatus`. Under RFC 7396 (JSON Merge Patch) an
    // explicit `null` DELETES the on-disk key while an ABSENT key
    // PRESERVES it. Getting the split wrong is silently destructive in
    // both directions, so each side gets its own test.

    /// `lease_ref`, `idle_since` and `state_since` are actively managed:
    /// the instance controller writes `None` to *clear* them. They must
    /// therefore serialize as explicit `null`, otherwise a released
    /// instance keeps a stale lease forever and the scale-down decision
    /// in `pool::manager` reads a stale idle timestamp.
    #[test]
    fn actively_managed_fields_serialize_none_as_explicit_null() {
        let status = ClusterInstanceStatus::default();
        let v = serde_json::to_value(&status).unwrap();

        for key in ["leaseRef", "idleSince", "stateSince"] {
            assert!(
                v.get(key).is_some(),
                "`{key}` must be present so a Merge Patch can CLEAR it; got: {v}"
            );
            assert!(
                v[key].is_null(),
                "`{key}` must serialize as explicit null (RFC 7396 delete); got: {}",
                v[key]
            );
        }
    }

    /// `spec_hash`, `created_with`, `message` and `active_bootstrap` are
    /// owned by another writer (the profile controller) or are purely
    /// informational. The instance controller round-trips them through
    /// every status patch, so a `None` MUST be omitted — emitting
    /// `"specHash": null` would wipe the profile controller's write
    /// whenever the instance controller loses the read/write race.
    #[test]
    fn write_once_fields_are_omitted_when_none_so_merge_patch_preserves_them() {
        let status = ClusterInstanceStatus::default();
        let v = serde_json::to_value(&status).unwrap();

        for key in [
            "specHash",
            "createdWith",
            "binding",
            "message",
            "activeBootstrap",
            "network",
        ] {
            assert!(
                v.get(key).is_none(),
                "`{key}` must be ABSENT when None so a Merge Patch preserves the on-disk value; got: {v}"
            );
        }
    }

    /// An empty condition list must be omitted rather than serialized as
    /// `[]`: JSON Merge Patch replaces arrays wholesale, so a status
    /// write from the profile controller (which never derives
    /// conditions) would otherwise erase the instance controller's list.
    #[test]
    fn empty_conditions_are_omitted_so_merge_patch_cannot_erase_them() {
        let empty = serde_json::to_value(ClusterInstanceStatus::default()).unwrap();
        assert!(
            empty.get("conditions").is_none(),
            "empty conditions must be omitted; got: {empty}"
        );

        let populated = serde_json::to_value(populated_status()).unwrap();
        assert_eq!(
            populated["conditions"].as_array().map(Vec::len),
            Some(1),
            "non-empty conditions must still serialize: {populated}"
        );
    }

    // ── Wire-format naming ────────────────────────────────────────────

    /// The stored CR is camelCase. Pin the exact key set of a fully
    /// populated status so a field rename (or a dropped
    /// `rename_all = "camelCase"`) can never silently orphan data
    /// already on disk.
    #[test]
    fn status_keys_are_camel_case() {
        let v = serde_json::to_value(populated_status()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "activeBootstrap",
                "bootstrapped",
                "conditions",
                "createdWith",
                "healthFailures",
                "idleSince",
                "leaseRef",
                "message",
                "network",
                "phase",
                "provisioned",
                "specHash",
                "stateSince",
            ]
        );
    }

    /// `ClusterInstanceSpec` is camelCase on the wire too. A snake_case
    /// key is silently ignored by serde, so an operator who hand-writes
    /// `pool_ref:` would get a standalone instance instead of a
    /// pool-managed one — pin the accepted spelling.
    #[test]
    fn spec_accepts_camel_case_keys_only() {
        let spec: ClusterInstanceSpec = serde_json::from_value(json!({
            "poolRef": { "name": "e2e-basic" },
            "healthCheck": { "intervalSeconds": 15 },
            "readinessGates": [ { "type": "NodesReady", "count": 1 } ],
        }))
        .unwrap();
        assert_eq!(
            spec.pool_ref.as_ref().map(|r| r.name.as_str()),
            Some("e2e-basic")
        );
        assert!(spec.health_check.is_some());
        assert_eq!(spec.readiness_gates.len(), 1);

        let snake: ClusterInstanceSpec =
            serde_json::from_value(json!({ "pool_ref": { "name": "e2e-basic" } })).unwrap();
        assert!(
            snake.pool_ref.is_none(),
            "snake_case keys are NOT part of the wire format and must not bind"
        );

        // …and the serialized form uses camelCase, so a spec read back
        // from the apiserver round-trips.
        let out = serde_json::to_value(&spec).unwrap();
        assert!(out.get("poolRef").is_some(), "got: {out}");
        assert!(out.get("healthCheck").is_some(), "got: {out}");
        assert!(out.get("readinessGates").is_some(), "got: {out}");
    }

    /// `ClusterInstanceNetwork` is consumed by the k3s/k0s backends
    /// straight off `status.network`. Pin the camelCase spelling of both
    /// CIDR keys — a rename would make every backend silently fall back
    /// to its hardcoded defaults and re-introduce the host-routing
    /// collision the allocator exists to prevent.
    #[test]
    fn network_cidrs_use_camel_case_keys_and_round_trip() {
        let net = ClusterInstanceNetwork {
            service_cidr: "10.245.32.0/20".into(),
            cluster_cidr: "10.253.32.0/20".into(),
        };
        let v = serde_json::to_value(&net).unwrap();
        assert_eq!(v["serviceCidr"], "10.245.32.0/20");
        assert_eq!(v["clusterCidr"], "10.253.32.0/20");

        let back: ClusterInstanceNetwork = serde_json::from_value(v).unwrap();
        assert_eq!(back, net);
    }

    /// The condition's Rust field is `condition_type` but the wire key
    /// must be `type` — that is what `kubectl`, `kubectl wait
    /// --for=condition=Ready` and every generic condition-reading tool
    /// look for. camelCase alone would render it as `conditionType`.
    #[test]
    fn condition_type_field_is_named_type_on_the_wire() {
        let cond = ClusterInstanceCondition {
            condition_type: "Ready".into(),
            status: "False".into(),
            reason: "Creating".into(),
            message: "provisioning backend resources".into(),
            last_transition_time: Some("2026-01-02T03:04:05Z".into()),
        };
        let v = serde_json::to_value(&cond).unwrap();
        assert_eq!(v["type"], "Ready");
        assert!(
            v.get("conditionType").is_none(),
            "must not leak the Rust field name: {v}"
        );
        assert_eq!(v["lastTransitionTime"], "2026-01-02T03:04:05Z");

        let back: ClusterInstanceCondition = serde_json::from_value(v).unwrap();
        assert_eq!(back, cond);
    }

    /// A condition that never transitioned omits `lastTransitionTime`
    /// entirely rather than writing `null`, so a later patch that does
    /// know the timestamp does not have to fight an on-disk null.
    #[test]
    fn condition_omits_last_transition_time_when_unset() {
        let cond = ClusterInstanceCondition {
            condition_type: "Bootstrapped".into(),
            status: "Unknown".into(),
            reason: "Creating".into(),
            message: String::new(),
            last_transition_time: None,
        };
        let v = serde_json::to_value(&cond).unwrap();
        assert!(
            v.get("lastTransitionTime").is_none(),
            "unset transition time must be omitted, not null: {v}"
        );
    }

    // ── Phase ─────────────────────────────────────────────────────────

    /// Phase is stored as a bare PascalCase string, and a freshly
    /// constructed status starts at `Creating` — the pool manager's
    /// stuck-instance timeout keys off exactly that value.
    #[test]
    fn phase_defaults_to_creating_and_round_trips_as_pascal_case() {
        assert_eq!(
            ClusterInstancePhase::default(),
            ClusterInstancePhase::Creating
        );

        let cases = [
            (ClusterInstancePhase::Creating, "Creating"),
            (ClusterInstancePhase::Ready, "Ready"),
            (ClusterInstancePhase::Leased, "Leased"),
            (ClusterInstancePhase::Recycling, "Recycling"),
            (ClusterInstancePhase::Unhealthy, "Unhealthy"),
            (ClusterInstancePhase::Failed, "Failed"),
        ];
        for (phase, wire) in cases {
            assert_eq!(serde_json::to_value(&phase).unwrap(), json!(wire));
            let back: ClusterInstancePhase = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, phase);
        }
    }

    // ── Provenance ────────────────────────────────────────────────────

    /// Provenance carries the two optional components only when they are
    /// known. `kobeSyncImage` is Vkobe-only and `backendType` did not
    /// exist before 0.23.1 — emitting `null` for either would write
    /// noise into every non-vkobe instance and, worse, wipe the value on
    /// a subsequent Merge Patch.
    #[test]
    fn provenance_omits_unknown_components() {
        let p = ClusterInstanceProvenance {
            operator_version: "0.37.0".into(),
            kobe_sync_image: None,
            backend_type: None,
            pool_uid: None,
            backend: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["operatorVersion"], "0.37.0");
        assert!(v.get("kobeSyncImage").is_none(), "got: {v}");
        assert!(v.get("backendType").is_none(), "got: {v}");
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    /// Instances stamped by kobe < 0.23.1 have no `backendType`. They must
    /// keep deserializing so the controller can surface/quarantine them; this
    /// compatibility does not authorize a security-sensitive fallback.
    #[test]
    fn provenance_from_pre_0_23_1_deserializes_without_backend_type() {
        let p: ClusterInstanceProvenance =
            serde_json::from_value(json!({ "operatorVersion": "0.17.0" })).unwrap();
        assert_eq!(p.operator_version, "0.17.0");
        assert!(p.backend_type.is_none());
        assert!(p.kobe_sync_image.is_none());
    }

    /// The pinned backend must survive the round trip verbatim — it is
    /// what decides which backend tears the instance down, so a
    /// mis-parse would leave orphaned host resources after a pool-level
    /// backend migration.
    #[test]
    fn provenance_backend_type_round_trips_for_every_backend() {
        for (bt, wire) in [
            (BackendType::K3s, "k3s"),
            (BackendType::K0s, "k0s"),
            (BackendType::Capi, "capi"),
            (BackendType::Vkobe, "vkobe"),
            (BackendType::Vcluster, "vcluster"),
        ] {
            let p = ClusterInstanceProvenance {
                operator_version: "0.37.0".into(),
                kobe_sync_image: None,
                backend_type: Some(bt),
                pool_uid: None,
                backend: None,
            };
            let v = serde_json::to_value(&p).unwrap();
            assert_eq!(v["backendType"], json!(wire));
            let back: ClusterInstanceProvenance = serde_json::from_value(v).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn backend_provenance_is_stable_and_never_copies_sensitive_config() {
        let config = BackendConfig {
            backend_type: BackendType::Capi,
            capi: Some(CapiConfig {
                infrastructure_api_version: "infra.example.io/v1".into(),
                infrastructure_kind: "SecretMachine".into(),
                infrastructure_plural: Some("secretmachines".into()),
                infrastructure_spec: Some(json!({
                    "password": "must-not-appear",
                    "token": "also-must-not-appear"
                })),
            }),
            ..Default::default()
        };
        let first = BackendProvenance::from_config(&config).unwrap();
        let second = BackendProvenance::from_config(&config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.config_digest.len(), 64);
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("must-not-appear"));
        assert!(!encoded.contains("also-must-not-appear"));
        assert!(encoded.contains("SecretMachine"));

        let dispatch = first.dispatch_config().unwrap();
        assert_eq!(dispatch.backend_type, BackendType::Capi);
        assert!(
            dispatch
                .capi
                .as_ref()
                .is_some_and(|capi| capi.infrastructure_spec.is_none())
        );
    }

    #[test]
    fn reciprocal_binding_wire_shape_contains_every_uid_fence() {
        let binding = LeaseBinding {
            binding_id: "binding-1".into(),
            lease: ResourceRef {
                name: "lease-a".into(),
                uid: Some("lease-uid".into()),
            },
            instance: BoundInstanceRef {
                name: "pool-a-0".into(),
                uid: "instance-uid".into(),
                observed_generation: 7,
            },
            pool: ResourceRef {
                name: "pool-a".into(),
                uid: Some("pool-uid".into()),
            },
            backend: BackendProvenance::from_config(&BackendConfig::default()).unwrap(),
            instance_spec_digest: "0123456789abcdef".into(),
        };
        let value = serde_json::to_value(&binding).unwrap();
        assert_eq!(value["bindingId"], "binding-1");
        assert_eq!(value["lease"]["uid"], "lease-uid");
        assert_eq!(value["instance"]["uid"], "instance-uid");
        assert_eq!(value["instance"]["observedGeneration"], 7);
        assert_eq!(value["pool"]["uid"], "pool-uid");
        assert_eq!(value["backend"]["type"], "k3s");
        assert_eq!(value["instanceSpecDigest"], "0123456789abcdef");
        assert_eq!(
            serde_json::from_value::<LeaseBinding>(value).unwrap(),
            binding
        );
    }

    // ── Compatibility ─────────────────────────────────────────────────

    /// A status written by kobe < 0.17 has no provenance, no network, no
    /// conditions and no message. It must still parse, defaulting the
    /// missing fields, or the operator would refuse to reconcile every
    /// instance created before the upgrade.
    #[test]
    fn status_from_older_kobe_deserializes_with_defaults() {
        let status: ClusterInstanceStatus = serde_json::from_value(json!({
            "phase": "Ready",
            "provisioned": true,
            "leaseRef": null,
            "healthFailures": 0
        }))
        .unwrap();

        assert_eq!(status.phase, ClusterInstancePhase::Ready);
        assert!(status.provisioned);
        assert!(!status.bootstrapped);
        assert!(status.lease_ref.is_none());
        assert!(status.created_with.is_none());
        assert!(status.network.is_none());
        assert!(status.message.is_none());
        assert!(status.conditions.is_empty());
    }

    /// An entirely empty status object must parse — during a rolling
    /// upgrade the operator reads CRs whose `status` subresource has not
    /// been written yet.
    #[test]
    fn status_deserializes_from_empty_object() {
        let status: ClusterInstanceStatus = serde_json::from_value(json!({})).unwrap();
        assert_eq!(status.phase, ClusterInstancePhase::Creating);
        assert_eq!(status.health_failures, 0);
        assert!(!status.provisioned);
        assert!(!status.bootstrapped);
    }

    /// Forward compatibility: during a rolling upgrade an older operator
    /// pod reads CRs written by the newer one. Unknown keys must be
    /// ignored, not rejected — `deny_unknown_fields` here would take the
    /// old replicas offline mid-upgrade.
    #[test]
    fn status_ignores_fields_written_by_a_newer_operator() {
        let status: ClusterInstanceStatus = serde_json::from_value(json!({
            "phase": "Ready",
            "someFutureField": { "nested": true },
            "anotherOne": 42
        }))
        .unwrap();
        assert_eq!(status.phase, ClusterInstancePhase::Ready);
    }

    /// Full serialize → deserialize → serialize must be a fixed point.
    /// Every status patch the instance controller issues is built from a
    /// value it just read back, so any lossy field would drift a little
    /// further on each reconcile.
    #[test]
    fn status_round_trips_through_json_without_loss() {
        let first = serde_json::to_value(populated_status()).unwrap();
        let parsed: ClusterInstanceStatus = serde_json::from_value(first.clone()).unwrap();
        let second = serde_json::to_value(&parsed).unwrap();
        assert_eq!(first, second);
    }

    /// `spec` round-trips too, including the `Vec` fields that default
    /// to empty and the options that default to `None`.
    #[test]
    fn spec_round_trips_through_json_without_loss() {
        let spec: ClusterInstanceSpec = serde_json::from_value(json!({
            "backend": { "type": "k0s" },
            "cluster": { "version": "v1.31.3+k3s1" },
            "addons": [ { "name": "metrics-server" } ],
            "bootstraps": [ { "name": "flux" } ],
        }))
        .unwrap();

        let first = serde_json::to_value(&spec).unwrap();
        let parsed: ClusterInstanceSpec = serde_json::from_value(first.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), first);
        assert_eq!(parsed.addons.len(), 1);
        assert_eq!(parsed.bootstraps.len(), 1);
    }

    // ── Generated CRD ─────────────────────────────────────────────────

    /// The CRD identity is part of kobe's public API: `kubectl get ci`,
    /// every RBAC rule in the chart, and every stored object's
    /// `apiVersion` depend on these exact strings. Changing any of them
    /// orphans data already in etcd.
    #[test]
    fn crd_identity_is_stable() {
        let crd = serde_json::to_value(ClusterInstance::crd()).unwrap();

        assert_eq!(crd["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(crd["spec"]["scope"], "Namespaced");
        assert_eq!(crd["spec"]["names"]["kind"], "ClusterInstance");
        assert_eq!(crd["spec"]["names"]["plural"], "clusterinstances");
        assert_eq!(crd["spec"]["names"]["shortNames"][0], "ci");
        assert_eq!(
            crd["metadata"]["name"],
            "clusterinstances.kobe.kunobi.ninja"
        );

        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }

    /// `status` must be a real subresource. Without it the apiserver
    /// silently drops every `patch_status` the controllers issue and the
    /// instance stays in `Creating` forever.
    #[test]
    fn crd_declares_status_subresource() {
        let crd = serde_json::to_value(ClusterInstance::crd()).unwrap();
        let subresources = &crd["spec"]["versions"][0]["subresources"];
        assert!(
            subresources.get("status").is_some(),
            "status subresource must be declared: {subresources}"
        );
    }

    /// `specHash` is deliberately a **string**, not an integer:
    /// Kubernetes' structural-schema validator parses numbers through
    /// `float64` and rejects u64 hashes outside ±2⁵³−1 with
    /// `specHash in body must be of type integer`. Pin the schema type so
    /// nobody "simplifies" it back to a number.
    #[test]
    fn crd_schema_types_spec_hash_as_string() {
        let crd = serde_json::to_value(ClusterInstance::crd()).unwrap();
        let status_props = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"]
            ["properties"];
        assert_eq!(
            status_props["specHash"]["type"], "string",
            "specHash must be a string in the OpenAPI schema: {status_props}"
        );
    }

    /// The generated OpenAPI schema must advertise the same camelCase
    /// property names the serde impls emit — a mismatch means the
    /// apiserver prunes fields the operator then cannot read back.
    #[test]
    fn crd_schema_property_names_match_serde_camel_case() {
        let crd = serde_json::to_value(ClusterInstance::crd()).unwrap();
        let schema = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"];

        for key in ["poolRef", "healthCheck", "readinessGates", "bootstraps"] {
            assert!(
                schema["spec"]["properties"].get(key).is_some(),
                "spec schema must expose `{key}`: {}",
                schema["spec"]["properties"]
            );
        }
        for key in [
            "leaseRef",
            "idleSince",
            "stateSince",
            "healthFailures",
            "createdWith",
            "activeBootstrap",
            "binding",
            "conditions",
            "network",
        ] {
            assert!(
                schema["status"]["properties"].get(key).is_some(),
                "status schema must expose `{key}`: {}",
                schema["status"]["properties"]
            );
        }
    }

    /// Legacy refs omit UID while new refs add it without changing the object
    /// shape stored in `spec.poolRef` and `status.leaseRef`.
    #[test]
    fn resource_ref_serializes_as_an_object_with_a_name_key() {
        let r = ResourceRef {
            name: "pool-e2e-basic".into(),
            uid: None,
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({ "name": "pool-e2e-basic" })
        );
        let exact = ResourceRef {
            name: "pool-e2e-basic".into(),
            uid: Some("pool-uid".into()),
        };
        assert_eq!(
            serde_json::to_value(&exact).unwrap(),
            json!({ "name": "pool-e2e-basic", "uid": "pool-uid" })
        );
    }
}
