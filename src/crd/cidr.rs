//! IPAM CRD: namespaced `CIDRClaim` against an operator-configured
//! address space.
//!
//! ## The problem
//!
//! kobe runs guest k3s/k0s clusters as workload pods inside the host
//! cluster. Each guest sets up its own apiserver + kube-proxy with
//! its own `--service-cidr` / `--cluster-cidr`; if that range overlaps
//! the host's, in-pod iptables rules race with the host's and traffic
//! to `kubernetes.default.svc` silently routes to the host apiserver
//! (CoreDNS readiness x509 fails, cluster broken). Two leased guests
//! sharing a service CIDR can't be peered. So we need an allocator
//! that hands each guest a non-colliding pair of slices, and a way to
//! pin specific ranges out of the rotation (corporate VPN, legacy
//! peer cluster, …).
//!
//! ## The whole API
//!
//! Two namespaced CRDs: `CIDRClaim` (one per consumer, a request for a
//! slice) and `CIDRPool` (optional singleton, the address plan itself).
//! The default address space is a Rust constant — see
//! `pool::cidr_alloc::ipam_plan` — the historical `10.240.0.0/13` (svc)
//! and `10.248.0.0/13` (cls) plan with `/20` slots, the right answer for
//! every deployment whose host cluster doesn't overlap it. A deployment
//! that DOES overlap (its own service range collides → guest CoreDNS
//! x509 failures, #42) applies a `CIDRPool` named `default` to relocate
//! the supernets; the allocator reads it at startup, else falls back to
//! the constant. `CIDRClaim` is unchanged either way.
//!
//! ## Lifecycle
//!
//! - The instance controller, on `ClusterInstance` create, also
//!   creates a `CIDRClaim` with `ownerReference` → ClusterInstance.
//! - The IPAM controller observes the claim, picks a free slot from
//!   the hardcoded plan (or honors `requestedServiceCidr` /
//!   `requestedClusterCidr` for a static reservation) and writes the
//!   bound CIDRs to `claim.status`.
//! - The instance controller waits for `claim.status.phase == Bound`,
//!   reads the CIDRs, copies them onto `ClusterInstance.status.network`
//!   and provisions the backend.
//! - On `ClusterInstance` delete, kube GC removes the `CIDRClaim`
//!   automatically (ownerReference). No finalizer needed — the
//!   claim's existence IS the allocation, deletion = release.
//!
//! ## Manual reservations
//!
//! A `CIDRClaim` with `spec.requestedServiceCidr` +
//! `spec.requestedClusterCidr` set asks the IPAM controller to bind
//! those exact CIDRs. If both are aligned to the plan's slot prefixes
//! and not already taken, the claim becomes `Bound`. Without an
//! `ownerReference`, the claim survives operator upgrades and helm
//! uninstalls — exactly the lifetime a static reservation should have.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Namespaced claim against the operator's IPAM space. Created by
/// whatever consumer needs a CIDR slice (today: the instance
/// controller, one per `ClusterInstance`).
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "CIDRClaim",
    plural = "cidrclaims",
    shortname = "cclaim",
    status = "CIDRClaimStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CIDRClaimSpec {
    /// Pin the service CIDR to this exact slice. Must be aligned to
    /// the operator's `service_prefix` and inside the configured
    /// service block. If the slice is free, the claim becomes
    /// `Bound`; if it's already allocated, the claim becomes
    /// `Conflict`. Set together with `requested_cluster_cidr` for
    /// static reservations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_service_cidr: Option<String>,

    /// Pin the cluster CIDR to this exact slice. Same rules as above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_cluster_cidr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct CIDRClaimStatus {
    /// Current state of the claim.
    #[serde(default)]
    pub phase: CIDRClaimPhase,

    /// Service CIDR assigned to this claim. `None` until `phase == Bound`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_cidr: Option<String>,

    /// Cluster (pod) CIDR assigned to this claim. `None` until `phase == Bound`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_cidr: Option<String>,

    /// RFC3339 timestamp of the binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<String>,

    /// Human-readable detail. Carries the conflict reason when
    /// `phase == Conflict` (e.g. "10.240.0.0/20 already bound to
    /// kobe/k3s-pool-abc123") or the validation error when the spec
    /// itself is malformed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum CIDRClaimPhase {
    /// Newly created, IPAM controller hasn't reconciled yet.
    #[default]
    Pending,
    /// Successfully allocated; `service_cidr` + `cluster_cidr` are set.
    Bound,
    /// Spec asked for a specific CIDR that's already in use, or the spec
    /// is malformed (unaligned prefix, outside pool's parent block,
    /// unknown poolRef, etc.). `message` carries the reason.
    Conflict,
}

/// Operator-level IPAM address-space configuration. The IPAM allocator
/// carves every guest k3s/k0s service+cluster CIDR out of two parent
/// supernets; by default those are the built-in `10.240.0.0/13` (svc)
/// and `10.248.0.0/13` (cls), `/20` slots. That default is well clear
/// of the common k8s ranges (10.42/10.43/10.96), but a host cluster
/// whose OWN service range overlaps it makes every guest's in-pod
/// `10.x.0.1` route to the HOST apiserver — guest CoreDNS then fails
/// with `x509: certificate signed by unknown authority` (#42).
///
/// A `CIDRPool` named `default` in the operator namespace overrides the
/// built-in plan so operators can relocate the supernets off a colliding
/// host range. When absent, the built-in plan is used unchanged — so
/// this is purely opt-in and existing deployments are unaffected.
///
/// Singleton by convention: the allocator reads the one named `default`
/// and ignores others. The plan is resolved at operator startup; editing
/// the `CIDRPool` takes effect on the next restart (existing `CIDRClaim`s
/// that fall outside a narrowed plan are re-validated to `Conflict`).
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "CIDRPool",
    plural = "cidrpools",
    shortname = "cpool",
    status = "CIDRPoolStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CIDRPoolSpec {
    /// Parent supernet for guest *service* CIDRs, e.g. `"10.240.0.0/13"`.
    /// Must be aligned to its own prefix and must NOT overlap the host
    /// cluster's service range.
    pub service_cidr: String,

    /// Prefix carved per guest from `service_cidr`, e.g. `20` (a `/20`
    /// slot = 4096 addresses). Must be >= the `service_cidr` prefix.
    pub service_slot_prefix: u8,

    /// Parent supernet for guest *cluster* (pod) CIDRs, e.g.
    /// `"10.248.0.0/13"`. Same alignment + non-overlap rules.
    pub cluster_cidr: String,

    /// Prefix carved per guest from `cluster_cidr`, e.g. `20`.
    pub cluster_slot_prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct CIDRPoolStatus {
    /// Whether the allocator accepted this pool as its active plan.
    #[serde(default)]
    pub phase: CIDRPoolPhase,

    /// Number of paired (service, cluster) slots this plan yields.
    /// `None` until the allocator has evaluated it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,

    /// Validation error when `phase == Invalid` (malformed CIDR,
    /// misaligned block, slot prefix smaller than the block prefix, …).
    /// On `Invalid` the allocator falls back to the built-in default plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum CIDRPoolPhase {
    /// Created but not yet evaluated by the allocator (e.g. operator
    /// not restarted since it was applied).
    #[default]
    Pending,
    /// Accepted as the allocator's active address plan.
    Active,
    /// Rejected as malformed; the built-in default plan is in effect.
    /// See `message`.
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allocated CIDRs must be OMITTED when unset, never serialized as
    /// null.
    ///
    /// This is the allocation record. A controller doing pass-through
    /// preservation that momentarily reads them as `None` would, with an
    /// explicit null, erase them via JSON Merge Patch (RFC 7396) — and the
    /// allocator derives the in-use set by listing bound claims. A cleared
    /// allocation is therefore not a display bug: the slot looks free and
    /// gets re-issued to a second cluster, which is the CIDR-collision class
    /// this type exists to prevent.
    #[test]
    fn an_unset_allocation_is_omitted_so_merge_patch_cannot_erase_it() {
        let unbound = CIDRClaimStatus {
            phase: CIDRClaimPhase::Pending,
            ..Default::default()
        };
        let v = serde_json::to_value(&unbound).unwrap();
        for key in ["serviceCidr", "clusterCidr", "boundAt", "message"] {
            assert!(
                v.get(key).is_none(),
                "{key} must be omitted when unset, not null: {v}"
            );
        }

        let bound = CIDRClaimStatus {
            phase: CIDRClaimPhase::Bound,
            service_cidr: Some("10.240.0.0/20".into()),
            cluster_cidr: Some("10.248.0.0/20".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&bound).unwrap();
        assert_eq!(
            v.get("serviceCidr").and_then(|x| x.as_str()),
            Some("10.240.0.0/20")
        );
        assert_eq!(
            v.get("clusterCidr").and_then(|x| x.as_str()),
            Some("10.248.0.0/20")
        );
    }

    /// A claim with no status yet is `Pending`, never `Bound`. Defaulting to
    /// `Bound` would make an unreconciled claim advertise an allocation it
    /// does not have — and its `service_cidr` would be `None`, so it would
    /// claim a slot of nothing.
    #[test]
    fn phase_defaults_to_pending() {
        let st: CIDRClaimStatus = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(st.phase, CIDRClaimPhase::Pending);
        assert_eq!(CIDRClaimPhase::default(), CIDRClaimPhase::Pending);
    }

    /// Phase round-trips as the bare variant name for every state. The IPAM
    /// controller and the pool manager both branch on this value.
    #[test]
    fn phase_round_trips_as_the_bare_variant_name() {
        for (phase, wire) in [
            (CIDRClaimPhase::Pending, "Pending"),
            (CIDRClaimPhase::Bound, "Bound"),
            (CIDRClaimPhase::Conflict, "Conflict"),
        ] {
            assert_eq!(
                serde_json::to_value(&phase).unwrap(),
                serde_json::Value::String(wire.to_string())
            );
            let back: CIDRClaimPhase = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, phase);
        }
    }

    /// Static reservations are requested in camelCase. A snake_case key is
    /// dropped as unknown, which for an optional field means the pin is
    /// silently ignored and the allocator hands out a dynamic slot instead
    /// of the one that was asked for.
    #[test]
    fn a_static_reservation_binds_camel_case_only() {
        let camel: CIDRClaimSpec = serde_json::from_value(serde_json::json!({
            "requestedServiceCidr": "10.240.0.0/20"
        }))
        .unwrap();
        assert_eq!(
            camel.requested_service_cidr.as_deref(),
            Some("10.240.0.0/20")
        );

        let snake: CIDRClaimSpec = serde_json::from_value(serde_json::json!({
            "requested_service_cidr": "10.240.0.0/20"
        }))
        .unwrap();
        assert!(
            snake.requested_service_cidr.is_none(),
            "snake_case must not bind — pinning would be silently ignored"
        );
    }

    /// A status written by a newer operator must still deserialize, or a
    /// rolling upgrade wedges the older replica on every claim it reads.
    #[test]
    fn a_status_from_a_newer_operator_still_deserializes() {
        let st: CIDRClaimStatus = serde_json::from_value(serde_json::json!({
            "phase": "Bound",
            "serviceCidr": "10.240.0.0/20",
            "someFieldFromTheFuture": true
        }))
        .expect("unknown fields must be ignored");
        assert_eq!(st.phase, CIDRClaimPhase::Bound);
        assert_eq!(st.service_cidr.as_deref(), Some("10.240.0.0/20"));
    }

    /// Both IPAM CRDs' public identity, and that the claim carries a real
    /// status subresource — without it the apiserver drops every allocation
    /// the controller writes and no claim ever binds.
    #[test]
    fn crd_identities_are_stable() {
        use kube::CustomResourceExt;

        let claim = serde_json::to_value(CIDRClaim::crd()).unwrap();
        assert_eq!(claim["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(claim["spec"]["names"]["kind"], "CIDRClaim");
        assert_eq!(claim["spec"]["names"]["plural"], "cidrclaims");
        assert_eq!(claim["spec"]["names"]["shortNames"][0], "cclaim");
        assert_eq!(claim["metadata"]["name"], "cidrclaims.kobe.kunobi.ninja");
        let versions = claim["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert!(
            versions[0]["subresources"].get("status").is_some(),
            "CIDRClaim must have a status subresource or allocations are dropped"
        );

        let pool = serde_json::to_value(CIDRPool::crd()).unwrap();
        assert_eq!(pool["spec"]["names"]["kind"], "CIDRPool");
        assert_eq!(pool["spec"]["names"]["plural"], "cidrpools");
        assert_eq!(pool["spec"]["names"]["shortNames"][0], "cpool");
    }
}
