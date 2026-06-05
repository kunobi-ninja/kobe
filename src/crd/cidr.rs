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
