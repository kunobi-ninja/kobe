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
//! One namespaced CRD: `CIDRClaim`. The address space itself is a
//! Rust constant — see `pool::cidr_alloc::ipam_plan`. There is
//! deliberately no `CIDRPool` CRD and no per-deployment config. In
//! every kobe deployment to date the historical `10.240.0.0/13` (svc)
//! and `10.248.0.0/13` (cls) plan with `/20` slots has been the right
//! answer, and adding configuration now would just be speculative
//! flexibility we'd have to test, document, and support. If a future
//! customer genuinely can't use that block, we promote `ipam_plan` to
//! a `CIDRPool` CRD at that point — `CIDRClaim` stays unchanged.
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
