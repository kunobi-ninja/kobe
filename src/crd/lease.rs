use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ClusterLease is the internal representation of a cluster lease.
///
/// Created when a user/CI leases a cluster via the HTTP API.
/// The lease controller binds it to a warm cluster, tracks TTL,
/// and handles release/expiry/recycling.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterLease",
    plural = "clusterleases",
    shortname = "cl",
    status = "ClusterLeaseStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseSpec {
    /// Which profile's pool to lease from.
    pub pool_ref: String,

    /// Requested TTL (e.g. "1h", "30m").
    pub ttl: String,

    /// Identity of the requester.
    pub requester: Requester,

    /// Lease priority for queue ordering.
    /// Higher values are served first.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Requester {
    /// Type of requester: "{provider}:{role}" (e.g. "github-actions:ci", "clerk:admin").
    #[serde(rename = "type")]
    pub requester_type: String,

    /// Identity string (e.g. "repo:org/repo:ref:refs/heads/main" for GitHub,
    /// or user ID for Clerk).
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseStatus {
    /// Current phase of the lease lifecycle.
    #[serde(default)]
    pub phase: LeasePhase,

    /// Name of the bound cluster (set when phase=Bound).
    #[serde(default)]
    pub cluster_name: Option<String>,

    /// When the lease was bound to a vcluster.
    #[serde(default)]
    pub bound_at: Option<String>,

    /// When the lease expires (TTL deadline).
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Position in the priority queue (0 = not queued, 1 = next).
    #[serde(default)]
    pub queue_position: u32,

    /// URL to the diagnostic bundle captured on release.
    #[serde(default)]
    pub diagnostics_url: Option<String>,

    /// Number of TTL extensions granted for this lease.
    #[serde(default)]
    pub extensions_count: u32,

    /// Maximum number of extensions allowed (from policy).
    #[serde(default)]
    pub max_extensions: u32,
}

/// Lease lifecycle phases.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
pub enum LeasePhase {
    /// Waiting for a warm cluster to become available.
    #[default]
    Pending,
    /// Bound to a cluster.
    Bound,
    /// Explicitly released by the user.
    Released,
    /// TTL expired, cluster being reclaimed.
    Expired,
    /// Cluster being deleted and recreated.
    Recycling,
}

impl std::fmt::Display for LeasePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeasePhase::Pending => write!(f, "Pending"),
            LeasePhase::Bound => write!(f, "Bound"),
            LeasePhase::Released => write!(f, "Released"),
            LeasePhase::Expired => write!(f, "Expired"),
            LeasePhase::Recycling => write!(f, "Recycling"),
        }
    }
}

/// Default priority: normal (50).
fn default_priority() -> u32 {
    50
}
