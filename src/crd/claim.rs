use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ClusterClaim is the internal representation of a cluster lease.
///
/// Created when a user/CI claims a cluster via the HTTP API.
/// The claim controller binds it to a warm cluster, tracks TTL,
/// and handles release/expiry/recycling.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterClaim",
    plural = "clusterclaims",
    shortname = "cc",
    status = "ClusterClaimStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterClaimSpec {
    /// Which profile's pool to claim from.
    pub profile_ref: String,

    /// Requested TTL (e.g. "1h", "30m").
    pub ttl: String,

    /// Identity of the requester.
    pub requester: Requester,

    /// Claim priority for queue ordering.
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
pub struct ClusterClaimStatus {
    /// Current phase of the claim lifecycle.
    #[serde(default)]
    pub phase: ClaimPhase,

    /// Name of the bound cluster (set when phase=Bound).
    #[serde(default, alias = "vclusterName")]
    pub cluster_name: Option<String>,

    /// When the claim was bound to a vcluster.
    #[serde(default)]
    pub bound_at: Option<String>,

    /// When the claim expires (TTL deadline).
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Position in the priority queue (0 = not queued, 1 = next).
    #[serde(default)]
    pub queue_position: u32,

    /// URL to the diagnostic bundle captured on release.
    #[serde(default)]
    pub diagnostics_url: Option<String>,

    /// Number of TTL extensions granted for this claim.
    #[serde(default)]
    pub extensions_count: u32,

    /// Maximum number of extensions allowed (from policy).
    #[serde(default)]
    pub max_extensions: u32,
}

/// Claim lifecycle phases.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
pub enum ClaimPhase {
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

impl std::fmt::Display for ClaimPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimPhase::Pending => write!(f, "Pending"),
            ClaimPhase::Bound => write!(f, "Bound"),
            ClaimPhase::Released => write!(f, "Released"),
            ClaimPhase::Expired => write!(f, "Expired"),
            ClaimPhase::Recycling => write!(f, "Recycling"),
        }
    }
}

/// Default priority: normal (50).
fn default_priority() -> u32 {
    50
}
