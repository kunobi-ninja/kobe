use std::collections::HashMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AuthPolicy configures a single OIDC provider with role extraction and per-role policies.
///
/// Each AuthPolicy CRD represents one identity provider (e.g., GitHub Actions, Clerk, Auth0).
/// The operator watches all AuthPolicy CRDs and compiles them into a lookup table keyed by issuer.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kunobi.ninja",
    version = "v1alpha1",
    kind = "AuthPolicy",
    plural = "authpolicies",
    shortname = "ap",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct AuthPolicySpec {
    /// Human-readable name for this provider (used as prefix in requester_type).
    pub name: String,

    /// OIDC issuer URL (must match the `iss` claim in JWTs).
    pub issuer: String,

    /// JWKS URL for fetching signing keys.
    /// Defaults to `{issuer}/.well-known/jwks.json` if not specified.
    #[serde(default)]
    pub jwks_url: Option<String>,

    /// Expected `aud` (audience) claim values. Empty = skip audience validation.
    #[serde(default)]
    pub audience: Vec<String>,

    /// Expected `azp` (Authorized Party) values. Empty = skip azp validation.
    #[serde(default)]
    pub authorized_parties: Vec<String>,

    /// Allowed JWT signing algorithms. Defaults to `["RS256"]`.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,

    /// Template for building the identity string from JWT claims.
    /// Use `{claim_name}` to interpolate claim values (e.g., `"repo:{repository}:ref:{ref}"`).
    /// Supports dot-path traversal (e.g., `{private_metadata.role}`).
    /// Defaults to `{sub}`.
    #[serde(default = "default_identity_template")]
    pub identity_template: String,

    /// How to extract the role from a JWT token.
    pub role_extraction: RoleExtractionConfig,

    /// Per-role authorization policies. Keys are role names.
    pub policies: HashMap<String, PolicySpec>,
}

/// Determines how the operator extracts a role name from JWT claims.
///
/// The extracted role is combined with the provider name to form
/// the `requester_type` string: `"{provider_name}:{role}"`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum RoleExtractionConfig {
    /// All tokens from this provider get the same role.
    /// Good for CI bots where every token has the same privileges.
    #[serde(rename = "static")]
    Static {
        /// The role name to assign to all tokens.
        role: String,
    },

    /// Read the role directly from a JWT claim.
    /// The claim value becomes the role name.
    #[serde(rename = "claim")]
    Claim {
        /// Claim path to read (supports dot-path like `private_metadata.role`).
        claim: String,
        /// Fallback role if the claim is missing. If not set, tokens without the claim are rejected.
        #[serde(default)]
        default: Option<String>,
    },

    /// Map specific claim values to role names.
    /// Useful when the claim value doesn't directly match your role naming.
    #[serde(rename = "mapping")]
    Mapping {
        /// Claim path to read.
        claim: String,
        /// Map of claim_value → role_name.
        values: HashMap<String, String>,
        /// Fallback role if no mapping matches.
        #[serde(default)]
        default: Option<String>,
    },

    /// First-matching conditional rule wins.
    /// For complex scenarios like Clerk admin detection via multiple claim paths.
    #[serde(rename = "conditional")]
    Conditional {
        /// Ordered list of rules. First match wins.
        rules: Vec<ConditionalRule>,
        /// Fallback role if no rule matches.
        #[serde(default)]
        default: Option<String>,
    },
}

/// A conditional rule for role extraction.
/// Matches when a claim at `claim` equals `value`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalRule {
    /// Claim path to check (supports dot-path).
    pub claim: String,
    /// Value to match against.
    pub value: String,
    /// Role to assign if this rule matches.
    pub role: String,
}

/// Per-role authorization policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySpec {
    /// Profile name patterns this role can claim (e.g., `["e2e-*"]`).
    /// Supports `*` suffix wildcard and literal `*` for all profiles.
    pub allowed_profiles: Vec<String>,

    /// Maximum TTL for claims (e.g., "1h", "30m", "4h").
    pub max_ttl: String,

    /// Maximum number of concurrent active claims.
    pub max_concurrent_claims: u32,

    /// Default priority for claims from this role.
    /// Higher values are served first in the priority queue.
    #[serde(default = "default_priority")]
    pub default_priority: u32,

    /// Maximum number of TTL extensions allowed.
    #[serde(default = "default_max_extensions")]
    pub max_extensions: u32,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_identity_template() -> String {
    "{sub}".to_string()
}

fn default_priority() -> u32 {
    50
}

fn default_max_extensions() -> u32 {
    2
}
