use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AccessPolicy configures authentication and authorization for cluster lease requests.
///
/// Each AccessPolicy represents one authentication method (OIDC provider, static token,
/// or Kubernetes ServiceAccount) with associated authorization rules.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "AccessPolicy",
    plural = "accesspolicies",
    shortname = "ap",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicySpec {
    /// Authentication method configuration.
    pub auth: AuthMethod,

    /// Identity template for OIDC providers.
    /// Uses `{claim_name}` syntax to interpolate JWT claims.
    /// Supports dot-path traversal (e.g., `{private_metadata.role}`).
    /// Defaults to `"{sub}"`. Ignored for token and serviceAccount auth.
    #[serde(default = "default_identity")]
    pub identity: String,

    /// Authorization rules. First matching rule wins for OIDC with match clauses.
    /// For token and serviceAccount auth, rules without match clauses apply directly.
    pub rules: Vec<AccessRule>,
}

/// Authentication method — exactly one field should be set.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    /// OIDC provider (JWT-based) authentication.
    #[serde(default)]
    pub oidc: Option<OidcAuth>,

    /// Static bearer token authentication.
    #[serde(default)]
    pub token: Option<TokenAuth>,

    /// Kubernetes ServiceAccount authentication.
    #[serde(default)]
    pub service_account: Option<ServiceAccountAuth>,
}

/// OIDC provider configuration for JWT validation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuth {
    /// OIDC issuer URL (must match `iss` claim).
    pub issuer: String,

    /// JWKS URL for key fetching. Defaults to `{issuer}/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,

    /// Expected audience (`aud` claim). Empty = skip validation.
    #[serde(default)]
    pub audience: Vec<String>,

    /// Expected authorized parties (`azp` claim). Empty = skip validation.
    #[serde(default)]
    pub authorized_parties: Vec<String>,

    /// Allowed JWT signing algorithms. Defaults to `["RS256"]`.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
}

/// Static bearer token authentication via a Kubernetes Secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuth {
    /// Name of the Secret containing the token (key: "token").
    pub secret_ref: String,
}

/// Kubernetes ServiceAccount-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAuth {
    /// ServiceAccount name.
    pub name: String,
    /// ServiceAccount namespace.
    pub namespace: String,
}

/// Authorization rule — what an authenticated caller can do.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessRule {
    /// Optional claim-based match for multi-role OIDC policies.
    /// When set, this rule only applies if the JWT claim matches.
    #[serde(default, rename = "match")]
    pub match_clause: Option<ClaimMatch>,

    /// Pool name patterns this rule allows (e.g., `["ci-*"]`).
    /// Supports `*` suffix wildcard and literal `*` for all pools.
    pub pools: Vec<String>,

    /// Maximum TTL for leases (e.g., "1h", "30m").
    pub max_ttl: String,

    /// Maximum concurrent active leases for this identity.
    pub max_concurrent_leases: u32,

    /// Maximum TTL extensions per lease.
    #[serde(default = "default_max_extensions")]
    pub max_extensions: u32,
}

/// Claim-based match condition for OIDC rules.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMatch {
    /// JWT claim path (supports dot-path like `private_metadata.role`).
    pub claim: String,
    /// Value to match.
    pub value: String,
}

fn default_identity() -> String {
    "{sub}".to_string()
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_max_extensions() -> u32 {
    2
}
