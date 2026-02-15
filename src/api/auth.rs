use std::collections::HashMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::crd::auth_policy::{AuthPolicy, PolicySpec, RoleExtractionConfig};
use crate::pool::parse_duration;

/// JWKS cache entry.
#[derive(Debug, Clone)]
struct JwkSet {
    keys: Vec<Jwk>,
    fetched_at: std::time::Instant,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    crv: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Generic JWT claims — captures all claims from any OIDC provider.
#[derive(Debug, Deserialize)]
struct GenericClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    azp: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Validated identity extracted from a JWT.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    /// Provider and role: "{provider_name}:{role}" (e.g., "github-actions:ci").
    pub requester_type: String,
    /// Identity string formatted per the provider's identityTemplate.
    pub identity: String,
    /// Raw issuer for logging/debugging.
    #[allow(dead_code)]
    pub issuer: String,
    /// Resolved authorization policy for this identity.
    pub policy: crate::api::policy::Policy,
}

/// A compiled provider entry, built from an AuthPolicy CRD.
#[derive(Debug, Clone)]
struct CompiledProvider {
    name: String,
    issuer: String,
    jwks_url: String,
    audience: Vec<String>,
    authorized_parties: Vec<String>,
    algorithms: Vec<Algorithm>,
    identity_template: String,
    role_extraction: RoleExtractionConfig,
    policies: HashMap<String, PolicySpec>,
}

/// JWT authenticator supporting any OIDC provider via AuthPolicy CRDs.
pub struct JwtAuthenticator {
    http: HttpClient,
    /// Compiled providers from AuthPolicy CRDs, keyed by issuer.
    providers: RwLock<Vec<CompiledProvider>>,
    /// Cached JWKS per URL.
    jwks_cache: RwLock<HashMap<String, JwkSet>>,
}

/// Cache TTL for JWKS keys.
const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

impl JwtAuthenticator {
    pub fn new() -> Self {
        let http = HttpClient::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            http,
            providers: RwLock::new(Vec::new()),
            jwks_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Recompile the provider lookup table from AuthPolicy CRDs.
    /// Called by the AuthPolicy watcher whenever CRDs change.
    pub async fn update_policies(&self, policies: Vec<AuthPolicy>) {
        let compiled: Vec<CompiledProvider> = policies
            .into_iter()
            .filter_map(|ap| {
                let spec = ap.spec;
                let jwks_url = spec
                    .jwks_url
                    .unwrap_or_else(|| format!("{}/.well-known/jwks.json", spec.issuer));

                let algorithms: Vec<Algorithm> = spec
                    .algorithms
                    .iter()
                    .filter_map(|a| parse_algorithm(a))
                    .collect();

                if algorithms.is_empty() {
                    warn!(
                        provider = %spec.name,
                        "No valid algorithms configured, skipping provider"
                    );
                    return None;
                }

                Some(CompiledProvider {
                    name: spec.name,
                    issuer: spec.issuer,
                    jwks_url,
                    audience: spec.audience,
                    authorized_parties: spec.authorized_parties,
                    algorithms,
                    identity_template: spec.identity_template,
                    role_extraction: spec.role_extraction,
                    policies: spec.policies,
                })
            })
            .collect();

        let count = compiled.len();
        *self.providers.write().await = compiled;
        debug!(providers = count, "Auth policies updated");
    }

    /// Look up a policy by requester_type string ("{provider}:{role}").
    /// Used by the claim controller when it doesn't have an AuthIdentity.
    pub async fn policy_for_requester_type(
        &self,
        requester_type: &str,
    ) -> Option<crate::api::policy::Policy> {
        let (provider_name, role) = requester_type.split_once(':')?;
        let providers = self.providers.read().await;
        let provider = providers.iter().find(|p| p.name == provider_name)?;
        let policy_spec = provider.policies.get(role)?;
        Some(policy_spec_to_policy(policy_spec))
    }

    /// Validate a JWT and return the authenticated identity.
    ///
    /// Decodes the JWT header to peek at the issuer (without signature validation),
    /// then validates against the matching provider's JWKS with full verification.
    pub async fn validate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let providers = self.providers.read().await;

        if providers.is_empty() {
            return Err(AuthError::InvalidToken(
                "No auth policies configured".into(),
            ));
        }

        // Try each provider — fail fast on kid mismatch
        let mut last_error = String::new();
        for provider in providers.iter() {
            match self.validate_with_provider(token, &header, provider).await {
                Ok(identity) => return Ok(identity),
                Err(e) => {
                    last_error = e.to_string();
                    continue;
                }
            }
        }

        Err(AuthError::InvalidToken(format!(
            "Token not accepted by any configured provider: {last_error}"
        )))
    }

    /// Validate a token against a specific compiled provider.
    async fn validate_with_provider(
        &self,
        token: &str,
        header: &jsonwebtoken::Header,
        provider: &CompiledProvider,
    ) -> Result<AuthIdentity, AuthError> {
        let key = self
            .get_decoding_key(&provider.jwks_url, header.kid.as_deref())
            .await?;

        // Use the first algorithm from the provider's list for validation
        let mut validation = Validation::new(provider.algorithms[0]);
        validation.algorithms = provider.algorithms.clone();

        // Configure audience validation
        if !provider.audience.is_empty() {
            validation.set_audience(&provider.audience);
        } else {
            validation.validate_aud = false;
        }

        validation.set_issuer(&[&provider.issuer]);

        let data = decode::<GenericClaims>(token, &key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Validate azp (Authorized Party) if configured
        if !provider.authorized_parties.is_empty() {
            match &data.claims.azp {
                Some(azp) if provider.authorized_parties.iter().any(|p| p == azp) => {}
                Some(azp) => {
                    return Err(AuthError::InvalidToken(format!("Unauthorized azp: {azp}")));
                }
                None => {
                    return Err(AuthError::InvalidToken("Missing azp claim in token".into()));
                }
            }
        }

        // Extract role from claims
        let role = extract_role(&provider.role_extraction, &data.claims)?;

        // Look up policy for this role
        let policy_spec = provider.policies.get(&role).ok_or_else(|| {
            AuthError::InvalidToken(format!(
                "No policy defined for role '{}' in provider '{}'",
                role, provider.name
            ))
        })?;

        // Format identity from template
        let identity = format_identity(&provider.identity_template, &data.claims);

        let requester_type = format!("{}:{}", provider.name, role);

        debug!(
            identity = %identity,
            requester_type = %requester_type,
            provider = %provider.name,
            "Token validated"
        );

        Ok(AuthIdentity {
            requester_type,
            identity,
            issuer: data.claims.iss,
            policy: policy_spec_to_policy(policy_spec),
        })
    }

    /// Fetch a decoding key from JWKS, with caching.
    async fn get_decoding_key(
        &self,
        jwks_url: &str,
        kid: Option<&str>,
    ) -> Result<DecodingKey, AuthError> {
        // Check cache
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.get(jwks_url) {
                if cached.fetched_at.elapsed() < JWKS_CACHE_TTL {
                    return Self::find_key(&cached.keys, kid);
                }
            }
        }

        // Fetch fresh JWKS
        let resp = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetchError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AuthError::JwksFetchError(format!(
                "JWKS endpoint returned HTTP {}",
                resp.status()
            )));
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::JwksFetchError(e.to_string()))?;

        let jwk_set = JwkSet {
            keys: jwks.keys.clone(),
            fetched_at: std::time::Instant::now(),
        };

        // Check-lock-check: another task may have refreshed while we were fetching
        let mut cache = self.jwks_cache.write().await;
        if let Some(existing) = cache.get(jwks_url) {
            if existing.fetched_at.elapsed() < JWKS_CACHE_TTL {
                return Self::find_key(&existing.keys, kid);
            }
        }
        cache.insert(jwks_url.to_string(), jwk_set);
        drop(cache);

        Self::find_key(&jwks.keys, kid)
    }

    fn find_key(keys: &[Jwk], kid: Option<&str>) -> Result<DecodingKey, AuthError> {
        let kid = kid.ok_or_else(|| {
            AuthError::InvalidToken("JWT header missing required 'kid' field".into())
        })?;
        let key = keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| AuthError::KeyNotFound(kid.to_string()))?;

        match key.kty.as_str() {
            "RSA" => {
                let n = key.n.as_ref().ok_or_else(|| {
                    AuthError::InvalidToken("RSA key missing 'n' component".into())
                })?;
                let e = key.e.as_ref().ok_or_else(|| {
                    AuthError::InvalidToken("RSA key missing 'e' component".into())
                })?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| AuthError::InvalidToken(e.to_string()))
            }
            other => Err(AuthError::InvalidToken(format!(
                "Unsupported key type: {other}"
            ))),
        }
    }
}

/// Extract a role from JWT claims using the configured extraction method.
fn extract_role(
    config: &RoleExtractionConfig,
    claims: &GenericClaims,
) -> Result<String, AuthError> {
    match config {
        RoleExtractionConfig::Static { role } => Ok(role.clone()),

        RoleExtractionConfig::Claim { claim, default } => {
            match get_claim_value(&claims.extra, &claims.sub, claim) {
                Some(val) => Ok(val),
                None => default.clone().ok_or_else(|| {
                    AuthError::InvalidToken(format!("Missing required claim: {claim}"))
                }),
            }
        }

        RoleExtractionConfig::Mapping {
            claim,
            values,
            default,
        } => {
            let claim_val = get_claim_value(&claims.extra, &claims.sub, claim);
            if let Some(val) = claim_val {
                if let Some(role) = values.get(&val) {
                    return Ok(role.clone());
                }
            }
            default.clone().ok_or_else(|| {
                AuthError::InvalidToken(format!("No mapping for claim '{claim}' value"))
            })
        }

        RoleExtractionConfig::Conditional { rules, default } => {
            for rule in rules {
                if let Some(val) = get_claim_value(&claims.extra, &claims.sub, &rule.claim) {
                    if val == rule.value {
                        return Ok(rule.role.clone());
                    }
                }
            }
            default
                .clone()
                .ok_or_else(|| AuthError::InvalidToken("No conditional rule matched".into()))
        }
    }
}

/// Get a claim value by dot-path from the claims map.
///
/// Supports paths like `sub`, `repository`, `private_metadata.role`.
/// Special-cases `sub` and `iss` which are top-level fields, not in the extra map.
fn get_claim_value(
    extra: &HashMap<String, serde_json::Value>,
    sub: &str,
    path: &str,
) -> Option<String> {
    // Handle the standard JWT claims that aren't in the extra map
    if path == "sub" {
        return Some(sub.to_string());
    }

    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return None;
    }

    // Start from the root of extra claims
    let mut current: &serde_json::Value = extra.get(parts[0])?;

    // Traverse nested path
    for part in &parts[1..] {
        current = current.get(part)?;
    }

    // Convert the final value to a string
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => Some(current.to_string()),
    }
}

/// Format an identity string by replacing `{claim_name}` placeholders with claim values.
///
/// Uses a single forward pass to avoid re-expansion when claim values contain `{`.
fn format_identity(template: &str, claims: &GenericClaims) -> String {
    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find('{') {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 1..];

        if let Some(end) = remaining.find('}') {
            let key = &remaining[..end];
            let value = if key == "sub" {
                claims.sub.clone()
            } else if key == "iss" {
                claims.iss.clone()
            } else {
                get_claim_value(&claims.extra, &claims.sub, key)
                    .unwrap_or_else(|| format!("_missing_{key}_"))
            };
            result.push_str(&value);
            remaining = &remaining[end + 1..];
        } else {
            // Unclosed brace — keep as-is
            result.push('{');
        }
    }

    result.push_str(remaining);
    result
}

/// Convert a PolicySpec from the CRD into the runtime Policy struct.
fn policy_spec_to_policy(spec: &PolicySpec) -> crate::api::policy::Policy {
    let max_ttl = parse_duration(&spec.max_ttl).unwrap_or_else(|| {
        warn!(
            raw_value = %spec.max_ttl,
            "Failed to parse max_ttl, defaulting to 1h"
        );
        chrono::Duration::hours(1)
    });
    crate::api::policy::Policy {
        allowed_profiles: spec.allowed_profiles.clone(),
        max_ttl,
        max_concurrent_claims: spec.max_concurrent_claims,
        default_priority: spec.default_priority,
        max_extensions: spec.max_extensions,
    }
}

/// Parse an algorithm string into a jsonwebtoken Algorithm.
fn parse_algorithm(s: &str) -> Option<Algorithm> {
    match s {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "EdDSA" => Some(Algorithm::EdDSA),
        other => {
            warn!(algorithm = other, "Unknown JWT algorithm, skipping");
            None
        }
    }
}

/// Auth errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
}

/// Axum extractor for AuthIdentity.
///
/// Extracts the Bearer token from the Authorization header,
/// validates it via the JwtAuthenticator in AppState.
impl<B: crate::backend::ClusterBackend> FromRequestParts<crate::api::routes::AppState<B>>
    for AuthIdentity
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::api::routes::AppState<B>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

        state.authenticator.validate(token).await.map_err(|e| {
            warn!("Authentication failed: {e}");
            axum::http::StatusCode::UNAUTHORIZED
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(sub: &str, extra: HashMap<String, serde_json::Value>) -> GenericClaims {
        GenericClaims {
            iss: "https://test.example.com".to_string(),
            sub: sub.to_string(),
            azp: None,
            extra,
        }
    }

    // --- extract_role tests ---

    #[test]
    fn test_extract_role_static() {
        let config = RoleExtractionConfig::Static {
            role: "ci".to_string(),
        };
        let claims = make_claims("test-sub", HashMap::new());
        assert_eq!(extract_role(&config, &claims).unwrap(), "ci");
    }

    #[test]
    fn test_extract_role_claim() {
        let config = RoleExtractionConfig::Claim {
            claim: "role".to_string(),
            default: None,
        };
        let mut extra = HashMap::new();
        extra.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        let claims = make_claims("test-sub", extra);
        assert_eq!(extract_role(&config, &claims).unwrap(), "admin");
    }

    #[test]
    fn test_extract_role_claim_missing_with_default() {
        let config = RoleExtractionConfig::Claim {
            claim: "role".to_string(),
            default: Some("user".to_string()),
        };
        let claims = make_claims("test-sub", HashMap::new());
        assert_eq!(extract_role(&config, &claims).unwrap(), "user");
    }

    #[test]
    fn test_extract_role_claim_missing_no_default() {
        let config = RoleExtractionConfig::Claim {
            claim: "role".to_string(),
            default: None,
        };
        let claims = make_claims("test-sub", HashMap::new());
        assert!(extract_role(&config, &claims).is_err());
    }

    #[test]
    fn test_extract_role_mapping() {
        let config = RoleExtractionConfig::Mapping {
            claim: "org_role".to_string(),
            values: HashMap::from([
                ("org:admin".to_string(), "admin".to_string()),
                ("org:member".to_string(), "user".to_string()),
            ]),
            default: None,
        };
        let mut extra = HashMap::new();
        extra.insert(
            "org_role".to_string(),
            serde_json::Value::String("org:admin".to_string()),
        );
        let claims = make_claims("test-sub", extra);
        assert_eq!(extract_role(&config, &claims).unwrap(), "admin");
    }

    #[test]
    fn test_extract_role_mapping_with_default() {
        let config = RoleExtractionConfig::Mapping {
            claim: "org_role".to_string(),
            values: HashMap::from([("org:admin".to_string(), "admin".to_string())]),
            default: Some("user".to_string()),
        };
        let mut extra = HashMap::new();
        extra.insert(
            "org_role".to_string(),
            serde_json::Value::String("org:viewer".to_string()),
        );
        let claims = make_claims("test-sub", extra);
        assert_eq!(extract_role(&config, &claims).unwrap(), "user");
    }

    #[test]
    fn test_extract_role_conditional() {
        let config = RoleExtractionConfig::Conditional {
            rules: vec![
                crate::crd::auth_policy::ConditionalRule {
                    claim: "org_role".to_string(),
                    value: "org:admin".to_string(),
                    role: "admin".to_string(),
                },
                crate::crd::auth_policy::ConditionalRule {
                    claim: "private_metadata.role".to_string(),
                    value: "admin".to_string(),
                    role: "admin".to_string(),
                },
            ],
            default: Some("user".to_string()),
        };

        // First rule matches
        let mut extra = HashMap::new();
        extra.insert(
            "org_role".to_string(),
            serde_json::Value::String("org:admin".to_string()),
        );
        let claims = make_claims("test-sub", extra);
        assert_eq!(extract_role(&config, &claims).unwrap(), "admin");

        // Second rule matches (nested claim)
        let mut extra = HashMap::new();
        extra.insert(
            "private_metadata".to_string(),
            serde_json::json!({"role": "admin"}),
        );
        let claims = make_claims("test-sub", extra);
        assert_eq!(extract_role(&config, &claims).unwrap(), "admin");

        // No rule matches, falls back to default
        let claims = make_claims("test-sub", HashMap::new());
        assert_eq!(extract_role(&config, &claims).unwrap(), "user");
    }

    // --- format_identity tests ---

    #[test]
    fn test_format_identity_simple_sub() {
        let claims = make_claims("user_123", HashMap::new());
        assert_eq!(format_identity("{sub}", &claims), "user_123");
    }

    #[test]
    fn test_format_identity_github_pattern() {
        let mut extra = HashMap::new();
        extra.insert(
            "repository".to_string(),
            serde_json::Value::String("zondax/kunobi".to_string()),
        );
        extra.insert(
            "ref".to_string(),
            serde_json::Value::String("refs/heads/main".to_string()),
        );
        let claims = make_claims("repo:zondax/kunobi:ref:refs/heads/main", extra);

        assert_eq!(
            format_identity("repo:{repository}:ref:{ref}", &claims),
            "repo:zondax/kunobi:ref:refs/heads/main"
        );
    }

    #[test]
    fn test_format_identity_missing_claim() {
        let claims = make_claims("user_123", HashMap::new());
        assert_eq!(
            format_identity("{sub}:{missing}", &claims),
            "user_123:_missing_missing_"
        );
    }

    // --- get_claim_value tests ---

    #[test]
    fn test_get_claim_value_top_level() {
        let mut extra = HashMap::new();
        extra.insert(
            "email".to_string(),
            serde_json::Value::String("test@example.com".to_string()),
        );
        assert_eq!(
            get_claim_value(&extra, "user_1", "email"),
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn test_get_claim_value_sub() {
        let extra = HashMap::new();
        assert_eq!(
            get_claim_value(&extra, "user_123", "sub"),
            Some("user_123".to_string())
        );
    }

    #[test]
    fn test_get_claim_value_nested() {
        let mut extra = HashMap::new();
        extra.insert(
            "private_metadata".to_string(),
            serde_json::json!({"role": "admin", "level": 5}),
        );

        assert_eq!(
            get_claim_value(&extra, "user_1", "private_metadata.role"),
            Some("admin".to_string())
        );
        assert_eq!(
            get_claim_value(&extra, "user_1", "private_metadata.level"),
            Some("5".to_string())
        );
    }

    #[test]
    fn test_get_claim_value_missing() {
        let extra = HashMap::new();
        assert_eq!(get_claim_value(&extra, "user_1", "nonexistent"), None);
    }

    #[test]
    fn test_get_claim_value_deeply_nested_missing() {
        let mut extra = HashMap::new();
        extra.insert("a".to_string(), serde_json::json!({"b": {"c": "found"}}));

        assert_eq!(
            get_claim_value(&extra, "u", "a.b.c"),
            Some("found".to_string())
        );
        assert_eq!(get_claim_value(&extra, "u", "a.b.d"), None);
        assert_eq!(get_claim_value(&extra, "u", "a.x.c"), None);
    }

    // --- parse_algorithm tests ---

    #[test]
    fn test_parse_algorithm_rs256() {
        assert_eq!(parse_algorithm("RS256"), Some(Algorithm::RS256));
    }

    #[test]
    fn test_parse_algorithm_rs384() {
        assert_eq!(parse_algorithm("RS384"), Some(Algorithm::RS384));
    }

    #[test]
    fn test_parse_algorithm_es256() {
        assert_eq!(parse_algorithm("ES256"), Some(Algorithm::ES256));
    }

    #[test]
    fn test_parse_algorithm_ps256() {
        assert_eq!(parse_algorithm("PS256"), Some(Algorithm::PS256));
    }

    #[test]
    fn test_parse_algorithm_unknown() {
        assert_eq!(parse_algorithm("UNKNOWN"), None);
    }

    #[test]
    fn test_parse_algorithm_empty() {
        assert_eq!(parse_algorithm(""), None);
    }

    // --- policy_spec_to_policy tests ---

    #[test]
    fn test_policy_spec_to_policy_valid() {
        let spec = PolicySpec {
            allowed_profiles: vec!["e2e-*".to_string()],
            max_ttl: "2h".to_string(),
            max_concurrent_claims: 5,
            default_priority: 100,
            max_extensions: 3,
        };
        let policy = policy_spec_to_policy(&spec);
        assert_eq!(policy.max_ttl, chrono::Duration::hours(2));
        assert_eq!(policy.allowed_profiles, vec!["e2e-*"]);
        assert_eq!(policy.max_concurrent_claims, 5);
        assert_eq!(policy.default_priority, 100);
        assert_eq!(policy.max_extensions, 3);
    }

    #[test]
    fn test_policy_spec_to_policy_invalid_duration() {
        let spec = PolicySpec {
            allowed_profiles: vec!["dev-*".to_string()],
            max_ttl: "invalid".to_string(),
            max_concurrent_claims: 1,
            default_priority: 50,
            max_extensions: 0,
        };
        let policy = policy_spec_to_policy(&spec);
        // Should default to 1h (3600s) when parsing fails
        assert_eq!(policy.max_ttl, chrono::Duration::hours(1));
    }

    #[test]
    fn test_policy_spec_to_policy_wildcard_profiles() {
        let spec = PolicySpec {
            allowed_profiles: vec!["*".to_string()],
            max_ttl: "30m".to_string(),
            max_concurrent_claims: 10,
            default_priority: 50,
            max_extensions: 2,
        };
        let policy = policy_spec_to_policy(&spec);
        assert_eq!(policy.allowed_profiles, vec!["*"]);
        assert_eq!(policy.max_ttl, chrono::Duration::minutes(30));
    }

    // --- find_key tests ---

    #[test]
    fn test_find_key_no_keys() {
        let keys: Vec<Jwk> = vec![];
        let result = JwtAuthenticator::find_key(&keys, Some("kid-1"));
        assert!(matches!(result, Err(AuthError::KeyNotFound(_))));
    }

    #[test]
    fn test_find_key_kid_mismatch() {
        let keys = vec![Jwk {
            kid: Some("kid-A".to_string()),
            kty: "RSA".to_string(),
            n: Some("test-n".to_string()),
            e: Some("test-e".to_string()),
            x: None,
            y: None,
            crv: None,
        }];
        let result = JwtAuthenticator::find_key(&keys, Some("kid-B"));
        assert!(matches!(result, Err(AuthError::KeyNotFound(_))));
    }

    #[test]
    fn test_find_key_missing_kid_header() {
        let keys = vec![Jwk {
            kid: Some("kid-A".to_string()),
            kty: "RSA".to_string(),
            n: Some("test-n".to_string()),
            e: Some("test-e".to_string()),
            x: None,
            y: None,
            crv: None,
        }];
        let result = JwtAuthenticator::find_key(&keys, None);
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    // --- JwtAuthenticator async tests ---

    #[tokio::test]
    async fn test_authenticator_new_has_no_providers() {
        let auth = JwtAuthenticator::new();
        let result = auth.policy_for_requester_type("anything:role").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_policies_compiles_providers() {
        let auth = JwtAuthenticator::new();

        let policy: AuthPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kunobi.ninja/v1alpha1",
            "kind": "AuthPolicy",
            "metadata": { "name": "test-policy" },
            "spec": {
                "name": "test-provider",
                "issuer": "https://example.com",
                "audience": ["test-aud"],
                "algorithms": ["RS256"],
                "roleExtraction": { "method": "static", "role": "admin" },
                "policies": {
                    "admin": {
                        "allowedProfiles": ["*"],
                        "maxTtl": "1h",
                        "maxConcurrentClaims": 10
                    }
                }
            }
        }))
        .unwrap();

        auth.update_policies(vec![policy]).await;

        let result = auth.policy_for_requester_type("test-provider:admin").await;
        assert!(result.is_some());
        let policy = result.unwrap();
        assert_eq!(policy.allowed_profiles, vec!["*"]);
        assert_eq!(policy.max_ttl, chrono::Duration::hours(1));
        assert_eq!(policy.max_concurrent_claims, 10);
    }

    #[tokio::test]
    async fn test_policy_for_requester_type_format() {
        let auth = JwtAuthenticator::new();

        let policy: AuthPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kunobi.ninja/v1alpha1",
            "kind": "AuthPolicy",
            "metadata": { "name": "fmt-test" },
            "spec": {
                "name": "my-provider",
                "issuer": "https://issuer.example.com",
                "audience": [],
                "algorithms": ["RS256"],
                "roleExtraction": { "method": "static", "role": "ci" },
                "policies": {
                    "ci": {
                        "allowedProfiles": ["e2e-*"],
                        "maxTtl": "2h",
                        "maxConcurrentClaims": 3
                    }
                }
            }
        }))
        .unwrap();

        auth.update_policies(vec![policy]).await;

        // Correct format "provider_name:role" should find the policy
        assert!(auth
            .policy_for_requester_type("my-provider:ci")
            .await
            .is_some());

        // Wrong provider name should not find
        assert!(auth
            .policy_for_requester_type("other-provider:ci")
            .await
            .is_none());

        // Wrong role should not find
        assert!(auth
            .policy_for_requester_type("my-provider:admin")
            .await
            .is_none());

        // Missing colon separator should not find
        assert!(auth
            .policy_for_requester_type("my-provider-ci")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_validate_no_providers_returns_error() {
        let auth = JwtAuthenticator::new();
        // Use a structurally valid JWT (header.payload.signature) so header
        // decoding succeeds and we exercise the "no providers" branch.
        let fake_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                          eyJzdWIiOiJ0ZXN0In0.\
                          signature";
        let result = auth.validate(fake_token).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No auth policies configured"),
            "Expected 'No auth policies configured' in error, got: {err_msg}"
        );
    }
}
