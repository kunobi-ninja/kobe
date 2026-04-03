use std::collections::HashMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::crd::access_policy::{AccessPolicy, AccessRule, ClaimMatch};
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

/// A compiled provider entry, built from an AccessPolicy CRD.
#[derive(Debug, Clone)]
struct CompiledProvider {
    /// The policy name (from metadata.name).
    name: String,
    issuer: String,
    jwks_url: String,
    audience: Vec<String>,
    authorized_parties: Vec<String>,
    algorithms: Vec<Algorithm>,
    identity_template: String,
    /// Flat rules list — first matching rule wins.
    rules: Vec<AccessRule>,
}

/// JWT authenticator supporting any OIDC provider via AccessPolicy CRDs.
pub struct JwtAuthenticator {
    http: HttpClient,
    /// Compiled providers from AccessPolicy CRDs.
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

    /// Recompile the provider lookup table from AccessPolicy CRDs.
    /// Called by the AccessPolicy watcher whenever CRDs change.
    pub async fn update_policies(&self, policies: Vec<AccessPolicy>) {
        let compiled: Vec<CompiledProvider> = policies
            .into_iter()
            .filter_map(|ap| {
                let policy_name = ap.metadata.name.unwrap_or_default();
                let spec = ap.spec;

                // Only OIDC auth is supported for JWT validation currently
                let oidc = spec.auth.oidc?;

                let jwks_url = oidc
                    .jwks_url
                    .unwrap_or_else(|| format!("{}/.well-known/jwks.json", oidc.issuer));

                let algorithms: Vec<Algorithm> = oidc
                    .algorithms
                    .iter()
                    .filter_map(|a| parse_algorithm(a))
                    .collect();

                if algorithms.is_empty() {
                    warn!(
                        provider = %policy_name,
                        "No valid algorithms configured, skipping provider"
                    );
                    return None;
                }

                Some(CompiledProvider {
                    name: policy_name,
                    issuer: oidc.issuer,
                    jwks_url,
                    audience: oidc.audience,
                    authorized_parties: oidc.authorized_parties,
                    algorithms,
                    identity_template: spec.identity,
                    rules: spec.rules,
                })
            })
            .collect();

        let count = compiled.len();
        *self.providers.write().await = compiled;
        debug!(providers = count, "Access policies updated");
    }

    /// Look up a policy by requester_type string.
    ///
    /// Format: `"{policy_name}"` (no match clause) or `"{policy_name}:{claim_value}"`.
    /// Used by the claim controller when it doesn't have an AuthIdentity.
    pub async fn policy_for_requester_type(
        &self,
        requester_type: &str,
    ) -> Option<crate::api::policy::Policy> {
        let (policy_name, matched_value) = match requester_type.split_once(':') {
            Some((name, val)) => (name, Some(val)),
            None => (requester_type, None),
        };
        let providers = self.providers.read().await;
        let provider = providers.iter().find(|p| p.name == policy_name)?;
        let rule = find_matching_rule(&provider.rules, matched_value)?;
        Some(access_rule_to_policy(rule))
    }

    /// Validate a JWT and return the authenticated identity.
    ///
    /// Peeks at the unverified `iss` claim to select the correct provider(s),
    /// then validates the token signature and claims against that provider's JWKS.
    pub async fn validate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let providers = self.providers.read().await;

        if providers.is_empty() {
            return Err(AuthError::InvalidToken(
                "No auth policies configured".into(),
            ));
        }

        // Peek at the unverified issuer to pre-select the correct provider(s),
        // avoiding cross-provider token acceptance.
        let issuer = peek_issuer(token, &header)?;

        let matching: Vec<_> = providers.iter().filter(|p| p.issuer == issuer).collect();

        if matching.is_empty() {
            return Err(AuthError::InvalidToken(format!(
                "No provider configured for issuer: {issuer}"
            )));
        }

        let mut last_error = String::new();
        for provider in matching {
            match self.validate_with_provider(token, &header, provider).await {
                Ok(identity) => return Ok(identity),
                Err(e) => {
                    last_error = e.to_string();
                    continue;
                }
            }
        }

        Err(AuthError::InvalidToken(format!(
            "Token not accepted by provider for issuer {issuer}: {last_error}"
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

        // Find matching rule — iterate rules, check match clauses against claims
        let (rule, matched_value) = find_matching_rule_with_claims(&provider.rules, &data.claims)?;

        // Format identity from template
        let identity = format_identity(&provider.identity_template, &data.claims);

        // Build requester_type: "{policy_name}" or "{policy_name}:{matched_value}"
        let requester_type = match &matched_value {
            Some(val) => format!("{}:{}", provider.name, val),
            None => provider.name.clone(),
        };

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
            policy: access_rule_to_policy(rule),
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
            "EC" => {
                let x = key.x.as_ref().ok_or_else(|| {
                    AuthError::InvalidToken("EC key missing 'x' component".into())
                })?;
                let y = key.y.as_ref().ok_or_else(|| {
                    AuthError::InvalidToken("EC key missing 'y' component".into())
                })?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| AuthError::InvalidToken(e.to_string()))
            }
            "OKP" => {
                let x = key.x.as_ref().ok_or_else(|| {
                    AuthError::InvalidToken("OKP key missing 'x' component".into())
                })?;
                DecodingKey::from_ed_components(x)
                    .map_err(|e| AuthError::InvalidToken(e.to_string()))
            }
            other => Err(AuthError::InvalidToken(format!(
                "Unsupported key type: {other}"
            ))),
        }
    }
}

/// Find the first matching rule from a rules list, checking match clauses against JWT claims.
/// Returns the matched rule and the optional matched claim value (used for requester_type).
fn find_matching_rule_with_claims<'a>(
    rules: &'a [AccessRule],
    claims: &GenericClaims,
) -> Result<(&'a AccessRule, Option<String>), AuthError> {
    for rule in rules {
        match &rule.match_clause {
            Some(ClaimMatch { claim, value }) => {
                if let Some(actual) = get_claim_value(&claims.extra, &claims.sub, claim) {
                    if actual == *value {
                        return Ok((rule, Some(value.clone())));
                    }
                }
            }
            None => {
                // No match clause — this rule applies unconditionally
                return Ok((rule, None));
            }
        }
    }
    Err(AuthError::InvalidToken(
        "No access rule matched for this token".into(),
    ))
}

/// Find the first matching rule by optional matched_value (for policy_for_requester_type lookups).
/// If matched_value is Some, find a rule whose match_clause.value matches.
/// If matched_value is None, find a rule without a match_clause.
fn find_matching_rule<'a>(
    rules: &'a [AccessRule],
    matched_value: Option<&str>,
) -> Option<&'a AccessRule> {
    match matched_value {
        Some(val) => rules
            .iter()
            .find(|r| r.match_clause.as_ref().is_some_and(|m| m.value == val)),
        None => rules.iter().find(|r| r.match_clause.is_none()),
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

/// Convert an AccessRule from the CRD into the runtime Policy struct.
fn access_rule_to_policy(rule: &AccessRule) -> crate::api::policy::Policy {
    let max_ttl = parse_duration(&rule.max_ttl).unwrap_or_else(|| {
        warn!(
            raw_value = %rule.max_ttl,
            "Failed to parse max_ttl, defaulting to 1h"
        );
        chrono::Duration::hours(1)
    });
    crate::api::policy::Policy {
        allowed_pools: rule.pools.clone(),
        max_ttl,
        max_concurrent_leases: rule.max_concurrent_leases,
        default_priority: 50,
        max_extensions: rule.max_extensions,
    }
}

/// Peek at the unverified `iss` claim from a JWT without signature validation.
///
/// Used to pre-select the correct provider before full token verification,
/// preventing cross-provider token acceptance.
fn peek_issuer(token: &str, header: &jsonwebtoken::Header) -> Result<String, AuthError> {
    let mut validation = Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::new();

    let dummy_key = DecodingKey::from_secret(b"");

    #[derive(Deserialize)]
    struct IssClaim {
        iss: String,
    }

    let data = decode::<IssClaim>(token, &dummy_key, &validation)
        .map_err(|e| AuthError::InvalidToken(format!("Failed to peek at JWT issuer: {e}")))?;

    Ok(data.claims.iss)
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

    // --- find_matching_rule_with_claims tests ---

    #[test]
    fn test_find_rule_no_match_clause() {
        let rules = vec![AccessRule {
            match_clause: None,
            pools: vec!["*".to_string()],
            max_ttl: "1h".to_string(),
            max_concurrent_leases: 5,
            max_extensions: 2,
        }];
        let claims = make_claims("test-sub", HashMap::new());
        let (rule, matched) = find_matching_rule_with_claims(&rules, &claims).unwrap();
        assert_eq!(rule.pools, vec!["*"]);
        assert!(matched.is_none());
    }

    #[test]
    fn test_find_rule_with_match_clause() {
        let rules = vec![
            AccessRule {
                match_clause: Some(ClaimMatch {
                    claim: "org_role".to_string(),
                    value: "org:admin".to_string(),
                }),
                pools: vec!["*".to_string()],
                max_ttl: "8h".to_string(),
                max_concurrent_leases: 10,
                max_extensions: 5,
            },
            AccessRule {
                match_clause: None,
                pools: vec!["dev-*".to_string()],
                max_ttl: "1h".to_string(),
                max_concurrent_leases: 3,
                max_extensions: 1,
            },
        ];

        // First rule matches
        let mut extra = HashMap::new();
        extra.insert(
            "org_role".to_string(),
            serde_json::Value::String("org:admin".to_string()),
        );
        let claims = make_claims("test-sub", extra);
        let (rule, matched) = find_matching_rule_with_claims(&rules, &claims).unwrap();
        assert_eq!(rule.max_ttl, "8h");
        assert_eq!(matched, Some("org:admin".to_string()));

        // No claim match — falls through to unconditional rule
        let claims = make_claims("test-sub", HashMap::new());
        let (rule, matched) = find_matching_rule_with_claims(&rules, &claims).unwrap();
        assert_eq!(rule.max_ttl, "1h");
        assert!(matched.is_none());
    }

    #[test]
    fn test_find_rule_nested_claim_match() {
        let rules = vec![AccessRule {
            match_clause: Some(ClaimMatch {
                claim: "private_metadata.role".to_string(),
                value: "admin".to_string(),
            }),
            pools: vec!["*".to_string()],
            max_ttl: "4h".to_string(),
            max_concurrent_leases: 10,
            max_extensions: 5,
        }];

        let mut extra = HashMap::new();
        extra.insert(
            "private_metadata".to_string(),
            serde_json::json!({"role": "admin"}),
        );
        let claims = make_claims("test-sub", extra);
        let (rule, matched) = find_matching_rule_with_claims(&rules, &claims).unwrap();
        assert_eq!(rule.max_ttl, "4h");
        assert_eq!(matched, Some("admin".to_string()));
    }

    #[test]
    fn test_find_rule_no_match() {
        let rules = vec![AccessRule {
            match_clause: Some(ClaimMatch {
                claim: "role".to_string(),
                value: "admin".to_string(),
            }),
            pools: vec!["*".to_string()],
            max_ttl: "1h".to_string(),
            max_concurrent_leases: 5,
            max_extensions: 2,
        }];
        let claims = make_claims("test-sub", HashMap::new());
        assert!(find_matching_rule_with_claims(&rules, &claims).is_err());
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

    // --- access_rule_to_policy tests ---

    #[test]
    fn test_access_rule_to_policy_valid() {
        let rule = AccessRule {
            match_clause: None,
            pools: vec!["e2e-*".to_string()],
            max_ttl: "2h".to_string(),
            max_concurrent_leases: 5,
            max_extensions: 3,
        };
        let policy = access_rule_to_policy(&rule);
        assert_eq!(policy.max_ttl, chrono::Duration::hours(2));
        assert_eq!(policy.allowed_pools, vec!["e2e-*"]);
        assert_eq!(policy.max_concurrent_leases, 5);
        assert_eq!(policy.max_extensions, 3);
    }

    #[test]
    fn test_access_rule_to_policy_invalid_duration() {
        let rule = AccessRule {
            match_clause: None,
            pools: vec!["dev-*".to_string()],
            max_ttl: "invalid".to_string(),
            max_concurrent_leases: 1,
            max_extensions: 0,
        };
        let policy = access_rule_to_policy(&rule);
        // Should default to 1h (3600s) when parsing fails
        assert_eq!(policy.max_ttl, chrono::Duration::hours(1));
    }

    #[test]
    fn test_access_rule_to_policy_wildcard_pools() {
        let rule = AccessRule {
            match_clause: None,
            pools: vec!["*".to_string()],
            max_ttl: "30m".to_string(),
            max_concurrent_leases: 10,
            max_extensions: 2,
        };
        let policy = access_rule_to_policy(&rule);
        assert_eq!(policy.allowed_pools, vec!["*"]);
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
    fn test_find_key_ec_unsupported_before_was_now_supported() {
        let keys = vec![Jwk {
            kid: Some("ec-kid".to_string()),
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: Some("test-x".to_string()),
            y: Some("test-y".to_string()),
            crv: Some("P-256".to_string()),
        }];
        // EC keys are now supported — should not return "Unsupported key type"
        let result = JwtAuthenticator::find_key(&keys, Some("ec-kid"));
        // May fail due to invalid key data, but should NOT be "Unsupported key type"
        match result {
            Ok(_) => {} // valid key was constructed
            Err(AuthError::InvalidToken(msg)) => {
                assert!(
                    !msg.contains("Unsupported key type"),
                    "EC should be supported, got: {msg}"
                );
            }
            Err(e) => panic!("Unexpected error type: {e:?}"),
        }
    }

    #[test]
    fn test_find_key_ec_missing_components() {
        let keys = vec![Jwk {
            kid: Some("ec-kid".to_string()),
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: Some("test-x".to_string()),
            y: None, // missing y
            crv: Some("P-256".to_string()),
        }];
        let result = JwtAuthenticator::find_key(&keys, Some("ec-kid"));
        assert!(
            matches!(result, Err(AuthError::InvalidToken(msg)) if msg.contains("EC key missing 'y'"))
        );
    }

    #[test]
    fn test_find_key_okp_supported() {
        let keys = vec![Jwk {
            kid: Some("okp-kid".to_string()),
            kty: "OKP".to_string(),
            n: None,
            e: None,
            x: Some("test-x".to_string()),
            y: None,
            crv: Some("Ed25519".to_string()),
        }];
        let result = JwtAuthenticator::find_key(&keys, Some("okp-kid"));
        match result {
            Ok(_) => {}
            Err(AuthError::InvalidToken(msg)) => {
                assert!(
                    !msg.contains("Unsupported key type"),
                    "OKP should be supported, got: {msg}"
                );
            }
            Err(e) => panic!("Unexpected error type: {e:?}"),
        }
    }

    #[test]
    fn test_find_key_okp_missing_x() {
        let keys = vec![Jwk {
            kid: Some("okp-kid".to_string()),
            kty: "OKP".to_string(),
            n: None,
            e: None,
            x: None, // missing x
            y: None,
            crv: Some("Ed25519".to_string()),
        }];
        let result = JwtAuthenticator::find_key(&keys, Some("okp-kid"));
        assert!(
            matches!(result, Err(AuthError::InvalidToken(msg)) if msg.contains("OKP key missing 'x'"))
        );
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

        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "test-policy" },
            "spec": {
                "auth": {
                    "oidc": {
                        "issuer": "https://example.com",
                        "audience": ["test-aud"],
                        "algorithms": ["RS256"]
                    }
                },
                "rules": [{
                    "pools": ["*"],
                    "maxTtl": "1h",
                    "maxConcurrentLeases": 10
                }]
            }
        }))
        .unwrap();

        auth.update_policies(vec![policy]).await;

        // No match clause — look up by policy name alone
        let result = auth.policy_for_requester_type("test-policy").await;
        assert!(result.is_some());
        let policy = result.unwrap();
        assert_eq!(policy.allowed_pools, vec!["*"]);
        assert_eq!(policy.max_ttl, chrono::Duration::hours(1));
        assert_eq!(policy.max_concurrent_leases, 10);
    }

    #[tokio::test]
    async fn test_policy_for_requester_type_format() {
        let auth = JwtAuthenticator::new();

        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "my-policy" },
            "spec": {
                "auth": {
                    "oidc": {
                        "issuer": "https://issuer.example.com",
                        "audience": [],
                        "algorithms": ["RS256"]
                    }
                },
                "rules": [{
                    "pools": ["e2e-*"],
                    "maxTtl": "2h",
                    "maxConcurrentLeases": 3
                }]
            }
        }))
        .unwrap();

        auth.update_policies(vec![policy]).await;

        // Policy name alone should find the rule (no match clause)
        assert!(auth.policy_for_requester_type("my-policy").await.is_some());

        // Wrong policy name should not find
        assert!(
            auth.policy_for_requester_type("other-policy")
                .await
                .is_none()
        );

        // With a match value but no match clause rules — should not find
        assert!(
            auth.policy_for_requester_type("my-policy:admin")
                .await
                .is_none()
        );
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
