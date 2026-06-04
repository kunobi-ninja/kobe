use std::collections::HashMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use kunobi_auth::secret_eq;
use kunobi_auth::server::ssh::{CompiledSshProvider, NonceTracker, ParsedAuthorizedKey};
use kunobi_auth::server::{JwksManager, verify_azp};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::crd::access_policy::{AccessPolicy, AccessRule, ClaimMatch};
use crate::pool::parse_duration;

/// Generic JWT claims — captures all claims from any OIDC provider.
///
/// Built by deserializing the validated claim map returned by
/// [`kunobi_auth::server::JwksManager::validate_jwt`], for kobe-specific rule
/// matching and identity templating.
#[derive(Debug, Deserialize)]
struct GenericClaims {
    iss: String,
    sub: String,
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

/// Auth method info for the /v1/status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethodInfo {
    #[serde(rename = "type")]
    pub method_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Service audience for SSH signature namespace binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
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
    /// Allowed signing algorithms as their string names (e.g. `"RS256"`), passed
    /// to [`JwksManager::validate_jwt`] which parses + enforces them.
    algorithms: Vec<String>,
    identity_template: String,
    /// Flat rules list — first matching rule wins.
    rules: Vec<AccessRule>,
}

/// A compiled static token provider, built from an AccessPolicy + Secret.
#[derive(Debug, Clone)]
struct CompiledTokenProvider {
    name: String,
    token: String,
    rules: Vec<AccessRule>,
}

/// A compiled SSH policy provider, pairing kunobi-auth's CompiledSshProvider
/// with kobe-specific authorization rules.
struct CompiledSshPolicyProvider {
    provider: CompiledSshProvider,
    rules: Vec<AccessRule>,
}

/// JWT authenticator supporting any OIDC provider via AccessPolicy CRDs.
pub struct JwtAuthenticator {
    /// JWKS fetch/cache + JWT signature/iss/aud/exp/nbf/alg verification,
    /// delegated to kunobi-auth so the rules stay shared across services.
    jwks: JwksManager,
    /// Compiled OIDC providers from AccessPolicy CRDs.
    providers: RwLock<Vec<CompiledProvider>>,
    /// Compiled SSH providers from AccessPolicy CRDs.
    ssh_providers: RwLock<Vec<CompiledSshPolicyProvider>>,
    /// Compiled static token providers from AccessPolicy CRDs + referenced Secrets.
    token_providers: RwLock<Vec<CompiledTokenProvider>>,
    /// Nonce tracker for SSH replay protection.
    nonce_tracker: NonceTracker,
    /// SSHSIG namespace (e.g. "kobe-system").
    ssh_namespace: String,
}

impl JwtAuthenticator {
    pub fn new(ssh_namespace: String) -> Self {
        Self {
            jwks: JwksManager::new(),
            providers: RwLock::new(Vec::new()),
            ssh_providers: RwLock::new(Vec::new()),
            token_providers: RwLock::new(Vec::new()),
            nonce_tracker: NonceTracker::new(std::time::Duration::from_secs(60)),
            ssh_namespace,
        }
    }

    /// Recompile the provider lookup table from AccessPolicy CRDs.
    /// Called by the AccessPolicy watcher whenever CRDs change.
    pub async fn update_policies(
        &self,
        policies: Vec<AccessPolicy>,
        token_secrets: HashMap<String, String>,
    ) {
        let mut oidc_policies = Vec::new();
        let mut token_policies = Vec::new();
        let mut ssh_policies = Vec::new();
        for policy in policies {
            if policy.spec.auth.ssh.is_some() {
                ssh_policies.push(policy);
            } else if policy.spec.auth.token.is_some() {
                token_policies.push(policy);
            } else {
                oidc_policies.push(policy);
            }
        }

        // Compile OIDC providers
        let compiled: Vec<CompiledProvider> = oidc_policies
            .into_iter()
            .filter_map(|ap| {
                let policy_name = ap.metadata.name.unwrap_or_default();
                let spec = ap.spec;

                // Only OIDC auth is supported for JWT validation currently
                let oidc = spec.auth.oidc?;

                let jwks_url = oidc
                    .jwks_url
                    .unwrap_or_else(|| format!("{}/.well-known/jwks.json", oidc.issuer));

                // Keep only algorithm names kunobi-auth can parse; it re-parses
                // and enforces them in `validate_jwt`.
                let algorithms: Vec<String> = oidc
                    .algorithms
                    .iter()
                    .filter(|a| parse_algorithm(a).is_some())
                    .cloned()
                    .collect();

                if algorithms.is_empty() {
                    warn!(
                        provider = %policy_name,
                        "No valid algorithms configured, skipping provider"
                    );
                    return None;
                }

                // `validate_jwt` refuses an empty audience (it is required for
                // token-confusion safety). Warn at compile time so an operator
                // sees the misconfiguration before tokens start being rejected.
                if oidc.audience.is_empty() {
                    warn!(
                        provider = %policy_name,
                        "OIDC provider has no audience configured; tokens will be \
                         rejected until `audience` is set"
                    );
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
        debug!(providers = count, "OIDC access policies updated");

        // Compile SSH providers
        let ssh_compiled: Vec<CompiledSshPolicyProvider> = ssh_policies
            .into_iter()
            .filter_map(|ap| {
                let policy_name = ap.metadata.name.unwrap_or_default();
                let spec = ap.spec;
                let ssh = spec.auth.ssh?;

                let mut keys: Vec<ParsedAuthorizedKey> = Vec::new();
                for key_str in &ssh.authorized_keys {
                    match kunobi_auth::server::ssh::parse_authorized_key(key_str) {
                        Ok(parsed) => keys.push(parsed),
                        Err(e) => {
                            warn!(provider = %policy_name, key = %key_str, "Skipping SSH key: {e}")
                        }
                    }
                }

                if keys.is_empty() {
                    warn!(provider = %policy_name, "No valid SSH keys, skipping");
                    return None;
                }

                let mut revoked_fingerprints = std::collections::HashSet::new();
                for key_str in &ssh.revoked_keys {
                    if let Ok(parsed) = kunobi_auth::server::ssh::parse_authorized_key(key_str) {
                        revoked_fingerprints.insert(parsed.fingerprint);
                    }
                }

                Some(CompiledSshPolicyProvider {
                    provider: CompiledSshProvider {
                        name: policy_name,
                        keys,
                        revoked_fingerprints,
                        identity_template: spec.identity,
                    },
                    rules: spec.rules,
                })
            })
            .collect();

        let ssh_count = ssh_compiled.len();
        *self.ssh_providers.write().await = ssh_compiled;
        debug!(ssh_providers = ssh_count, "SSH policies updated");

        let token_compiled: Vec<CompiledTokenProvider> = token_policies
            .into_iter()
            .filter_map(|ap| {
                let policy_name = ap.metadata.name.unwrap_or_default();
                let spec = ap.spec;
                let token_auth = spec.auth.token?;
                let token = match token_secrets.get(&token_auth.secret_ref) {
                    Some(token) if !token.is_empty() => token.clone(),
                    _ => {
                        warn!(
                            provider = %policy_name,
                            secret_ref = %token_auth.secret_ref,
                            "Missing or empty token Secret, skipping token provider"
                        );
                        return None;
                    }
                };

                Some(CompiledTokenProvider {
                    name: policy_name,
                    token,
                    rules: spec.rules,
                })
            })
            .collect();

        let token_count = token_compiled.len();
        *self.token_providers.write().await = token_compiled;
        debug!(
            token_providers = token_count,
            "Static token policies updated"
        );
    }

    /// Return the list of supported auth methods for the /v1/status endpoint.
    pub async fn auth_methods(&self) -> Vec<AuthMethodInfo> {
        let providers = self.providers.read().await;
        let ssh_providers = self.ssh_providers.read().await;
        let token_providers = self.token_providers.read().await;

        let mut methods: Vec<AuthMethodInfo> = providers
            .iter()
            .map(|p| AuthMethodInfo {
                method_type: "oidc".to_string(),
                issuer: Some(p.issuer.clone()),
                client_id: None, // TODO: expose client_id for CLI discovery
                description: Some(p.name.clone()),
                audience: None,
            })
            .collect();

        for sp in ssh_providers.iter() {
            methods.push(AuthMethodInfo {
                method_type: "ssh".to_string(),
                issuer: None,
                client_id: None,
                description: Some(sp.provider.name.clone()),
                audience: Some(self.ssh_namespace.clone()),
            });
        }

        for tp in token_providers.iter() {
            methods.push(AuthMethodInfo {
                method_type: "token".to_string(),
                issuer: None,
                client_id: None,
                description: Some(tp.name.clone()),
                audience: None,
            });
        }

        methods
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
        if let Some(provider) = providers.iter().find(|p| p.name == policy_name) {
            let rule = find_matching_rule(&provider.rules, matched_value)?;
            return Some(access_rule_to_policy(rule));
        }
        drop(providers);

        let ssh_providers = self.ssh_providers.read().await;
        if let Some(provider) = ssh_providers
            .iter()
            .find(|p| p.provider.name == policy_name)
        {
            let rule = find_matching_rule(&provider.rules, matched_value)?;
            return Some(access_rule_to_policy(rule));
        }
        drop(ssh_providers);

        let token_providers = self.token_providers.read().await;
        let provider = token_providers.iter().find(|p| p.name == policy_name)?;
        let rule = find_matching_rule(&provider.rules, matched_value)?;
        Some(access_rule_to_policy(rule))
    }

    /// Validate an SSH-signed request and return the authenticated identity.
    pub async fn validate_ssh(
        &self,
        ssh_header: &str,
        method: &str,
        path_with_query: &str,
        body: Option<&[u8]>,
    ) -> Result<AuthIdentity, AuthError> {
        let parsed = kunobi_auth::server::ssh::parse_ssh_auth_header(ssh_header)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        if self.nonce_tracker.check_and_insert(&parsed.nonce).await {
            return Err(AuthError::InvalidToken("Replayed nonce".into()));
        }

        let ssh_providers = self.ssh_providers.read().await;
        let body = body.unwrap_or(b"");

        // Build a slice of CompiledSshProvider for the kunobi-auth verify function.
        let raw_providers: Vec<CompiledSshProvider> =
            ssh_providers.iter().map(|p| p.provider.clone()).collect();

        let verified = kunobi_auth::server::ssh::verify_ssh_signature(
            &parsed,
            &self.ssh_namespace,
            method,
            path_with_query,
            body,
            &raw_providers,
            std::time::Duration::from_secs(30),
        )
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Find the matching kobe policy provider.
        let policy_provider = ssh_providers
            .iter()
            .find(|p| p.provider.name == verified.provider_name)
            .ok_or_else(|| {
                AuthError::InvalidToken("Provider not found after verification".into())
            })?;

        // SSH policies use a single unconditional rule (no claim matching).
        let rule = find_matching_rule(&policy_provider.rules, None).ok_or_else(|| {
            AuthError::InvalidToken("No access rule configured for SSH provider".into())
        })?;

        Ok(AuthIdentity {
            requester_type: verified.provider_name,
            identity: verified.identity,
            issuer: "ssh".to_string(),
            policy: access_rule_to_policy(rule),
        })
    }

    /// Validate a JWT and return the authenticated identity.
    ///
    /// Peeks at the unverified `iss` claim to select the correct provider(s),
    /// then validates the token signature and claims against that provider's JWKS.
    pub async fn validate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        {
            let token_providers = self.token_providers.read().await;
            if let Some(provider) = token_providers.iter().find(|p| secret_eq(&p.token, token)) {
                let rule = find_matching_rule(&provider.rules, None).ok_or_else(|| {
                    AuthError::InvalidToken(
                        "No access rule configured for static token provider".into(),
                    )
                })?;

                debug!(
                    requester_type = %provider.name,
                    provider = %provider.name,
                    "Static token validated"
                );

                return Ok(AuthIdentity {
                    requester_type: provider.name.clone(),
                    identity: provider.name.clone(),
                    issuer: "token".to_string(),
                    policy: access_rule_to_policy(rule),
                });
            }
        }

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
            match self.validate_with_provider(token, provider).await {
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
    ///
    /// Delegates signature / issuer / audience / exp / nbf / algorithm checks to
    /// [`JwksManager::validate_jwt`] (which fetches + caches JWKS and refuses an
    /// empty audience), then enforces `azp` via the shared [`verify_azp`] helper,
    /// before kobe-specific rule matching and identity templating.
    async fn validate_with_provider(
        &self,
        token: &str,
        provider: &CompiledProvider,
    ) -> Result<AuthIdentity, AuthError> {
        let claims_map = self
            .jwks
            .validate_jwt(
                token,
                &provider.jwks_url,
                &provider.issuer,
                &provider.audience,
                &provider.algorithms,
            )
            .await
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        verify_azp(&claims_map, &provider.authorized_parties)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let claims: GenericClaims =
            serde_json::from_value(serde_json::Value::Object(claims_map.into_iter().collect()))
                .map_err(|e| AuthError::InvalidToken(format!("malformed claims: {e}")))?;

        // Find matching rule — iterate rules, check match clauses against claims
        let (rule, matched_value) = find_matching_rule_with_claims(&provider.rules, &claims)?;

        // Format identity from template
        let identity = format_identity(&provider.identity_template, &claims);

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
            issuer: claims.iss,
            policy: access_rule_to_policy(rule),
        })
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
                if let Some(actual) = get_claim_value(&claims.extra, &claims.sub, claim)
                    && actual == *value
                {
                    return Ok((rule, Some(value.clone())));
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

        // SSH-Signature path
        if let Some(ssh_header) = auth_header.strip_prefix("SSH-Signature ") {
            let method = parts.method.as_str();
            let path_with_query = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or(parts.uri.path());

            return state
                .authenticator
                .validate_ssh(ssh_header, method, path_with_query, None)
                .await
                .map_err(|e| {
                    warn!(
                        method = method,
                        path = path_with_query,
                        error = %e,
                        "SSH authentication failed"
                    );
                    axum::http::StatusCode::UNAUTHORIZED
                });
        }

        // Bearer token path (existing OIDC/JWT)
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

        let method = parts.method.as_str();
        let path_with_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(parts.uri.path());

        state.authenticator.validate(token).await.map_err(|e| {
            warn!(
                method = method,
                path = path_with_query,
                error = %e,
                "Bearer authentication failed"
            );
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

    // --- JwtAuthenticator async tests ---

    #[tokio::test]
    async fn test_authenticator_new_has_no_providers() {
        let auth = JwtAuthenticator::new("test".to_string());
        let result = auth.policy_for_requester_type("anything:role").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_policies_compiles_providers() {
        let auth = JwtAuthenticator::new("test".to_string());

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

        auth.update_policies(vec![policy], HashMap::new()).await;

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
        let auth = JwtAuthenticator::new("test".to_string());

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

        auth.update_policies(vec![policy], HashMap::new()).await;

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
        let auth = JwtAuthenticator::new("test".to_string());
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

    #[tokio::test]
    async fn test_validate_static_token() {
        let auth = JwtAuthenticator::new("test".to_string());

        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "local-token" },
            "spec": {
                "auth": {
                    "token": {
                        "secretRef": "local-token-secret"
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

        let mut token_secrets = HashMap::new();
        token_secrets.insert(
            "local-token-secret".to_string(),
            "e2e-dev-token".to_string(),
        );

        auth.update_policies(vec![policy], token_secrets).await;

        let identity = auth.validate("e2e-dev-token").await.unwrap();
        assert_eq!(identity.requester_type, "local-token");
        assert_eq!(identity.identity, "local-token");
        assert_eq!(identity.issuer, "token");
        assert_eq!(identity.policy.allowed_pools, vec!["*"]);
    }
}
