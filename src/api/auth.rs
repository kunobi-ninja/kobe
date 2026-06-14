use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::Algorithm;
use kunobi_auth::server::ssh::{CompiledSshProvider, NonceTracker, ParsedAuthorizedKey};
use kunobi_auth::server::{
    AuthBuilder, AuthEvent, AuthObserver, AuthnProvider, ConfiguredAuth, JwtAuthConfig,
};
use kunobi_auth::{AuthFailReason, KunobiAuthDiscovery};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::crd::access_policy::{AccessPolicy, AccessRule, ClaimMatch};
use crate::pool::parse_duration;

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

/// kobe's authorization context for one Bearer-validatable provider (OIDC or
/// static token), recovered after kunobi-auth verifies the credential.
struct ProviderAuthz {
    rules: Vec<AccessRule>,
    kind: ProviderKind,
}

enum ProviderKind {
    /// OIDC provider: identity is rendered from the template over the JWT claims.
    Oidc {
        issuer: String,
        /// OAuth client ID for interactive CLI login (`/v1/status` +
        /// `/.well-known/kunobi-auth`). `None` for machine-only providers.
        client_id: Option<String>,
        identity_template: String,
    },
    /// Static bearer token: identity is the provider name, issuer is `"token"`.
    Token,
}

/// An atomically-published snapshot of the Bearer-auth configuration: the
/// kunobi-auth verifier plus kobe's per-provider authorization context, kept in
/// one value so a request never observes a verifier provider whose rules aren't
/// published yet (or vice versa).
struct AuthSnapshot {
    /// kunobi-auth verifier (static-token + JWT signature/iss/aud/azp/exp/nbf),
    /// with kobe's [`AuthObserver`] wired in for telemetry.
    configured: Arc<ConfiguredAuth>,
    /// Provider name -> kobe authorization context (rules + identity source).
    by_provider: HashMap<String, ProviderAuthz>,
    /// The OIDC provider advertised at `/.well-known/kunobi-auth` for interactive
    /// CLI login — the one with a `client_id` set. `None` when no provider
    /// configures interactive login.
    discovery: Option<KunobiAuthDiscovery>,
}

/// A compiled SSH policy provider, pairing kunobi-auth's CompiledSshProvider
/// with kobe-specific authorization rules.
struct CompiledSshPolicyProvider {
    provider: CompiledSshProvider,
    rules: Vec<AccessRule>,
}

/// Feeds credential-verification FAILURES into kobe's metrics, tagged with the
/// precise [`AuthFailReason`] from kunobi-auth (bad signature, expired, audience
/// mismatch, …). Registered on the [`ConfiguredAuth`].
///
/// `Success` is deliberately NOT counted here: kunobi verifies the *credential*,
/// but kobe's authorization (rule -> Policy) runs afterwards and can still
/// reject. [`JwtAuthenticator::validate`] emits `AUTH_SUCCESS_TOTAL` only once a
/// request is fully authenticated AND authorized, and emits the kobe-side
/// authorization failures the observer never sees — so the counters stay honest
/// end-to-end (and symmetric with the SSH path).
struct KobeAuthObserver;

impl AuthObserver for KobeAuthObserver {
    fn observe(&self, event: AuthEvent<'_>) {
        if let AuthEvent::Failure { provider, reason } = event {
            crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&[provider.unwrap_or("unknown"), reason.label()])
                .inc();
        }
    }
}

/// JWT authenticator supporting any OIDC provider via AccessPolicy CRDs.
///
/// Credential verification (static token + JWT) is delegated to kunobi-auth's
/// [`ConfiguredAuth`]; kobe layers authorization (rule -> Policy resolution),
/// identity templating, and the SSH path on top.
pub struct JwtAuthenticator {
    /// Atomically-swapped Bearer-auth config, rebuilt on every policy change.
    auth: RwLock<Arc<AuthSnapshot>>,
    /// Compiled SSH providers (kobe-side; SSH is not modeled by ConfiguredAuth).
    ssh_providers: RwLock<Vec<CompiledSshPolicyProvider>>,
    /// Nonce tracker for SSH replay protection (survives policy rebuilds).
    nonce_tracker: NonceTracker,
    /// SSHSIG namespace (e.g. "kobe-system").
    ssh_namespace: String,
    /// Telemetry hook, shared across every ConfiguredAuth rebuild.
    observer: Arc<KobeAuthObserver>,
    /// JWT clock-skew tolerance applied on each rebuild (None = kunobi-auth's 60s).
    leeway: Option<Duration>,
}

impl JwtAuthenticator {
    pub fn new(ssh_namespace: String) -> Self {
        // Optional operator override for JWT clock-skew tolerance; unset keeps
        // kunobi-auth's implicit 60s default, matching prior behavior exactly.
        let leeway = std::env::var("KOBE_JWT_LEEWAY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);

        Self {
            auth: RwLock::new(Arc::new(AuthSnapshot {
                configured: Arc::new(AuthBuilder::new().build()),
                by_provider: HashMap::new(),
                discovery: None,
            })),
            ssh_providers: RwLock::new(Vec::new()),
            nonce_tracker: NonceTracker::new(std::time::Duration::from_secs(60)),
            ssh_namespace,
            observer: Arc::new(KobeAuthObserver),
            leeway,
        }
    }

    /// Load the current Bearer-auth snapshot (cheap `Arc` clone; lock released).
    async fn snapshot(&self) -> Arc<AuthSnapshot> {
        self.auth.read().await.clone()
    }

    /// The auth-discovery document served at `/.well-known/kunobi-auth` — the
    /// OIDC provider designated for interactive CLI login (the one with a
    /// `clientId`), or `None` when no provider configures interactive login.
    pub async fn discovery_metadata(&self) -> Option<KunobiAuthDiscovery> {
        self.snapshot().await.discovery.clone()
    }

    /// Recompile the auth configuration from AccessPolicy CRDs. Called by the
    /// AccessPolicy watcher whenever CRDs change. Rebuilds the kunobi-auth
    /// verifier + kobe's authorization context into one new [`AuthSnapshot`]
    /// (published atomically); SSH providers are swapped separately.
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

        // Build the kunobi-auth verifier (JWT + static token) and kobe's
        // per-provider authorization context together, so they stay coherent.
        let mut builder = AuthBuilder::new().observer(self.observer.clone());
        if let Some(leeway) = self.leeway {
            builder = builder.leeway(leeway);
        }
        let mut by_provider: HashMap<String, ProviderAuthz> = HashMap::new();
        // OIDC providers that set a `clientId` — candidates for the
        // /.well-known/kunobi-auth discovery document. (name, doc) pairs.
        let mut discovery_candidates: Vec<(String, KunobiAuthDiscovery)> = Vec::new();

        // OIDC providers
        for ap in oidc_policies {
            let policy_name = ap.metadata.name.unwrap_or_default();
            let spec = ap.spec;
            let Some(oidc) = spec.auth.oidc else { continue };

            let jwks_url = oidc
                .jwks_url
                .unwrap_or_else(|| format!("{}/.well-known/jwks.json", oidc.issuer));

            // Keep only algorithm names kunobi-auth can parse; it re-parses and
            // enforces them in validate_jwt_bound.
            let algorithms: Vec<String> = oidc
                .algorithms
                .iter()
                .filter(|a| parse_algorithm(a).is_some())
                .cloned()
                .collect();
            if algorithms.is_empty() {
                warn!(provider = %policy_name, "No valid algorithms configured, skipping provider");
                continue;
            }

            // A provider must bind tokens by `audience` or `authorizedParties`
            // (azp); with neither, any validly-signed token from the issuer would
            // be accepted (token confusion). validate_jwt_bound rejects that at
            // runtime, but skip it at compile time too with a clear warning.
            if oidc.audience.is_empty() && oidc.authorized_parties.is_empty() {
                warn!(
                    provider = %policy_name,
                    "OIDC provider sets neither audience nor authorizedParties; \
                     skipping (tokens cannot be bound safely)"
                );
                continue;
            }

            // Capture discovery data before oidc's fields move into the builder.
            let client_id = oidc.client_id.clone();
            let discovery_audience = oidc.audience.first().cloned();
            let issuer = oidc.issuer.clone();

            builder = builder.jwt(
                JwtAuthConfig::oidc(policy_name.clone(), issuer.clone(), jwks_url, oidc.audience)
                    .authorized_parties(oidc.authorized_parties)
                    .algorithms(algorithms)
                    // Enforces "sub present and a string" (kobe's historical
                    // contract); kobe derives the real identity from the template.
                    .identity_claim("sub"),
            );

            // A `clientId` marks this provider as the interactive-login target
            // advertised at /.well-known/kunobi-auth.
            if let Some(cid) = &client_id {
                discovery_candidates.push((
                    policy_name.clone(),
                    KunobiAuthDiscovery {
                        issuer: issuer.clone(),
                        client_id: cid.clone(),
                        audience: discovery_audience,
                    },
                ));
            }

            by_provider.insert(
                policy_name,
                ProviderAuthz {
                    rules: spec.rules,
                    kind: ProviderKind::Oidc {
                        issuer,
                        client_id,
                        identity_template: spec.identity,
                    },
                },
            );
        }

        // Static token providers
        for ap in token_policies {
            let policy_name = ap.metadata.name.unwrap_or_default();
            let spec = ap.spec;
            let Some(token_auth) = spec.auth.token else {
                continue;
            };
            let token = match token_secrets.get(&token_auth.secret_ref) {
                Some(token) if !token.is_empty() => token.clone(),
                _ => {
                    warn!(
                        provider = %policy_name,
                        secret_ref = %token_auth.secret_ref,
                        "Missing or empty token Secret, skipping token provider"
                    );
                    continue;
                }
            };
            // Static identity = provider name (kobe's historical behavior).
            builder = builder.static_token(policy_name.clone(), token, policy_name.clone());
            by_provider.insert(
                policy_name,
                ProviderAuthz {
                    rules: spec.rules,
                    kind: ProviderKind::Token,
                },
            );
        }

        let oidc_count = by_provider
            .values()
            .filter(|p| matches!(p.kind, ProviderKind::Oidc { .. }))
            .count();
        let token_count = by_provider.len() - oidc_count;

        // Discovery doc: the OIDC provider designated for interactive CLI login
        // (the one with a clientId). Pick deterministically by name; warn if
        // several configure interactive login (only one can be advertised).
        discovery_candidates.sort_by(|a, b| a.0.cmp(&b.0));
        if discovery_candidates.len() > 1 {
            warn!(
                count = discovery_candidates.len(),
                chosen = %discovery_candidates[0].0,
                "Multiple OIDC providers set a clientId; advertising the \
                 first by name at /.well-known/kunobi-auth"
            );
        }
        let discovery = discovery_candidates.into_iter().next().map(|(_, doc)| doc);

        // Publish the new Bearer-auth snapshot atomically (one swap keeps the
        // verifier and the rule table coherent for every in-flight request).
        *self.auth.write().await = Arc::new(AuthSnapshot {
            configured: Arc::new(builder.build()),
            by_provider,
            discovery,
        });
        debug!(
            oidc_providers = oidc_count,
            token_providers = token_count,
            "Bearer auth config updated"
        );

        // SSH providers (kobe-side; swapped independently of the Bearer config).
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
    }

    /// Return the list of supported auth methods for the /v1/status endpoint.
    pub async fn auth_methods(&self) -> Vec<AuthMethodInfo> {
        let snap = self.snapshot().await;
        let ssh_providers = self.ssh_providers.read().await;

        let mut methods: Vec<AuthMethodInfo> = snap
            .by_provider
            .iter()
            .map(|(name, pa)| match &pa.kind {
                ProviderKind::Oidc {
                    issuer, client_id, ..
                } => AuthMethodInfo {
                    method_type: "oidc".to_string(),
                    issuer: Some(issuer.clone()),
                    client_id: client_id.clone(),
                    description: Some(name.clone()),
                    audience: None,
                },
                ProviderKind::Token => AuthMethodInfo {
                    method_type: "token".to_string(),
                    issuer: None,
                    client_id: None,
                    description: Some(name.clone()),
                    audience: None,
                },
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

        // `by_provider` is a HashMap, so sort for a stable /v1/status response.
        // method_type order ("oidc" < "ssh" < "token") matches the prior layout.
        methods.sort_by(|a, b| {
            (a.method_type.as_str(), a.description.as_deref())
                .cmp(&(b.method_type.as_str(), b.description.as_deref()))
        });
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

        // Bearer providers (OIDC + static token) live in the snapshot.
        let snap = self.snapshot().await;
        if let Some(pa) = snap.by_provider.get(policy_name) {
            let rule = find_matching_rule(&pa.rules, matched_value)?;
            return Some(access_rule_to_policy(rule));
        }

        // SSH providers are kept separately.
        let ssh_providers = self.ssh_providers.read().await;
        let provider = ssh_providers
            .iter()
            .find(|p| p.provider.name == policy_name)?;
        let rule = find_matching_rule(&provider.rules, matched_value)?;
        Some(access_rule_to_policy(rule))
    }

    /// Validate an SSH-signed request and return the authenticated identity.
    ///
    /// Wraps [`Self::validate_ssh_inner`] to emit auth metrics: SSH runs outside
    /// kunobi-auth's `ConfiguredAuth`, so its outcomes never reach the
    /// `AuthObserver` — emit the same counters here for a uniform namespace.
    pub async fn validate_ssh(
        &self,
        ssh_header: &str,
        method: &str,
        path_with_query: &str,
        body: Option<&[u8]>,
    ) -> Result<AuthIdentity, AuthError> {
        let result = self
            .validate_ssh_inner(ssh_header, method, path_with_query, body)
            .await;
        match &result {
            Ok(id) => crate::metrics::AUTH_SUCCESS_TOTAL
                .with_label_values(&[id.requester_type.as_str(), "ssh"])
                .inc(),
            // The provider isn't attributable for most pre-verification failures.
            Err(_) => crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&["unknown", AuthFailReason::TokenRejected.label()])
                .inc(),
        }
        result
    }

    async fn validate_ssh_inner(
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

    /// Validate a Bearer credential (static token or JWT) and return the
    /// authenticated identity.
    ///
    /// Verification (static-token match, or JWT signature / iss / aud / azp /
    /// exp / nbf) is delegated to kunobi-auth's [`ConfiguredAuth`], which fires
    /// the [`AuthObserver`]. kobe then resolves the matched provider's rule into
    /// a [`Policy`](crate::api::policy::Policy) and renders the identity.
    pub async fn validate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let snap = self.snapshot().await;

        // No Bearer-validatable providers configured at all. ConfiguredAuth is
        // never called, so the observer doesn't see this — count it here.
        if snap.by_provider.is_empty() {
            crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&["unknown", AuthFailReason::NoMatchingProvider.label()])
                .inc();
            return Err(AuthError::InvalidToken(
                "No auth policies configured".into(),
            ));
        }

        // kunobi-auth verifies the credential; on failure the observer has
        // already counted it (with the precise reason), so just propagate.
        let kid = snap
            .configured
            .authenticate(token)
            .await
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Recover kobe's authorization context for the provider that accepted
        // the credential. The claims are already verified, so this is a pure,
        // cheap re-evaluation over trusted data — no re-parse, no JWKS re-fetch.
        // Authorization failures below are kobe-side (post-credential), so the
        // observer never sees them — count them here for honest telemetry.
        let Some(pa) = snap.by_provider.get(&kid.provider) else {
            // Invariant: a provider verified by this snapshot's ConfiguredAuth is
            // always in the same snapshot's by_provider. Count + reject defensively.
            crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&[kid.provider.as_str(), "no_matching_rule"])
                .inc();
            return Err(AuthError::InvalidToken(
                "verified provider missing from auth snapshot".into(),
            ));
        };

        let Some((rule, matched_value)) = match_rule(&pa.rules, &kid) else {
            // Credential verified but no AccessRule authorizes it (deny-by-default).
            crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&[kid.provider.as_str(), "no_matching_rule"])
                .inc();
            return Err(AuthError::InvalidToken(
                "No access rule matched for this token".into(),
            ));
        };

        let requester_type = match &matched_value {
            Some(val) => format!("{}:{}", kid.provider, val),
            None => kid.provider.clone(),
        };

        let (identity, issuer) = match &pa.kind {
            ProviderKind::Oidc {
                identity_template, ..
            } => (
                format_identity(identity_template, &kid),
                kid.claim_str("iss").unwrap_or_default(),
            ),
            // Static token: kunobi-auth sets kid.identity to the provider name;
            // the issuer is the "token" sentinel (kobe's historical behavior).
            ProviderKind::Token => (kid.identity.clone(), "token".to_string()),
        };

        debug!(
            identity = %identity,
            requester_type = %requester_type,
            provider = %kid.provider,
            "Credential validated"
        );

        // Fully authenticated AND authorized — count the success here (not in the
        // observer), so it never includes credential-valid-but-unauthorized tokens.
        crate::metrics::AUTH_SUCCESS_TOTAL
            .with_label_values(&[kid.provider.as_str(), kid.method.as_str()])
            .inc();

        Ok(AuthIdentity {
            requester_type,
            identity,
            issuer,
            policy: access_rule_to_policy(rule),
        })
    }
}

/// Project kobe's CRD [`ClaimMatch`](crate::crd::access_policy::ClaimMatch) into
/// the field-identical [`kunobi_auth::ClaimMatch`] so the shared `first_match`
/// primitive can evaluate it. kobe keeps its own CRD type because it must derive
/// `JsonSchema` (which `kunobi_auth::ClaimMatch` deliberately does not).
fn claim_match_to_kunobi(m: &ClaimMatch) -> kunobi_auth::ClaimMatch {
    kunobi_auth::ClaimMatch {
        claim: m.claim.clone(),
        value: m.value.clone(),
    }
}

/// First rule whose claim-match is satisfied by `claims`, deny-by-default — an
/// unconditional rule (no `match_clause`) is the fallback. Returns the rule and
/// the matched clause value (used to build `requester_type`). Matching is
/// delegated to [`kunobi_auth::first_match`] over kobe's rules, projecting each
/// CRD [`ClaimMatch`](crate::crd::access_policy::ClaimMatch) into the
/// field-identical `kunobi_auth::ClaimMatch` the primitive evaluates.
fn match_rule<'a>(
    rules: &'a [AccessRule],
    claims: &kunobi_auth::AuthIdentity,
) -> Option<(&'a AccessRule, Option<String>)> {
    let projected: Vec<(&'a AccessRule, Option<kunobi_auth::ClaimMatch>)> = rules
        .iter()
        .map(|r| (r, r.match_clause.as_ref().map(claim_match_to_kunobi)))
        .collect();
    let matched = kunobi_auth::first_match(&projected, claims, |(_, clause)| clause.as_ref())?;
    // `matched.0` is the `&'a AccessRule` from `rules`; the projected vec (and
    // the borrowed clause) are dropped at return, so nothing of it escapes.
    Some((matched.0, matched.1.as_ref().map(|m| m.value.clone())))
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

/// Format an identity string by replacing `{claim_name}` placeholders with claim
/// values read from the validated claim set via
/// [`kunobi_auth::AuthIdentity::claim_str`] (dot-path + String/Number/Bool
/// coercion). A single forward pass avoids re-expansion when claim values
/// contain `{`; an unclosed `{` is kept verbatim; an unknown claim renders as
/// `_missing_{name}_`.
fn format_identity(template: &str, claims: &kunobi_auth::AuthIdentity) -> String {
    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find('{') {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 1..];

        if let Some(end) = remaining.find('}') {
            let key = &remaining[..end];
            let value = claims
                .claim_str(key)
                .unwrap_or_else(|| format!("_missing_{key}_"));
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

    /// Build a `kunobi_auth::AuthIdentity` over a claim set (sub + iss + extra) —
    /// the view kobe's rule matching + identity templating now operate on.
    fn make_claims(
        sub: &str,
        extra: HashMap<String, serde_json::Value>,
    ) -> kunobi_auth::AuthIdentity {
        let mut claims = extra;
        claims.insert(
            "sub".to_string(),
            serde_json::Value::String(sub.to_string()),
        );
        claims.insert(
            "iss".to_string(),
            serde_json::Value::String("https://test.example.com".to_string()),
        );
        kunobi_auth::AuthIdentity {
            provider: "test".to_string(),
            identity: String::new(),
            method: "oidc".to_string(),
            claims,
        }
    }

    // --- match_rule (rule matching via kunobi_auth::first_match) tests ---

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
        let (rule, matched) = match_rule(&rules, &claims).unwrap();
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
        let (rule, matched) = match_rule(&rules, &claims).unwrap();
        assert_eq!(rule.max_ttl, "8h");
        assert_eq!(matched, Some("org:admin".to_string()));

        // No claim match — falls through to unconditional rule
        let claims = make_claims("test-sub", HashMap::new());
        let (rule, matched) = match_rule(&rules, &claims).unwrap();
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
        let (rule, matched) = match_rule(&rules, &claims).unwrap();
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
        assert!(match_rule(&rules, &claims).is_none());
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

    // --- claim extraction via AuthIdentity::claim_str ---
    // (these previously exercised kobe's get_claim_value; the dot-path +
    // String/Number/Bool coercion is now kunobi-auth's claim_str — same results.)

    #[test]
    fn test_claim_str_top_level() {
        let mut extra = HashMap::new();
        extra.insert(
            "email".to_string(),
            serde_json::Value::String("test@example.com".to_string()),
        );
        assert_eq!(
            make_claims("user_1", extra).claim_str("email"),
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn test_claim_str_sub() {
        assert_eq!(
            make_claims("user_123", HashMap::new()).claim_str("sub"),
            Some("user_123".to_string())
        );
    }

    #[test]
    fn test_claim_str_nested() {
        let mut extra = HashMap::new();
        extra.insert(
            "private_metadata".to_string(),
            serde_json::json!({"role": "admin", "level": 5}),
        );
        let claims = make_claims("user_1", extra);
        assert_eq!(
            claims.claim_str("private_metadata.role"),
            Some("admin".to_string())
        );
        assert_eq!(
            claims.claim_str("private_metadata.level"),
            Some("5".to_string())
        );
    }

    #[test]
    fn test_claim_str_missing() {
        assert_eq!(
            make_claims("user_1", HashMap::new()).claim_str("nonexistent"),
            None
        );
    }

    #[test]
    fn test_claim_str_deeply_nested_missing() {
        let mut extra = HashMap::new();
        extra.insert("a".to_string(), serde_json::json!({"b": {"c": "found"}}));
        let claims = make_claims("u", extra);
        assert_eq!(claims.claim_str("a.b.c"), Some("found".to_string()));
        assert_eq!(claims.claim_str("a.b.d"), None);
        assert_eq!(claims.claim_str("a.x.c"), None);
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
                        "audience": ["test-aud"],
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
    async fn test_azp_only_provider_is_compiled() {
        // A provider bound by authorizedParties (azp) with no audience — e.g.
        // Clerk — must still compile and be usable.
        let auth = JwtAuthenticator::new("test".to_string());
        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "clerk" },
            "spec": {
                "auth": { "oidc": {
                    "issuer": "https://clerk.example.com",
                    "authorizedParties": ["https://app.example.com"],
                    "algorithms": ["RS256"]
                }},
                "rules": [{ "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1 }]
            }
        }))
        .unwrap();
        auth.update_policies(vec![policy], HashMap::new()).await;
        assert!(auth.policy_for_requester_type("clerk").await.is_some());
    }

    #[tokio::test]
    async fn test_provider_without_aud_or_azp_is_skipped() {
        // Neither audience nor authorizedParties → would accept any signed token
        // from the issuer, so the provider is skipped at compile time.
        let auth = JwtAuthenticator::new("test".to_string());
        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "unbound" },
            "spec": {
                "auth": { "oidc": {
                    "issuer": "https://issuer.example.com",
                    "algorithms": ["RS256"]
                }},
                "rules": [{ "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1 }]
            }
        }))
        .unwrap();
        auth.update_policies(vec![policy], HashMap::new()).await;
        assert!(auth.policy_for_requester_type("unbound").await.is_none());
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

    #[tokio::test]
    async fn validate_credential_valid_but_unauthorized_counts_failure_not_success() {
        // Static token whose only rule has a match clause (no unconditional
        // fallback): the credential matches, but static tokens carry no claims,
        // so no rule authorizes it -> 401. The success counter must NOT move;
        // the no_matching_rule failure counter must. (Regression guard for
        // emitting metrics on the full authn+authz outcome, not mid-pipeline.)
        let auth = JwtAuthenticator::new("test".to_string());
        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": "metrics-authz-reject" },
            "spec": {
                "auth": { "token": { "secretRef": "s" } },
                "rules": [{
                    "match": { "claim": "role", "value": "admin" },
                    "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1
                }]
            }
        }))
        .unwrap();
        let mut secrets = HashMap::new();
        secrets.insert("s".to_string(), "the-token".to_string());
        auth.update_policies(vec![policy], secrets).await;

        // Unique provider label, so the global counters don't race other tests.
        let provider = "metrics-authz-reject";
        let success_before = crate::metrics::AUTH_SUCCESS_TOTAL
            .with_label_values(&[provider, "token"])
            .get();
        let failure_before = crate::metrics::AUTH_FAILURE_TOTAL
            .with_label_values(&[provider, "no_matching_rule"])
            .get();

        assert!(auth.validate("the-token").await.is_err());

        assert_eq!(
            crate::metrics::AUTH_SUCCESS_TOTAL
                .with_label_values(&[provider, "token"])
                .get(),
            success_before,
            "credential-valid-but-unauthorized must NOT count as success"
        );
        assert_eq!(
            crate::metrics::AUTH_FAILURE_TOTAL
                .with_label_values(&[provider, "no_matching_rule"])
                .get(),
            failure_before + 1,
            "must count as a no_matching_rule failure"
        );
    }

    #[tokio::test]
    async fn discovery_metadata_advertises_the_provider_with_a_client_id() {
        let auth = JwtAuthenticator::new("test".to_string());

        // A machine provider (no clientId) and an interactive one (clientId set).
        let machine: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1", "kind": "AccessPolicy",
            "metadata": { "name": "ci" },
            "spec": { "auth": { "oidc": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audience": ["kobe"], "algorithms": ["RS256"]
            }}, "rules": [{ "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1 }] }
        }))
        .unwrap();
        let human: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1", "kind": "AccessPolicy",
            "metadata": { "name": "corp" },
            "spec": { "auth": { "oidc": {
                "issuer": "https://login.corp.example",
                "audience": ["kobe-api"], "algorithms": ["RS256"],
                "clientId": "kobe-cli"
            }}, "rules": [{ "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1 }] }
        }))
        .unwrap();
        auth.update_policies(vec![machine, human], HashMap::new())
            .await;

        let doc = auth
            .discovery_metadata()
            .await
            .expect("the interactive provider must be advertised");
        assert_eq!(doc.issuer, "https://login.corp.example");
        assert_eq!(doc.client_id, "kobe-cli");
        assert_eq!(doc.audience.as_deref(), Some("kobe-api"));

        // /v1/status exposes client_id only for the interactive provider.
        let methods = auth.auth_methods().await;
        let corp = methods
            .iter()
            .find(|m| m.description.as_deref() == Some("corp"))
            .unwrap();
        assert_eq!(corp.client_id.as_deref(), Some("kobe-cli"));
        let ci = methods
            .iter()
            .find(|m| m.description.as_deref() == Some("ci"))
            .unwrap();
        assert_eq!(ci.client_id, None);
    }

    #[tokio::test]
    async fn discovery_metadata_is_none_without_an_interactive_provider() {
        let auth = JwtAuthenticator::new("test".to_string());
        let machine: AccessPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1", "kind": "AccessPolicy",
            "metadata": { "name": "ci" },
            "spec": { "auth": { "oidc": {
                "issuer": "https://idp", "audience": ["kobe"], "algorithms": ["RS256"]
            }}, "rules": [{ "pools": ["*"], "maxTtl": "1h", "maxConcurrentLeases": 1 }] }
        }))
        .unwrap();
        auth.update_policies(vec![machine], HashMap::new()).await;
        assert!(auth.discovery_metadata().await.is_none());
    }
}
