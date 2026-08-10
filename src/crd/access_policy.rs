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

    /// SSH Ed25519 public key authentication.
    #[serde(default)]
    pub ssh: Option<SshAuth>,
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

    /// OAuth client ID for interactive CLI login. When set, this provider is
    /// advertised at `/.well-known/kunobi-auth` (issuer + client_id + audience)
    /// so `kobe login` can discover where to authenticate. Machine providers
    /// (e.g. CI/GitHub Actions) that never do interactive login leave this unset.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Static bearer token authentication via a Kubernetes Secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuth {
    /// Name of the Secret containing the token (key: "token").
    pub secret_ref: String,
}

/// SSH Ed25519 public key authentication.
///
/// Public keys stored in OpenSSH authorized_keys format.
/// Only Ed25519 keys are supported.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshAuth {
    /// Public keys in OpenSSH authorized_keys format.
    pub authorized_keys: Vec<String>,

    /// Revoked public keys (same format). Takes precedence over authorized_keys.
    #[serde(default)]
    pub revoked_keys: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_json() -> serde_json::Value {
        serde_json::json!({
            "pools": ["ci-*"],
            "maxTtl": "1h",
            "maxConcurrentLeases": 5
        })
    }

    /// `match_clause` is spelled `match` on the wire — it has to be, since
    /// `match` is a Rust keyword.
    ///
    /// This is the whole multi-role OIDC mechanism. If the rename were lost,
    /// a rule's match clause would deserialize as absent, and a rule scoped
    /// to one role would start applying to every caller the policy
    /// authenticates. That is an authorization widening, and nothing else in
    /// the type would look wrong.
    #[test]
    fn match_clause_is_named_match_on_the_wire() {
        let mut json = rule_json();
        json["match"] = serde_json::json!({ "claim": "role", "value": "admin" });
        let rule: AccessRule = serde_json::from_value(json).unwrap();
        let m = rule
            .match_clause
            .as_ref()
            .expect("`match` must bind to match_clause");
        assert_eq!(m.claim, "role");
        assert_eq!(m.value, "admin");

        // And it round-trips back under the same key.
        let v = serde_json::to_value(&rule).unwrap();
        assert!(
            v.get("match").is_some() && v.get("matchClause").is_none(),
            "must serialize as `match`, got: {v}"
        );
    }

    /// A rule written with the Rust field name must NOT silently become an
    /// unscoped rule. `matchClause` is not the wire name, so it is ignored —
    /// and an ignored match clause means the rule applies to everyone.
    /// Pinned so the failure mode is visible if anyone "fixes" the rename.
    #[test]
    fn a_mis_spelled_match_clause_does_not_scope_the_rule() {
        let mut json = rule_json();
        json["matchClause"] = serde_json::json!({ "claim": "role", "value": "admin" });
        let rule: AccessRule = serde_json::from_value(json).unwrap();
        assert!(
            rule.match_clause.is_none(),
            "only `match` binds; if this ever starts binding, the rename changed"
        );
    }

    /// The two ceilings are REQUIRED, deliberately. Giving either a default
    /// would let a policy that forgot them be admitted with a silent value
    /// instead of rejected — the difference between "no TTL cap configured"
    /// and "some cap I never chose".
    #[test]
    fn the_lease_ceilings_have_no_default_and_must_be_declared() {
        let missing_ttl = serde_json::json!({ "pools": ["*"], "maxConcurrentLeases": 1 });
        assert!(
            serde_json::from_value::<AccessRule>(missing_ttl).is_err(),
            "maxTtl must be required"
        );

        let missing_quota = serde_json::json!({ "pools": ["*"], "maxTtl": "1h" });
        assert!(
            serde_json::from_value::<AccessRule>(missing_quota).is_err(),
            "maxConcurrentLeases must be required"
        );

        let missing_pools = serde_json::json!({ "maxTtl": "1h", "maxConcurrentLeases": 1 });
        assert!(
            serde_json::from_value::<AccessRule>(missing_pools).is_err(),
            "pools must be required — a rule with no pool scope is not a rule"
        );
    }

    /// snake_case keys do not bind. The apiserver stores what the CRD schema
    /// declares (camelCase), so a snake_case manifest field is dropped as
    /// unknown — and for a required field that surfaces as a rejection rather
    /// than a policy quietly missing its ceiling.
    #[test]
    fn rule_binds_camel_case_keys_only() {
        let snake = serde_json::json!({
            "pools": ["*"],
            "max_ttl": "1h",
            "max_concurrent_leases": 5
        });
        assert!(
            serde_json::from_value::<AccessRule>(snake).is_err(),
            "snake_case must not bind — it would drop the ceilings"
        );
    }

    /// Defaults are load-bearing values, not formalities: `maxExtensions`
    /// bounds how far a lease's TTL can be pushed past its original grant.
    #[test]
    fn max_extensions_defaults_to_two() {
        let rule: AccessRule = serde_json::from_value(rule_json()).unwrap();
        assert_eq!(rule.max_extensions, 2);

        let mut explicit = rule_json();
        explicit["maxExtensions"] = serde_json::json!(0);
        let rule: AccessRule = serde_json::from_value(explicit).unwrap();
        assert_eq!(rule.max_extensions, 0, "an explicit 0 must be honoured");
    }

    /// The identity template decides WHO a caller is taken to be. Defaulting
    /// to anything other than the subject claim would silently re-map every
    /// OIDC identity in a policy that omits it.
    #[test]
    fn identity_template_defaults_to_the_subject_claim() {
        let spec: AccessPolicySpec = serde_json::from_value(serde_json::json!({
            "auth": { "token": { "secretRef": "kobe-token" } },
            "rules": [rule_json()]
        }))
        .unwrap();
        assert_eq!(spec.identity, "{sub}");
    }

    /// JWT algorithms default to RS256 — asymmetric, never an HMAC family.
    /// An empty or symmetric default is the classic algorithm-confusion
    /// footgun, where a token signed with the public key as an HMAC secret
    /// validates.
    #[test]
    fn oidc_algorithms_default_to_an_asymmetric_algorithm() {
        let oidc: OidcAuth = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example",
            "audience": ["kobe"]
        }))
        .unwrap();
        assert_eq!(oidc.algorithms, vec!["RS256".to_string()]);
        assert!(
            !oidc.algorithms.is_empty(),
            "an empty algorithm list must never be the default"
        );
        for alg in &oidc.algorithms {
            assert!(
                !alg.starts_with("HS"),
                "an HMAC algorithm must never be defaulted in: {alg}"
            );
        }
    }

    /// Every auth method is optional, so a policy naming none still parses.
    /// That is deliberate — provider registration skips such a policy rather
    /// than failing the whole reconcile — but it means the SKIP is what
    /// enforces safety, so the parse must stay permissive on purpose.
    #[test]
    fn an_auth_block_naming_no_method_still_parses() {
        let auth: AuthMethod = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(auth.oidc.is_none());
        assert!(auth.token.is_none());
        assert!(auth.service_account.is_none());
        assert!(auth.ssh.is_none());
    }

    /// The CRD's public identity. Changing any of it breaks every manifest
    /// and `kubectl` invocation in the wild.
    #[test]
    fn crd_identity_is_stable() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(AccessPolicy::crd()).unwrap();

        assert_eq!(crd["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(crd["spec"]["scope"], "Namespaced");
        assert_eq!(crd["spec"]["names"]["kind"], "AccessPolicy");
        assert_eq!(crd["spec"]["names"]["plural"], "accesspolicies");
        assert_eq!(crd["spec"]["names"]["shortNames"][0], "ap");
        assert_eq!(crd["metadata"]["name"], "accesspolicies.kobe.kunobi.ninja");

        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }

    /// A policy written by a newer operator must still deserialize, or a
    /// rolling upgrade wedges the older replica on every policy it reads —
    /// which for this type means it stops authenticating anyone.
    #[test]
    fn a_policy_from_a_newer_operator_still_deserializes() {
        let spec: AccessPolicySpec = serde_json::from_value(serde_json::json!({
            "auth": { "token": { "secretRef": "kobe-token" } },
            "rules": [rule_json()],
            "someFieldFromTheFuture": { "nested": true }
        }))
        .expect("unknown fields must be ignored, not rejected");
        assert_eq!(spec.rules.len(), 1);
    }
}
