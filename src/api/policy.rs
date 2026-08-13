use crate::api::auth::AuthIdentity;
use crate::crd::{SandboxResourceCeiling, SandboxVerb};
use crate::pool::parse_duration;

/// Authorization policy — what each identity type is allowed to do.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Pool name patterns this identity can access.
    pub allowed_pools: Vec<String>,
    /// Maximum TTL for leases.
    pub max_ttl: chrono::Duration,
    /// Maximum concurrent active leases.
    pub max_concurrent_leases: u32,
    /// Default priority for leases.
    pub default_priority: u32,
    /// Maximum number of TTL extensions.
    pub max_extensions: u32,
    /// Optional kind-specific Sandbox grant. Absence always denies Sandbox and
    /// preserves the meaning of legacy Cluster-only AccessPolicy objects.
    pub sandbox: Option<SandboxPolicy>,
}

/// Runtime form of a validated Sandbox access grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub allowed_pools: Vec<String>,
    pub verbs: Vec<SandboxVerb>,
    pub max_ttl: chrono::Duration,
    pub max_concurrent_leases: u32,
    pub resource_ceiling: SandboxResourceCeiling,
}

/// Get the authorization policy for a given identity.
/// The policy is resolved at authentication time and carried on the AuthIdentity.
pub fn policy_for(identity: &AuthIdentity) -> Policy {
    identity.policy.clone()
}

/// Check if a pool name matches the allowed patterns for an identity.
pub fn is_pool_allowed(pool: &str, policy: &Policy) -> bool {
    pool_matches(pool, &policy.allowed_pools)
}

fn pool_matches(pool: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            pool.starts_with(prefix)
        } else {
            pool == pattern
        }
    })
}

/// Check a Sandbox operation against both its pool scope and independent verb
/// grant. A missing Sandbox grant fails closed even when Cluster pools allow
/// the same name or the wildcard `*`.
pub fn is_sandbox_allowed(pool: &str, verb: SandboxVerb, policy: &Policy) -> bool {
    policy.sandbox.as_ref().is_some_and(|sandbox| {
        pool_matches(pool, &sandbox.allowed_pools) && sandbox.verbs.contains(&verb)
    })
}

/// Clamp a valid positive runtime TTL to the Sandbox-specific maximum.
/// Invalid, zero, or negative values return `None` instead of inheriting the
/// legacy Cluster one-hour fallback.
pub fn clamp_sandbox_ttl(requested: &str, policy: &Policy) -> Option<chrono::Duration> {
    let grant = policy.sandbox.as_ref()?;
    let requested = parse_duration(requested)?;
    if requested <= chrono::Duration::zero() {
        return None;
    }
    Some(requested.min(grant.max_ttl))
}

/// Clamp a requested TTL to the policy maximum.
/// Returns the effective TTL as a chrono::Duration.
pub fn clamp_ttl(requested: &str, policy: &Policy) -> chrono::Duration {
    let requested_duration = parse_duration(requested).unwrap_or(chrono::Duration::hours(1));

    if requested_duration > policy.max_ttl {
        policy.max_ttl
    } else {
        requested_duration
    }
}

/// Format a chrono::Duration as a human-readable string (e.g. "1h30m").
///
/// Seconds-aware: sub-minute durations are preserved as an `Ns`
/// component rather than truncated to `"0m"`. Truncating to `"0m"` used
/// to round-trip through `parse_duration` as a 0 TTL, which the lease
/// controller then replaced with its 1h fallback — silently turning a
/// requested 30s lease into 1h. Examples: 3600s → "1h", 90s → "1m30s",
/// 30s → "30s", 0s → "0s".
pub fn format_duration(d: &chrono::Duration) -> String {
    let total_secs = d.num_seconds();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    if seconds > 0 {
        out.push_str(&format!("{seconds}s"));
    }
    if out.is_empty() {
        // A true zero (or sub-second) duration.
        out.push_str("0s");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_matching() {
        let ci_policy = Policy {
            allowed_pools: vec!["e2e-*".to_string()],
            max_ttl: chrono::Duration::hours(1),
            max_concurrent_leases: 5,
            default_priority: 100,
            max_extensions: 2,
            sandbox: None,
        };

        assert!(is_pool_allowed("e2e-basic", &ci_policy));
        assert!(is_pool_allowed("e2e-full", &ci_policy));
        assert!(!is_pool_allowed("dev-basic", &ci_policy));

        let admin_policy = Policy {
            allowed_pools: vec!["*".to_string()],
            max_ttl: chrono::Duration::hours(8),
            max_concurrent_leases: 10,
            default_priority: 100,
            max_extensions: 10,
            sandbox: None,
        };

        assert!(is_pool_allowed("e2e-basic", &admin_policy));
        assert!(is_pool_allowed("dev-basic", &admin_policy));
        assert!(is_pool_allowed("anything", &admin_policy));
    }

    #[test]
    fn test_clamp_ttl() {
        let policy = Policy {
            allowed_pools: vec![],
            max_ttl: chrono::Duration::hours(1),
            max_concurrent_leases: 5,
            default_priority: 100,
            max_extensions: 2,
            sandbox: None,
        };

        // Within limit
        let clamped = clamp_ttl("30m", &policy);
        assert_eq!(clamped, chrono::Duration::minutes(30));

        // Exceeds limit
        let clamped = clamp_ttl("2h", &policy);
        assert_eq!(clamped, chrono::Duration::hours(1));
    }

    fn policy_with_sandbox() -> Policy {
        Policy {
            allowed_pools: vec!["cluster-*".into()],
            max_ttl: chrono::Duration::hours(8),
            max_concurrent_leases: 5,
            default_priority: 100,
            max_extensions: 2,
            sandbox: Some(SandboxPolicy {
                allowed_pools: vec!["agent-*".into()],
                verbs: vec![SandboxVerb::Lease, SandboxVerb::Release],
                max_ttl: chrono::Duration::minutes(30),
                max_concurrent_leases: 3,
                resource_ceiling: SandboxResourceCeiling {
                    max_cpu: "2".into(),
                    max_memory: "4Gi".into(),
                },
            }),
        }
    }

    #[test]
    fn sandbox_grant_is_kind_pool_and_verb_specific() {
        let policy = policy_with_sandbox();
        assert!(is_pool_allowed("cluster-ci", &policy));
        assert!(!is_sandbox_allowed(
            "cluster-ci",
            SandboxVerb::Lease,
            &policy
        ));
        assert!(is_sandbox_allowed("agent-ci", SandboxVerb::Lease, &policy));
        assert!(!is_sandbox_allowed("agent-ci", SandboxVerb::Exec, &policy));

        let mut legacy = policy;
        legacy.sandbox = None;
        assert!(!is_sandbox_allowed("agent-ci", SandboxVerb::Lease, &legacy));
    }

    #[test]
    fn sandbox_wildcard_and_every_verb_are_checked_independently() {
        let mut policy = policy_with_sandbox();
        let sandbox = policy.sandbox.as_mut().unwrap();
        sandbox.allowed_pools = vec!["*".into()];
        sandbox.verbs = vec![
            SandboxVerb::Lease,
            SandboxVerb::Exec,
            SandboxVerb::Logs,
            SandboxVerb::PortForward,
            SandboxVerb::Release,
        ];

        for verb in sandbox.verbs.clone() {
            assert!(is_sandbox_allowed("any-sandbox-pool", verb, &policy));
        }
        policy
            .sandbox
            .as_mut()
            .unwrap()
            .verbs
            .retain(|verb| *verb != SandboxVerb::Release);
        assert!(!is_sandbox_allowed(
            "any-sandbox-pool",
            SandboxVerb::Release,
            &policy
        ));
    }

    #[test]
    fn sandbox_ttl_is_fail_closed_and_uses_kind_specific_limit() {
        let policy = policy_with_sandbox();
        assert_eq!(
            clamp_sandbox_ttl("15m", &policy),
            Some(chrono::Duration::minutes(15))
        );
        assert_eq!(
            clamp_sandbox_ttl("2h", &policy),
            Some(chrono::Duration::minutes(30))
        );
        assert_eq!(clamp_sandbox_ttl("invalid", &policy), None);
        assert_eq!(clamp_sandbox_ttl("0s", &policy), None);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(&chrono::Duration::hours(1)), "1h");
        assert_eq!(format_duration(&chrono::Duration::minutes(30)), "30m");
        assert_eq!(format_duration(&chrono::Duration::minutes(90)), "1h30m");
    }

    #[test]
    fn test_format_duration_is_seconds_aware() {
        // Sub-minute durations must NOT truncate to "0m" (which would
        // round-trip back as a 0 TTL and hit the lease controller's 1h
        // fallback). They keep an `Ns` component instead.
        assert_eq!(format_duration(&chrono::Duration::seconds(30)), "30s");
        assert_eq!(format_duration(&chrono::Duration::seconds(90)), "1m30s");
        assert_eq!(format_duration(&chrono::Duration::seconds(3661)), "1h1m1s");
        assert_eq!(format_duration(&chrono::Duration::seconds(3600)), "1h");
        // A true zero is the only thing that renders as "0s".
        assert_eq!(format_duration(&chrono::Duration::zero()), "0s");
    }

    #[test]
    fn test_format_duration_round_trips_through_parse_duration() {
        // The regression we're guarding: format → parse must preserve a
        // short TTL instead of collapsing it to zero.
        for secs in [30i64, 45, 90, 600, 3600, 5400] {
            let formatted = format_duration(&chrono::Duration::seconds(secs));
            let parsed =
                parse_duration(&formatted).expect("formatted duration must re-parse cleanly");
            assert_eq!(
                parsed.num_seconds(),
                secs,
                "round-trip mismatch for {secs}s (formatted as {formatted})"
            );
        }
    }
}
