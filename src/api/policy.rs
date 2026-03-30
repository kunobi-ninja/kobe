use crate::api::auth::AuthIdentity;
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
}

/// Get the authorization policy for a given identity.
/// The policy is resolved at authentication time and carried on the AuthIdentity.
pub fn policy_for(identity: &AuthIdentity) -> Policy {
    identity.policy.clone()
}

/// Check if a pool name matches the allowed patterns for an identity.
pub fn is_pool_allowed(pool: &str, policy: &Policy) -> bool {
    policy.allowed_pools.iter().any(|pattern| {
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
pub fn format_duration(d: &chrono::Duration) -> String {
    let total_secs = d.num_seconds();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;

    if hours > 0 && minutes > 0 {
        format!("{hours}h{minutes}m")
    } else if hours > 0 {
        format!("{hours}h")
    } else {
        format!("{minutes}m")
    }
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
        };

        // Within limit
        let clamped = clamp_ttl("30m", &policy);
        assert_eq!(clamped, chrono::Duration::minutes(30));

        // Exceeds limit
        let clamped = clamp_ttl("2h", &policy);
        assert_eq!(clamped, chrono::Duration::hours(1));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(&chrono::Duration::hours(1)), "1h");
        assert_eq!(format_duration(&chrono::Duration::minutes(30)), "30m");
        assert_eq!(format_duration(&chrono::Duration::minutes(90)), "1h30m");
    }
}
