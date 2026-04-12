use std::collections::HashMap;

use crate::crd::ClusterPool;

/// Hash of the cluster spec at creation time, used to detect drift.
pub type SpecHash = u64;

/// Compute a hash of the profile's cluster-relevant fields.
pub fn profile_spec_hash(profile: &ClusterPool) -> SpecHash {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Hash the fields that affect how a cluster is created
    profile.spec.cluster.version.hash(&mut hasher);
    profile.spec.cluster.servers.hash(&mut hasher);
    profile.spec.cluster.agents.hash(&mut hasher);
    profile.spec.cluster.server_args.hash(&mut hasher);
    format!("{:?}", profile.spec.backend).hash(&mut hasher);
    hasher.finish()
}

/// Tracks the state of each cluster in a profile's pool.
#[derive(Debug, Clone, PartialEq)]
pub enum ClusterState {
    /// Being created, not yet ready.
    Creating,
    /// Ready and idle, available for claims.
    Ready,
    /// Bound to a claim.
    Leased,
    /// Failed health check, being recycled.
    Unhealthy,
    /// Being deleted and recreated.
    #[allow(dead_code)]
    Recycling,
}

/// Pool state for a single profile.
#[derive(Debug, Clone)]
pub struct PoolState {
    /// Map of cluster name → state.
    pub clusters: HashMap<String, ClusterEntry>,
}

#[derive(Debug, Clone)]
pub struct ClusterEntry {
    pub state: ClusterState,
    /// When this cluster became idle (for scale-down decisions).
    pub idle_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Consecutive health check failures.
    #[allow(dead_code)]
    pub health_failures: u32,
    /// When this entry was created/entered current state (for stuck-Creating timeout).
    pub state_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of the profile spec when this cluster was created.
    /// Used to detect spec drift and trigger recreation of unclaimed clusters.
    pub spec_hash: Option<SpecHash>,
}

/// Decisions the pool manager emits after evaluating state.
#[derive(Debug, Clone)]
pub enum PoolAction {
    /// Create a new cluster with this name.
    Create(String),
    /// Delete this cluster (scale down or recycle).
    Delete(String),
    /// Mark this cluster as unhealthy for recycling.
    #[allow(dead_code)]
    MarkUnhealthy(String),
}

/// Computes the desired pool actions given current state and profile config.
///
/// This is the core autoscaling logic:
/// - Scale up when ready clusters < desired floor
/// - Scale down when idle clusters > min_ready and idle too long
/// - Respect max_clusters ceiling
/// - Cap creation burst to avoid thundering herd
pub fn compute_pool_actions(
    profile: &ClusterPool,
    state: &PoolState,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<PoolAction> {
    let spec = &profile.spec;
    let mut actions = Vec::new();

    // --- Recycle Unhealthy clusters ---
    for (name, entry) in &state.clusters {
        if entry.state == ClusterState::Unhealthy {
            actions.push(PoolAction::Delete(name.clone()));
        }
    }

    // --- Recycle unclaimed clusters with stale spec ---
    let current_hash = profile_spec_hash(profile);
    for (name, entry) in &state.clusters {
        if entry.state == ClusterState::Ready {
            if let Some(hash) = entry.spec_hash {
                if hash != current_hash {
                    tracing::info!(
                        cluster = %name,
                        "Cluster spec differs from profile, scheduling recreation"
                    );
                    actions.push(PoolAction::Delete(name.clone()));
                }
            }
        }
    }

    // --- Timeout stuck Creating clusters (>10 minutes) ---
    let creating_timeout = chrono::Duration::minutes(10);
    for (name, entry) in &state.clusters {
        if entry.state == ClusterState::Creating {
            if let Some(since) = entry.state_since {
                if now - since > creating_timeout {
                    actions.push(PoolAction::Delete(name.clone()));
                }
            }
        }
    }

    let counts = count_states(state);
    let total =
        counts.creating + counts.ready + counts.leased + counts.unhealthy + counts.recycling;

    // Determine target from scaling config or fixed size
    let (min_ready, max_clusters, scale_up_threshold, scale_down_after) =
        if let Some(scaling) = &spec.scaling {
            (
                scaling.min_ready,
                scaling.max_clusters,
                scaling.scale_up_threshold,
                parse_duration(&scaling.scale_down_after),
            )
        } else {
            // Fixed pool: size is both min and max ready
            (spec.size, spec.size + 10, 0, None) // no scale-down for fixed pools
        };

    // --- Scale Up ---
    // We want at least `min_ready` clusters in Ready state.
    // Scale up when ready clusters fall to scale_up_threshold.
    if counts.ready <= scale_up_threshold && total < max_clusters {
        let deficit = min_ready.saturating_sub(counts.ready + counts.creating);
        let room = max_clusters.saturating_sub(total);
        let to_create = deficit.min(room).min(MAX_BURST);

        // Find the highest existing index to avoid name collisions from gaps
        let profile_name = profile.metadata.name.clone().unwrap_or_default();
        let max_index = max_existing_index(state, &profile_name);

        for i in 0..to_create {
            let name = generate_cluster_name(&profile_name, max_index + 1 + i);
            actions.push(PoolAction::Create(name));
        }
    }

    // --- Scale Down ---
    // Delete idle clusters above min_ready that have been idle too long.
    if let Some(idle_max) = scale_down_after {
        let mut idle_candidates: Vec<(&String, &ClusterEntry)> = state
            .clusters
            .iter()
            .filter(|(_, e)| e.state == ClusterState::Ready)
            .collect();

        // Sort by idle_since ascending (oldest idle first)
        idle_candidates.sort_by_key(|(_, e)| e.idle_since);

        let excess = counts.ready.saturating_sub(min_ready);
        let mut deleted = 0u32;

        for (name, entry) in idle_candidates {
            if deleted >= excess {
                break;
            }
            if let Some(idle_since) = entry.idle_since {
                let idle_duration = now - idle_since;
                if idle_duration > idle_max {
                    actions.push(PoolAction::Delete(name.clone()));
                    deleted += 1;
                }
            }
        }
    }

    actions
}

/// Maximum clusters to create in a single reconciliation pass.
const MAX_BURST: u32 = 2;

/// Find the highest existing cluster index for a profile.
///
/// Parses names like `pool-{profile}-{index}` and returns the max index,
/// or 0 if no clusters exist. This prevents name collisions when there
/// are gaps in the index sequence (e.g., 0, 2 → next should be 3, not 2).
fn max_existing_index(state: &PoolState, profile_name: &str) -> u32 {
    let prefix = format!("pool-{profile_name}-");
    state
        .clusters
        .keys()
        .filter_map(|name| {
            name.strip_prefix(&prefix)
                .and_then(|suffix| suffix.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub struct StateCounts {
    pub creating: u32,
    pub ready: u32,
    pub leased: u32,
    pub unhealthy: u32,
    pub recycling: u32,
}

pub fn count_states(state: &PoolState) -> StateCounts {
    let mut c = StateCounts::default();
    for entry in state.clusters.values() {
        match entry.state {
            ClusterState::Creating => c.creating += 1,
            ClusterState::Ready => c.ready += 1,
            ClusterState::Leased => c.leased += 1,
            ClusterState::Unhealthy => c.unhealthy += 1,
            ClusterState::Recycling => c.recycling += 1,
        }
    }
    c
}

/// Validate that a name is a valid Kubernetes DNS label (RFC 1123).
///
/// Must match: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` (2-63 chars)
/// or a single alphanumeric char. This prevents names like `--set`
/// from being misinterpreted as CLI flags by helm/kubectl.
pub fn is_valid_k8s_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Generate a deterministic cluster name for a profile.
///
/// Logs a warning if the profile name produces an invalid K8s name.
/// This indicates a bug in profile validation upstream.
pub fn generate_cluster_name(profile_name: &str, index: u32) -> String {
    let name = format!("pool-{profile_name}-{index}");
    if !is_valid_k8s_name(&name) {
        tracing::warn!(name = %name, "Generated cluster name failed K8s DNS label validation");
    }
    name
}

/// Parse a duration string like "30m", "1h", "2h30m" into a chrono::Duration.
///
/// Returns None for empty strings, invalid formats, and values exceeding 1 year.
pub fn parse_duration(s: &str) -> Option<chrono::Duration> {
    const MAX_SECONDS: i64 = 365 * 24 * 3600; // 1 year

    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let mut total_seconds: i64 = 0;
    let mut current_num = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let n: i64 = current_num.parse().ok()?;
            current_num.clear();
            let secs = match ch {
                'h' => n.checked_mul(3600)?,
                'm' => n.checked_mul(60)?,
                's' => n,
                _ => return None,
            };
            total_seconds = total_seconds.checked_add(secs)?;
            if total_seconds > MAX_SECONDS {
                return None;
            }
        }
    }

    // Reject trailing digits without a unit (e.g. "1h30" should fail, use "1h30m")
    if !current_num.is_empty() {
        return None;
    }

    if total_seconds > 0 {
        chrono::Duration::try_seconds(total_seconds)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30m"), Some(chrono::Duration::seconds(1800)));
        assert_eq!(parse_duration("1h"), Some(chrono::Duration::seconds(3600)));
        assert_eq!(
            parse_duration("2h30m"),
            Some(chrono::Duration::seconds(9000))
        );
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn test_parse_duration_rejects_overflow() {
        // Values exceeding 1 year are rejected
        assert_eq!(parse_duration("9000h"), None);
        assert_eq!(parse_duration("600000m"), None);
        // Just under the limit is fine (8760h = 1 year)
        assert!(parse_duration("8760h").is_some());
        // Invalid unit characters
        assert_eq!(parse_duration("5d"), None);
    }

    #[test]
    fn test_parse_duration_rejects_trailing_digits() {
        // "1h30" should fail — ambiguous, use "1h30m"
        assert_eq!(parse_duration("1h30"), None);
        // Bare number with no unit
        assert_eq!(parse_duration("10"), None);
        // Mixed valid then trailing
        assert_eq!(parse_duration("1m5"), None);
    }

    #[test]
    fn test_max_existing_index() {
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Ready));
        clusters.insert("pool-test-5".into(), make_entry(ClusterState::Leased));
        clusters.insert("pool-test-2".into(), make_entry(ClusterState::Creating));
        let state = PoolState { clusters };

        assert_eq!(max_existing_index(&state, "test"), 5);
    }

    #[test]
    fn test_max_existing_index_empty() {
        let state = PoolState {
            clusters: HashMap::new(),
        };
        assert_eq!(max_existing_index(&state, "test"), 0);
    }

    #[test]
    fn test_count_states() {
        let mut clusters = HashMap::new();
        clusters.insert(
            "a".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        clusters.insert(
            "b".into(),
            ClusterEntry {
                state: ClusterState::Leased,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        clusters.insert(
            "c".into(),
            ClusterEntry {
                state: ClusterState::Creating,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );

        let state = PoolState { clusters };
        let counts = count_states(&state);

        assert_eq!(counts.ready, 1);
        assert_eq!(counts.leased, 1);
        assert_eq!(counts.creating, 1);
    }

    // --- K8s name validation ---

    #[test]
    fn test_valid_k8s_names() {
        assert!(is_valid_k8s_name("a"));
        assert!(is_valid_k8s_name("abc"));
        assert!(is_valid_k8s_name("my-app"));
        assert!(is_valid_k8s_name("pool-e2e-basic-0"));
        assert!(is_valid_k8s_name("a1b2c3"));
        assert!(is_valid_k8s_name("0abc"));
    }

    #[test]
    fn test_invalid_k8s_names() {
        assert!(!is_valid_k8s_name("")); // empty
        assert!(!is_valid_k8s_name("-abc")); // starts with hyphen
        assert!(!is_valid_k8s_name("abc-")); // ends with hyphen
        assert!(!is_valid_k8s_name("--set")); // CLI flag injection
        assert!(!is_valid_k8s_name("ABC")); // uppercase
        assert!(!is_valid_k8s_name("my_app")); // underscore
        assert!(!is_valid_k8s_name("my.app")); // dot
        assert!(!is_valid_k8s_name(&"a".repeat(64))); // too long (>63)
    }

    #[test]
    fn test_k8s_name_boundary_lengths() {
        // Exactly 63 chars — maximum valid length
        assert!(is_valid_k8s_name(&"a".repeat(63)));
        // Single char — valid
        assert!(is_valid_k8s_name("x"));
    }

    // --- Name generation ---

    #[test]
    fn test_generate_cluster_name() {
        assert_eq!(generate_cluster_name("e2e-basic", 0), "pool-e2e-basic-0");
        assert_eq!(generate_cluster_name("e2e-basic", 5), "pool-e2e-basic-5");
        assert_eq!(generate_cluster_name("dev", 10), "pool-dev-10");
    }

    #[test]
    fn test_generate_cluster_name_is_valid_k8s() {
        let name = generate_cluster_name("e2e-basic", 42);
        assert!(is_valid_k8s_name(&name));
    }

    // --- Autoscaling: compute_pool_actions ---

    fn make_profile(
        size: u32,
        scaling: Option<crate::crd::ScalingConfig>,
    ) -> crate::crd::ClusterPool {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        crate::crd::ClusterPool {
            metadata: ObjectMeta {
                name: Some("test-profile".to_string()),
                ..Default::default()
            },
            spec: crate::crd::ClusterPoolSpec {
                size,
                ttl: "1h".to_string(),
                backend: Default::default(),
                cluster: crate::crd::ClusterConfig {
                    version: "v1.31.3+k3s1".to_string(),
                    servers: 1,
                    agents: None,
                    server_args: vec![],
                    persistence: None,
                    expose: None,
                },
                addons: vec![],
                resources: None,
                health_check: None,
                readiness_gates: vec![],
                scaling,
                diagnostics: None,
                snapshot: None,
            },
            status: None,
        }
    }

    fn make_entry(state: ClusterState) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: None,
            health_failures: 0,
            state_since: None,
            spec_hash: None,
        }
    }

    #[test]
    fn test_scale_up_when_pool_empty() {
        let profile = make_profile(
            3,
            Some(crate::crd::ScalingConfig {
                min_ready: 3,
                max_clusters: 10,
                scale_up_threshold: 1,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
            }),
        );
        let state = PoolState {
            clusters: HashMap::new(),
        };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(&profile, &state, now);

        // Should create up to MAX_BURST (2) clusters
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().all(|a| matches!(a, PoolAction::Create(_))));

        // Names should start from index 1 (max_existing=0, so 0+1=1)
        if let PoolAction::Create(ref name) = actions[0] {
            assert!(name.starts_with("pool-test-profile-"));
        }
    }

    #[test]
    fn test_no_scale_up_when_enough_ready() {
        let profile = make_profile(
            2,
            Some(crate::crd::ScalingConfig {
                min_ready: 2,
                max_clusters: 10,
                scale_up_threshold: 1,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
            }),
        );
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Ready));
        clusters.insert("pool-test-1".into(), make_entry(ClusterState::Ready));
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(&profile, &state, now);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_no_scale_up_when_at_max() {
        let profile = make_profile(
            3,
            Some(crate::crd::ScalingConfig {
                min_ready: 3,
                max_clusters: 2,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
            }),
        );
        let mut clusters = HashMap::new();
        clusters.insert("pool-test-0".into(), make_entry(ClusterState::Leased));
        clusters.insert("pool-test-1".into(), make_entry(ClusterState::Leased));
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(&profile, &state, now);

        // At max_clusters=2 with 2 leased, no room to create
        assert!(actions.is_empty());
    }

    #[test]
    fn test_scale_down_idle_clusters() {
        let profile = make_profile(
            1,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
            }),
        );
        let now = chrono::Utc::now();
        let long_ago = now - chrono::Duration::hours(1);
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-0".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(long_ago),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        clusters.insert(
            "pool-test-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(long_ago),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        let state = PoolState { clusters };

        let actions = compute_pool_actions(&profile, &state, now);

        // 2 ready, min_ready=1, one idle >30m → delete 1
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn test_no_scale_down_when_recently_idle() {
        let profile = make_profile(
            1,
            Some(crate::crd::ScalingConfig {
                min_ready: 1,
                max_clusters: 10,
                scale_up_threshold: 0,
                scale_down_after: "30m".to_string(),
                queue_timeout: "5m".to_string(),
            }),
        );
        let now = chrono::Utc::now();
        let just_now = now - chrono::Duration::minutes(5);
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-0".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(just_now),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        clusters.insert(
            "pool-test-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(just_now),
                health_failures: 0,
                state_since: None,
                spec_hash: None,
            },
        );
        let state = PoolState { clusters };

        let actions = compute_pool_actions(&profile, &state, now);

        // Both idle only 5m, threshold is 30m — no deletes
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 0);
    }

    #[test]
    fn test_spec_drift_triggers_recreation_of_unclaimed_clusters() {
        let profile = make_profile(2, None);
        let current_hash = profile_spec_hash(&profile);
        let stale_hash = current_hash.wrapping_add(1); // different hash

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(chrono::Utc::now()),
                health_failures: 0,
                state_since: None,
                spec_hash: Some(stale_hash), // stale
            },
        );
        clusters.insert(
            "pool-test-profile-2".into(),
            ClusterEntry {
                state: ClusterState::Leased,
                idle_since: None,
                health_failures: 0,
                state_since: None,
                spec_hash: Some(stale_hash), // stale but leased
            },
        );
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(&profile, &state, now);

        // Only the Ready (unclaimed) cluster should be deleted
        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 1);
        if let PoolAction::Delete(name) = &deletes[0] {
            assert_eq!(name, "pool-test-profile-1");
        }
    }

    #[test]
    fn test_no_drift_when_spec_hash_matches() {
        let profile = make_profile(2, None);
        let current_hash = profile_spec_hash(&profile);

        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-test-profile-1".into(),
            ClusterEntry {
                state: ClusterState::Ready,
                idle_since: Some(chrono::Utc::now()),
                health_failures: 0,
                state_since: None,
                spec_hash: Some(current_hash),
            },
        );
        let state = PoolState { clusters };
        let now = chrono::Utc::now();

        let actions = compute_pool_actions(&profile, &state, now);

        let deletes: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, PoolAction::Delete(_)))
            .collect();
        assert_eq!(deletes.len(), 0);
    }
}
