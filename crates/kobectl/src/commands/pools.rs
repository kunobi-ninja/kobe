use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::config::ResolvedConfig;
use super::leases::LeaseSummary;
use super::{OutputFormat, authed_client, get_auth_header, get_auth_header_for_output, with_auth};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PoolPolicySummary {
    pub mode: String,
    pub ttl: String,
    pub warm_target: u32,
    pub max_clusters: Option<u32>,
    pub scale_up_threshold: Option<u32>,
    pub scale_down_after: Option<String>,
    pub queue_timeout: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PoolSummary {
    pub name: String,
    /// Resource allocated by this pool. Older endpoints omitted the field and
    /// served Cluster pools only, so Cluster is the compatibility default.
    #[serde(default = "default_resource_kind")]
    pub resource_kind: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub phase: Option<String>,
    pub ready: u32,
    #[serde(default, alias = "claimed")]
    pub leased: u32,
    #[serde(default)]
    pub creating: u32,
    #[serde(default)]
    pub recycling: u32,
    #[serde(default)]
    pub unhealthy: u32,
    #[serde(default)]
    pub quarantined: u32,
    #[serde(default)]
    pub queue_depth: u32,
    #[serde(default)]
    pub policy: Option<PoolPolicySummary>,
}

fn default_resource_kind() -> String {
    "Cluster".to_string()
}

impl PoolSummary {
    pub(crate) fn is_sandbox(&self) -> bool {
        self.resource_kind.eq_ignore_ascii_case("sandbox")
    }

    pub(crate) fn supports(&self, capability: &str) -> bool {
        if self.capabilities.is_empty() {
            return if self.is_sandbox() {
                matches!(
                    capability,
                    "lease"
                        | "exec"
                        | "cancel"
                        | "logs"
                        | "attach"
                        | "port-forward"
                        | "extend"
                        | "release"
                )
            } else {
                matches!(capability, "lease" | "kubeconfig" | "extend" | "release")
            };
        }
        self.capabilities
            .iter()
            .any(|candidate| candidate == capability)
    }
}

pub(crate) async fn fetch_pools_for_config(config: &ResolvedConfig) -> Result<Vec<PoolSummary>> {
    let endpoint = config.endpoint.as_str();
    let token = get_auth_header(config, "GET", "/v1/pools", b"").await?;

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}/v1/pools")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to list pools (HTTP {})", response.status());
    }

    Ok(response.json().await?)
}

pub(crate) async fn fetch_pool_for_config_with_output(
    config: &ResolvedConfig,
    name: &str,
    output: OutputFormat,
) -> Result<PoolSummary> {
    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/pools/{name}");
    let token = get_auth_header_for_output(config, "GET", &path, b"", output).await?;
    let response = with_auth(
        super::authed_client().get(format!("{endpoint}{path}")),
        &token,
    )
    .send()
    .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_string))
            .unwrap_or(body);
        anyhow::bail!("Failed to resolve pool {name} (HTTP {status}): {message}");
    }
    Ok(response.json().await?)
}

/// Ready is always shown. Other counters only when non-zero.
pub(crate) fn format_pool_counts(pool: &PoolSummary) -> String {
    let mut parts = vec![format!("ready {}", pool.ready)];
    for (label, value) in [
        ("leased", pool.leased),
        ("creating", pool.creating),
        ("recycling", pool.recycling),
        ("quarantined", pool.quarantined),
        ("unhealthy", pool.unhealthy),
        ("queue", pool.queue_depth),
    ] {
        if value > 0 {
            parts.push(format!("{label} {value}"));
        }
    }
    parts.join("  ")
}

pub(crate) fn format_policy(pool: &PoolSummary) -> Option<String> {
    let Some(policy) = &pool.policy else {
        return None;
    };

    if policy.mode == "autoscaled" {
        let max_clusters = policy.max_clusters.unwrap_or(policy.warm_target);
        let scale_down_after = policy.scale_down_after.as_deref().unwrap_or("-");

        Some(format!(
            "ttl {}  warm {} [max {}]  scale down after {}",
            policy.ttl, policy.warm_target, max_clusters, scale_down_after
        ))
    } else {
        Some(format!(
            "ttl {}  warm {} fixed",
            policy.ttl, policy.warm_target
        ))
    }
}

/// Count leases in `Recycling` phase per pool (keyed by lease `profile`).
///
/// These leases are reclaiming their backend instances but still occupy a slot
/// against the pool's `maxClusters` until cleanup completes — so the pool
/// manager counts them toward capacity even though they do not appear in the
/// pool's `recycling` instance count (the instance was already torn down).
pub(crate) fn recycling_leases_by_pool(leases: &[LeaseSummary]) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for lease in leases {
        if lease.phase.eq_ignore_ascii_case("recycling") {
            *counts.entry(lease.profile.clone()).or_insert(0) += 1;
        }
    }
    counts
}

pub(crate) fn print_pool_table(pools: &[PoolSummary], leases: &[LeaseSummary], indent: &str) {
    let recycling_leases = recycling_leases_by_pool(leases);

    for (index, pool) in pools.iter().enumerate() {
        if index > 0 {
            println!();
        }

        let phase = pool.phase.as_deref().unwrap_or("Unknown");
        println!("{indent}{}  {}  {phase}", pool.name, pool.resource_kind);
        println!("{indent}  {}", format_pool_counts(pool));
        if let Some(policy) = format_policy(pool) {
            println!("{indent}  {policy}");
        }
        if !pool.capabilities.is_empty() {
            println!("{indent}  actions {}", pool.capabilities.join(", "));
        }
        if let Some(count) = recycling_leases.get(&pool.name)
            && *count > 0
        {
            let leases_word = if *count == 1 { "lease" } else { "leases" };
            println!(
                "{indent}  note: {count} {leases_word} reclaiming capacity (new warm slots will open when cleanup finishes)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolSummary, format_policy, format_pool_counts, recycling_leases_by_pool};
    use crate::commands::leases::LeaseSummary;

    #[test]
    fn pool_summary_accepts_legacy_claimed_field() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "ci-small",
            "ready": 2,
            "claimed": 1
        }))
        .expect("legacy pool payload should deserialize");

        assert_eq!(pool.leased, 1);
        assert_eq!(pool.resource_kind, "Cluster");
        assert!(pool.supports("kubeconfig"));
        assert_eq!(pool.creating, 0);
        assert_eq!(pool.recycling, 0);
        assert_eq!(pool.unhealthy, 0);
        assert_eq!(pool.queue_depth, 0);
        assert!(pool.policy.is_none());
    }

    #[test]
    fn typed_pool_exposes_only_advertised_capabilities() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "agents",
            "resourceKind": "Sandbox",
            "capabilities": ["lease", "exec", "logs"],
            "ready": 1,
            "leased": 0
        }))
        .unwrap();
        assert!(pool.is_sandbox());
        assert!(pool.supports("exec"));
        assert!(!pool.supports("kubeconfig"));
    }

    #[test]
    fn format_pool_counts_hides_zeros() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "agent-trusted",
            "resourceKind": "Sandbox",
            "ready": 4,
            "leased": 0,
            "creating": 0,
            "recycling": 0,
            "quarantined": 0,
            "queueDepth": 0
        }))
        .unwrap();
        assert_eq!(format_pool_counts(&pool), "ready 4");

        let busy: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "ci-k3s-kunobi",
            "ready": 4,
            "leased": 5,
            "creating": 2
        }))
        .unwrap();
        assert_eq!(format_pool_counts(&busy), "ready 4  leased 5  creating 2");
    }

    #[test]
    fn format_policy_returns_none_when_endpoint_does_not_expose_policy() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "ci-small",
            "ready": 2,
            "leased": 1
        }))
        .expect("pool payload should deserialize");

        assert!(format_policy(&pool).is_none());
    }

    #[test]
    fn format_policy_renders_autoscaled_warm_target_and_max_capacity() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "ci-small",
            "ready": 2,
            "leased": 0,
            "policy": {
                "mode": "autoscaled",
                "ttl": "1h",
                "warmTarget": 2,
                "maxClusters": 8,
                "scaleDownAfter": "30m"
            }
        }))
        .expect("pool payload should deserialize");

        assert_eq!(
            format_policy(&pool).as_deref(),
            Some("ttl 1h  warm 2 [max 8]  scale down after 30m")
        );
    }

    fn lease(phase: &str, pool: &str) -> LeaseSummary {
        serde_json::from_value(serde_json::json!({
            "id": "l-test",
            "phase": phase,
            "profile": pool,
        }))
        .expect("test lease payload should deserialize")
    }

    #[test]
    fn recycling_leases_by_pool_counts_per_pool_case_insensitive() {
        let leases = vec![
            lease("Recycling", "ci-k0s-small"),
            lease("recycling", "ci-k0s-small"),
            lease("Bound", "ci-k0s-small"),
            lease("RECYCLING", "ci-k3s-small"),
            lease("Pending", "ci-vkobe-small"),
        ];

        let counts = recycling_leases_by_pool(&leases);
        assert_eq!(counts.get("ci-k0s-small"), Some(&2));
        assert_eq!(counts.get("ci-k3s-small"), Some(&1));
        assert_eq!(counts.get("ci-vkobe-small"), None);
    }

    #[test]
    fn recycling_leases_by_pool_returns_empty_when_nothing_is_recycling() {
        let leases = vec![lease("Bound", "ci-k0s-small"), lease("Pending", "ci-small")];
        let counts = recycling_leases_by_pool(&leases);
        assert!(counts.is_empty());
    }
}
