use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::ResolvedConfig;
use super::{authed_client, get_auth_header, with_auth};

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
    pub queue_depth: u32,
    #[serde(default)]
    pub policy: Option<PoolPolicySummary>,
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

pub(crate) fn format_policy(pool: &PoolSummary) -> Option<String> {
    let Some(policy) = &pool.policy else {
        return None;
    };

    if policy.mode == "autoscaled" {
        let max_clusters = policy.max_clusters.unwrap_or(policy.warm_target);
        let scale_down_after = policy.scale_down_after.as_deref().unwrap_or("-");

        Some(format!(
            "ttl {}  warm {}/{}  scale down after {}",
            policy.ttl, policy.warm_target, max_clusters, scale_down_after
        ))
    } else {
        Some(format!(
            "ttl {}  warm {} fixed",
            policy.ttl, policy.warm_target
        ))
    }
}

pub(crate) fn print_pool_table(pools: &[PoolSummary], indent: &str) {
    for (index, pool) in pools.iter().enumerate() {
        if index > 0 {
            println!();
        }

        println!("{indent}{}", pool.name);
        println!(
            "{indent}  ready {}  leased {}  creating {}  recycling {}  queue {}",
            pool.ready, pool.leased, pool.creating, pool.recycling, pool.queue_depth
        );
        if let Some(policy) = format_policy(pool) {
            println!("{indent}  {policy}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolSummary, format_policy};

    #[test]
    fn pool_summary_accepts_legacy_claimed_field() {
        let pool: PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "ci-small",
            "ready": 2,
            "claimed": 1
        }))
        .expect("legacy pool payload should deserialize");

        assert_eq!(pool.leased, 1);
        assert_eq!(pool.creating, 0);
        assert_eq!(pool.recycling, 0);
        assert_eq!(pool.unhealthy, 0);
        assert_eq!(pool.queue_depth, 0);
        assert!(pool.policy.is_none());
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
}
