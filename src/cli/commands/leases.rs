use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::ResolvedConfig;
use super::{authed_client, get_auth_header, with_auth};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaseSummary {
    pub id: String,
    pub phase: String,
    pub profile: String,
    #[serde(default)]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub queue_position: u32,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LeaseDetail {
    pub id: String,
    pub phase: String,
    pub profile: String,
    #[serde(default)]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub queue_position: u32,
    #[serde(default)]
    pub kubeconfig: Option<String>,
}

pub(crate) async fn fetch_leases_path(
    config: &ResolvedConfig,
    path: &str,
) -> Result<Vec<LeaseSummary>> {
    let endpoint = config.endpoint.as_str();
    let token = get_auth_header(config, "GET", path, b"").await?;

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}{path}")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to list leases (HTTP {})", response.status());
    }

    Ok(response.json().await?)
}

pub(crate) async fn fetch_lease(
    config: &ResolvedConfig,
    lease_id: &str,
) -> Result<LeaseDetail> {
    let path = format!("/v1/leases/{lease_id}");
    let endpoint = config.endpoint.as_str();
    let token = get_auth_header(config, "GET", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}{path}")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get lease {lease_id} (HTTP {})", response.status());
    }

    Ok(response.json().await?)
}

pub(crate) fn format_relative_time(iso: &str) -> String {
    let Ok(expires) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let now = chrono::Utc::now();
    let diff = expires.signed_duration_since(now);

    if diff.num_seconds() < 0 {
        "expired".to_string()
    } else if diff.num_hours() > 0 {
        format!("{}h {}m left", diff.num_hours(), diff.num_minutes() % 60)
    } else if diff.num_minutes() > 0 {
        format!("{}m left", diff.num_minutes())
    } else {
        format!("{}s left", diff.num_seconds())
    }
}

pub(crate) fn lease_phase_label(lease: &LeaseSummary) -> String {
    lease.phase.to_ascii_lowercase()
}

pub(crate) fn lease_cluster_label(lease: &LeaseSummary) -> &str {
    lease.cluster_name.as_deref().unwrap_or("-")
}

pub(crate) fn lease_when_label(lease: &LeaseSummary) -> String {
    if lease.phase.eq_ignore_ascii_case("pending") && lease.queue_position > 0 {
        format!("queue #{}", lease.queue_position)
    } else if let Some(expires_at) = lease.expires_at.as_deref() {
        format_relative_time(expires_at)
    } else {
        lease_phase_label(lease)
    }
}
