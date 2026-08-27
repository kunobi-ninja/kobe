use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::ResolvedConfig;
use super::{OutputFormat, authed_client, get_auth_header, get_auth_header_for_output, with_auth};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaseSummary {
    pub id: String,
    pub phase: String,
    #[serde(default = "default_resource_kind")]
    pub resource_kind: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(alias = "pool")]
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
    /// Caller-supplied alias (#107 P2), selectable interchangeably with the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LeaseDetail {
    pub id: String,
    pub phase: String,
    #[serde(default = "default_resource_kind")]
    pub resource_kind: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(alias = "pool")]
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

fn default_resource_kind() -> String {
    "Cluster".to_string()
}

impl LeaseSummary {
    pub(crate) fn is_sandbox(&self) -> bool {
        self.resource_kind.eq_ignore_ascii_case("sandbox") || self.id.starts_with("sandbox-")
    }
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

async fn fetch_sandbox_leases_with_output(
    config: &ResolvedConfig,
    output: OutputFormat,
) -> Result<Vec<LeaseSummary>> {
    let path = "/v1/sandbox-leases";
    let endpoint = config.endpoint.as_str();
    let token = get_auth_header_for_output(config, "GET", path, b"", output).await?;
    let response = with_auth(
        super::authed_client().get(format!("{endpoint}{path}")),
        &token,
    )
    .send()
    .await?;
    let status = response.status();
    if matches!(status.as_u16(), 403 | 404 | 501) {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        anyhow::bail!("Failed to list Sandbox leases (HTTP {status})");
    }
    let mut leases: Vec<LeaseSummary> = response.json().await?;
    for lease in &mut leases {
        lease.resource_kind = "Sandbox".to_string();
        lease.capabilities = vec![
            "exec".to_string(),
            "cancel".to_string(),
            "logs".to_string(),
            "attach".to_string(),
            "port-forward".to_string(),
            "extend".to_string(),
            "release".to_string(),
        ];
    }
    Ok(leases)
}

/// Return every lease kind through one client-side inventory. The server keeps
/// kind-specific storage and authorization routes; callers should not need to
/// know that to select, inspect, extend, or release a lease.
pub(crate) async fn fetch_all_leases(config: &ResolvedConfig) -> Result<Vec<LeaseSummary>> {
    fetch_all_leases_with_output(config, OutputFormat::Text).await
}

pub(crate) async fn fetch_all_leases_with_output(
    config: &ResolvedConfig,
    output: OutputFormat,
) -> Result<Vec<LeaseSummary>> {
    let mut leases = if output == OutputFormat::Text {
        fetch_leases_path(config, "/v1/leases").await?
    } else {
        let path = "/v1/leases";
        let endpoint = config.endpoint.as_str();
        let token = get_auth_header_for_output(config, "GET", path, b"", output).await?;
        let response = with_auth(authed_client().get(format!("{endpoint}{path}")), &token)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to list leases (HTTP {})", response.status());
        }
        response.json().await?
    };
    for lease in &mut leases {
        lease.resource_kind = "Cluster".to_string();
        lease.capabilities = vec![
            "kubeconfig".to_string(),
            "extend".to_string(),
            "release".to_string(),
        ];
    }
    leases.extend(fetch_sandbox_leases_with_output(config, output).await?);
    leases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(leases)
}

/// A lease is terminal once it no longer refers to a live/pending cluster.
pub(crate) fn is_terminal_phase(phase: &str) -> bool {
    matches!(
        phase.to_ascii_lowercase().as_str(),
        "released" | "expired" | "recycling"
    )
}

/// Find the caller's single ACTIVE lease carrying `alias`, if any (#107 P3).
/// Lists the caller's leases (server already scopes to identity) and filters
/// client-side, so it shares the proven `/v1/leases` request path.
pub(crate) async fn find_active_lease_by_alias(
    config: &ResolvedConfig,
    alias: &str,
) -> Result<Option<LeaseSummary>> {
    let found = fetch_all_leases(config)
        .await?
        .into_iter()
        .find(|l| l.alias.as_deref() == Some(alias) && !is_terminal_phase(&l.phase));
    Ok(found)
}

pub(crate) async fn fetch_lease(config: &ResolvedConfig, lease_id: &str) -> Result<LeaseDetail> {
    let sandbox = lease_id.starts_with("sandbox-");
    let path = if sandbox {
        format!("/v1/sandbox-leases/{lease_id}")
    } else {
        format!("/v1/leases/{lease_id}")
    };
    let endpoint = config.endpoint.as_str();
    let token = get_auth_header(config, "GET", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}{path}")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to get lease {lease_id} (HTTP {})",
            response.status()
        );
    }

    let mut detail: LeaseDetail = response.json().await?;
    if sandbox {
        detail.resource_kind = "Sandbox".to_string();
        detail.capabilities = vec![
            "exec".to_string(),
            "cancel".to_string(),
            "logs".to_string(),
            "attach".to_string(),
            "port-forward".to_string(),
            "extend".to_string(),
            "release".to_string(),
        ];
    }
    Ok(detail)
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
