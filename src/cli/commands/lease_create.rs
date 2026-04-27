use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::config::CliConfig;
use super::leases::LeaseDetail;
use super::picker::{PickerItem, run_picker};
use super::pools::fetch_pools_for_config;
use super::state::record_kubeconfig;
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

pub struct LeaseCreateCommand<'a> {
    pub pool: Option<&'a str>,
    pub ttl: &'a str,
    pub no_wait: bool,
    pub wait_timeout: Option<&'a str>,
    pub kubeconfig_path: Option<&'a str>,
    pub target_override: Option<&'a str>,
    pub endpoint_override: Option<&'a str>,
    pub output: OutputFormat,
}

#[derive(Deserialize)]
struct LeaseAcceptedResponse {
    id: String,
    phase: String,
    profile: String,
    #[serde(default)]
    queue_position: u32,
    #[serde(default)]
    effective_ttl: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaseCreateOutput {
    id: String,
    phase: String,
    profile: String,
    cluster_name: Option<String>,
    expires_at: Option<String>,
    queue_position: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kubeconfig_path: Option<String>,
}

pub async fn lease_create(command: LeaseCreateCommand<'_>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(command.target_override, command.endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    let pool = match command.pool {
        Some(pool) => pool.to_string(),
        None => select_pool_for_lease(&config, command.output).await?,
    };
    let body_json = serde_json::json!({
        "profile": pool,
        "ttl": command.ttl,
    });
    let body_bytes = serde_json::to_vec(&body_json)?;
    // Body signing not yet supported server-side (extractor doesn't have body access).
    // Sign with empty body for now.
    let token = get_auth_header(&config, "POST", "/v1/leases", b"").await?;

    let client = authed_client();
    let response = with_auth(client.post(format!("{endpoint}/v1/leases")), &token)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
            .unwrap_or(text);
        anyhow::bail!("Failed to lease cluster (HTTP {status}): {msg}");
    }

    let accepted: LeaseAcceptedResponse = response.json().await?;

    if command.no_wait {
        return emit_pending_output(&accepted, command.output);
    }

    if command.output == OutputFormat::Text {
        eprintln!("Waiting for lease {} to become ready...", accepted.id);
    }

    let ready = wait_for_usable_lease(
        &config,
        &accepted.id,
        accepted.effective_ttl.clone(),
        command.wait_timeout,
    )
    .await?;

    let kubeconfig = ready
        .kubeconfig
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Lease {} became bound without kubeconfig", ready.id))?;
    let path = write_kubeconfig(
        &accepted.id,
        &accepted.profile,
        kubeconfig,
        command.kubeconfig_path,
    )?;
    if let Err(err) = record_kubeconfig(&config.endpoint, &accepted.id, &path) {
        eprintln!(
            "Warning: failed to record local kubeconfig path for {}: {err}",
            accepted.id
        );
    }

    emit_ready_output(&ready, accepted.effective_ttl, path, command.output)
}

async fn select_pool_for_lease(
    config: &super::config::ResolvedConfig,
    output: OutputFormat,
) -> Result<String> {
    let pools = fetch_pools_for_config(config).await?;
    if pools.is_empty() {
        anyhow::bail!("No pools available");
    }

    if output == OutputFormat::Json {
        return Ok(pools[0].name.clone());
    }

    let items: Vec<PickerItem> = pools
        .iter()
        .map(|pool| PickerItem {
            primary: pool.name.clone(),
            secondary: format!(
                "ready={} leased={} creating={} queue={}  {}",
                pool.ready,
                pool.leased,
                pool.creating,
                pool.queue_depth,
                pool.policy
                    .as_ref()
                    .map(|policy| format!(
                        "warm {} [max {}]",
                        policy.warm_target,
                        policy.max_clusters.unwrap_or(policy.warm_target)
                    ))
                    .unwrap_or_else(|| "no policy".to_string())
            ),
        })
        .collect();

    let idx = run_picker(
        "Lease Pool",
        "Use ↑/↓ and Enter. Press q or Esc to cancel.",
        &items,
    )?;
    Ok(pools[idx].name.clone())
}

fn emit_pending_output(accepted: &LeaseAcceptedResponse, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Text => {
            println!("Lease:   {}", accepted.id);
            println!("Pool:    {}", accepted.profile);
            println!("Status:  pending");
            if accepted.queue_position > 0 {
                println!("Queue:   #{}", accepted.queue_position);
            }
            if let Some(ttl) = accepted.effective_ttl.as_deref() {
                println!("TTL:     {ttl}");
            }
        }
        OutputFormat::Json => print_json(&LeaseCreateOutput {
            id: accepted.id.clone(),
            phase: accepted.phase.clone(),
            profile: accepted.profile.clone(),
            cluster_name: None,
            expires_at: None,
            queue_position: accepted.queue_position,
            effective_ttl: accepted.effective_ttl.clone(),
            kubeconfig_path: None,
        })?,
    }

    Ok(())
}

fn emit_ready_output(
    ready: &LeaseDetail,
    effective_ttl: Option<String>,
    kubeconfig_path: PathBuf,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Text => {
            println!("Cluster: {}", ready.cluster_name.as_deref().unwrap_or("-"));
            println!("Lease:   {}", ready.id);
            println!("Pool:    {}", ready.profile);
            if let Some(expires_at) = ready.expires_at.as_deref() {
                println!("Expires: {expires_at}");
            }
            if let Some(ttl) = effective_ttl.as_deref() {
                println!("TTL:     {ttl}");
            }
            println!("Config:  {}", kubeconfig_path.display());
            println!();
            println!("export KUBECONFIG={}", kubeconfig_path.display());
        }
        OutputFormat::Json => print_json(&LeaseCreateOutput {
            id: ready.id.clone(),
            phase: ready.phase.clone(),
            profile: ready.profile.clone(),
            cluster_name: ready.cluster_name.clone(),
            expires_at: ready.expires_at.clone(),
            queue_position: ready.queue_position,
            effective_ttl,
            kubeconfig_path: Some(kubeconfig_path.display().to_string()),
        })?,
    }

    Ok(())
}

async fn wait_for_usable_lease(
    config: &super::config::ResolvedConfig,
    lease_id: &str,
    effective_ttl: Option<String>,
    wait_timeout: Option<&str>,
) -> Result<LeaseDetail> {
    let deadline = parse_wait_timeout(wait_timeout)?;
    let path = format!("/v1/leases/{lease_id}");
    let endpoint = config.endpoint.as_str();
    let client = authed_client();

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            anyhow::bail!(
                "Timed out waiting for lease {lease_id} to become ready. Use --no-wait to return the queued lease immediately."
            );
        }

        let token = get_auth_header(config, "GET", &path, b"").await?;
        let response = with_auth(client.get(format!("{endpoint}{path}")), &token)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let detail: LeaseDetail = response.json().await?;
                if lease_is_usable(&detail) {
                    return Ok(detail);
                }
                if is_terminal_failure_phase(&detail.phase) {
                    let ttl = effective_ttl.unwrap_or_else(|| "requested TTL".to_string());
                    anyhow::bail!(
                        "Lease {lease_id} ended in phase {} before it became usable (effective TTL {ttl})",
                        detail.phase
                    );
                }
            }
            503 => {
                // Bound leases can briefly return 503 while kubeconfig extraction catches up.
            }
            404 => anyhow::bail!("Lease {lease_id} was not found while waiting for readiness"),
            status => anyhow::bail!("Failed to get lease {lease_id} while waiting (HTTP {status})"),
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn lease_is_usable(detail: &LeaseDetail) -> bool {
    detail.phase.eq_ignore_ascii_case("bound") && detail.kubeconfig.is_some()
}

fn is_terminal_failure_phase(phase: &str) -> bool {
    phase.eq_ignore_ascii_case("expired")
        || phase.eq_ignore_ascii_case("released")
        || phase.eq_ignore_ascii_case("recycling")
}

fn parse_wait_timeout(wait_timeout: Option<&str>) -> Result<Option<Instant>> {
    let Some(wait_timeout) = wait_timeout else {
        return Ok(None);
    };
    let std_duration = parse_cli_duration(wait_timeout)
        .ok_or_else(|| anyhow::anyhow!("Invalid --wait-timeout '{wait_timeout}'"))?;
    Ok(Some(Instant::now() + std_duration))
}

fn write_kubeconfig(
    lease_id: &str,
    pool: &str,
    kubeconfig: &str,
    kubeconfig_path: Option<&str>,
) -> Result<PathBuf> {
    let path = match kubeconfig_path {
        Some(p) => PathBuf::from(p),
        None => default_named_kubeconfig_path(pool, lease_id),
    };

    let kubeconfig =
        rewrite_local_kubeconfig_names(kubeconfig, &local_kubeconfig_alias(pool, lease_id))
            .unwrap_or_else(|_| kubeconfig.to_string());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, kubeconfig)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(path)
}

fn short_lease_id(lease_id: &str) -> &str {
    lease_id
        .strip_prefix("lease-")
        .unwrap_or(lease_id)
        .get(..8)
        .unwrap_or_else(|| lease_id.strip_prefix("lease-").unwrap_or(lease_id))
}

fn local_kubeconfig_alias(pool: &str, lease_id: &str) -> String {
    format!("kobe-{pool}-{}", short_lease_id(lease_id))
}

fn default_named_kubeconfig_path(pool: &str, lease_id: &str) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kube")
        .join(format!("{}.yaml", local_kubeconfig_alias(pool, lease_id)))
}

fn rewrite_local_kubeconfig_names(kubeconfig: &str, alias: &str) -> Result<String> {
    let mut doc: Value = serde_yaml_ng::from_str(kubeconfig)?;

    if let Some(clusters) = doc.get_mut("clusters").and_then(Value::as_sequence_mut)
        && let Some(cluster) = clusters.first_mut()
        && let Some(name) = cluster.get_mut("name")
    {
        *name = Value::String(alias.to_string());
    }

    if let Some(current_context) = doc.get_mut("current-context") {
        *current_context = Value::String(alias.to_string());
    }

    if let Some(contexts) = doc.get_mut("contexts").and_then(Value::as_sequence_mut)
        && let Some(context) = contexts.first_mut()
    {
        if let Some(name) = context.get_mut("name") {
            *name = Value::String(alias.to_string());
        }
        if let Some(cluster) = context
            .get_mut("context")
            .and_then(|ctx| ctx.get_mut("cluster"))
        {
            *cluster = Value::String(alias.to_string());
        }
        if let Some(user) = context
            .get_mut("context")
            .and_then(|ctx| ctx.get_mut("user"))
        {
            *user = Value::String(alias.to_string());
        }
    }

    if let Some(users) = doc.get_mut("users").and_then(Value::as_sequence_mut)
        && let Some(user) = users.first_mut()
        && let Some(name) = user.get_mut("name")
    {
        *name = Value::String(alias.to_string());
    }

    Ok(serde_yaml_ng::to_string(&doc)?)
}

fn parse_cli_duration(s: &str) -> Option<Duration> {
    const MAX_SECONDS: u64 = 365 * 24 * 3600;

    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let mut total_seconds: u64 = 0;
    let mut current_num = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
            continue;
        }

        let n: u64 = current_num.parse().ok()?;
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

    if !current_num.is_empty() || total_seconds == 0 {
        return None;
    }

    Some(Duration::from_secs(total_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_lease_requires_bound_phase_and_kubeconfig() {
        let detail = LeaseDetail {
            id: "lease-1".to_string(),
            phase: "Bound".to_string(),
            profile: "ci-small".to_string(),
            cluster_name: Some("pool-ci-small-1".to_string()),
            expires_at: Some("2026-01-01T00:00:00Z".to_string()),
            queue_position: 0,
            kubeconfig: Some("apiVersion: v1".to_string()),
        };

        assert!(lease_is_usable(&detail));
        assert!(!lease_is_usable(&LeaseDetail {
            kubeconfig: None,
            ..detail.clone()
        }));
        assert!(!lease_is_usable(&LeaseDetail {
            phase: "Pending".to_string(),
            ..detail
        }));
    }

    #[test]
    fn terminal_failure_phases_are_rejected() {
        assert!(is_terminal_failure_phase("Expired"));
        assert!(is_terminal_failure_phase("Released"));
        assert!(is_terminal_failure_phase("Recycling"));
        assert!(!is_terminal_failure_phase("Pending"));
        assert!(!is_terminal_failure_phase("Bound"));
    }

    #[test]
    fn parse_cli_duration_accepts_human_time() {
        assert_eq!(parse_cli_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_cli_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_cli_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_cli_duration(""), None);
        assert_eq!(parse_cli_duration("10"), None);
        assert_eq!(parse_cli_duration("5d"), None);
    }

    #[test]
    fn short_lease_id_strips_prefix_and_truncates() {
        assert_eq!(short_lease_id("lease-9ff83245ea0f"), "9ff83245");
        assert_eq!(short_lease_id("abc"), "abc");
    }

    #[test]
    fn rewrite_local_kubeconfig_names_uses_alias_for_context_and_user() {
        let raw = r#"apiVersion: v1
kind: Config
clusters:
- name: pool-ci-k3s-small
  cluster:
    server: https://example
contexts:
- name: lease-abc
  context:
    cluster: pool-ci-k3s-small
    user: lease-abc
current-context: lease-abc
users:
- name: lease-abc
  user:
    token: test
"#;

        let rewritten = rewrite_local_kubeconfig_names(raw, "kobe-ci-k3s-small-9ff83245").unwrap();
        assert!(rewritten.contains("current-context: kobe-ci-k3s-small-9ff83245"));
        assert!(rewritten.contains("- name: kobe-ci-k3s-small-9ff83245"));
        assert!(rewritten.contains("user: kobe-ci-k3s-small-9ff83245"));
        assert!(rewritten.contains("cluster: kobe-ci-k3s-small-9ff83245"));
        assert!(!rewritten.contains("name: pool-ci-k3s-small"));
    }
}
