use anyhow::Result;
use serde::Serialize;

use super::config::{AuthMode, CliConfig};
use super::leases::{
    LeaseSummary, fetch_all_leases, fetch_lease, format_lease_status_line, is_status_hidden_phase,
    lease_cluster_label,
};
use super::pools::{PoolSummary, fetch_pools_for_config, print_pool_table};
use super::purge::live_lease_ids;
use super::state::{find_orphan_kubeconfigs, resolve_kubeconfig_path};
use super::{OutputFormat, authed_client, cli_version, get_auth_header, print_json, with_auth};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusAuthOutput {
    mode: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusPoolOutput {
    #[serde(flatten)]
    pool: PoolSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusOutput {
    cli_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    endpoint: String,
    endpoint_version: String,
    auth: StatusAuthOutput,
    leases: Vec<LeaseSummary>,
    pools: Vec<StatusPoolOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pools_error: Option<String>,
    /// Always serialized so JSON consumers can rely on the field existing
    /// (e.g. `jq '.orphanKubeconfigs | length'` on a fresh state with no
    /// orphans returns 0 instead of erroring on `null`).
    orphan_kubeconfigs: Vec<String>,
}

fn format_status_header(endpoint: &str, endpoint_version: &str, auth_summary: &str) -> String {
    format!(
        "{endpoint}  cli {}  api {endpoint_version}  {auth_summary}",
        cli_version()
    )
}

fn auth_error_hint(error: &str) -> Option<&'static str> {
    if error.contains("found in SSH agent") {
        Some("check SSH_AUTH_SOCK and ssh-add -l")
    } else {
        None
    }
}

fn hidden_lease_counts(leases: &[LeaseSummary]) -> (usize, usize) {
    let mut released = 0;
    let mut expired = 0;
    for lease in leases {
        match lease.phase.to_ascii_lowercase().as_str() {
            "released" => released += 1,
            "expired" => expired += 1,
            _ => {}
        }
    }
    (released, expired)
}

fn format_hidden_lease_parts(released: usize, expired: usize) -> String {
    let mut parts = Vec::new();
    if expired > 0 {
        parts.push(format!("{expired} expired"));
    }
    if released > 0 {
        parts.push(format!("{released} released"));
    }
    parts.join(", ")
}

pub async fn status(
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
    show_all: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();

    // Fetch server status (unauthenticated — /v1/status supports OptionalAuth)
    let (token, auth_error) = match get_auth_header(&config, "GET", "/v1/status", b"").await {
        Ok(token) => (token, None),
        Err(err) => (None, Some(err.to_string())),
    };

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}/v1/status")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get status (HTTP {})", response.status());
    }

    let server: serde_json::Value = response.json().await?;
    let endpoint_version = server["version"].as_str().unwrap_or("?");

    let auth_summary = match &config.auth {
        AuthMode::Ssh => {
            let fp = config
                .ssh_fingerprint
                .as_deref()
                .map(|f| {
                    if f.len() > 20 {
                        format!("{}...{}", &f[..12], &f[f.len() - 4..])
                    } else {
                        f.to_string()
                    }
                })
                .unwrap_or_else(|| "auto".to_string());
            format!("ssh {fp}")
        }
        AuthMode::Oidc => "oidc".to_string(),
        AuthMode::Token => "token".to_string(),
        AuthMode::None => "none".to_string(),
    };
    let auth_mode = config.auth.to_string();

    let (pools, pools_error, leases) = if auth_error.is_some() {
        (Vec::new(), None, Vec::new())
    } else {
        let (pools, pools_error) = match fetch_pools_for_config(&config).await {
            Ok(pools) => (pools, None),
            Err(err) => (Vec::new(), Some(err.to_string())),
        };
        let leases = fetch_all_leases(&config).await.unwrap_or_default();
        (pools, pools_error, leases)
    };
    let leases = enrich_leases(&config, leases).await;

    // Orphan detection only makes sense when we successfully fetched leases —
    // otherwise we don't know which lease IDs are actually active server-side
    // and would surface a false positive on every tracked kubeconfig. Uses the
    // shared `live_lease_ids` filter (treats Recycling leases as still-live so
    // their kubeconfigs aren't flagged mid-teardown).
    let orphan_kubeconfigs: Vec<String> = if auth_error.is_none() {
        let live_ids = live_lease_ids(&leases);
        find_orphan_kubeconfigs(endpoint, &live_ids)
            .unwrap_or_default()
            .into_iter()
            .map(|orphan| orphan.path.display().to_string())
            .collect()
    } else {
        Vec::new()
    };

    let mut pool_details = Vec::with_capacity(pools.len());
    for pool in pools {
        pool_details.push(StatusPoolOutput { pool });
    }

    if output == OutputFormat::Json {
        return print_json(&StatusOutput {
            cli_version: cli_version().to_string(),
            target: config.target.clone(),
            endpoint: endpoint.to_string(),
            endpoint_version: endpoint_version.to_string(),
            auth: StatusAuthOutput {
                mode: auth_mode,
                summary: auth_summary,
                ssh_fingerprint: config.ssh_fingerprint.clone(),
                error: auth_error.clone(),
            },
            leases,
            pools: pool_details,
            pools_error,
            orphan_kubeconfigs,
        });
    }

    println!(
        "{}",
        format_status_header(endpoint, endpoint_version, &auth_summary)
    );
    super::version::warn_if_cli_behind_endpoint(endpoint_version);

    if let Some(err) = &auth_error {
        println!("auth failed: {err}");
        if let Some(hint) = auth_error_hint(err) {
            println!("hint: {hint}");
        }
        println!();
        return Ok(());
    }
    println!();

    let (hidden_released, hidden_expired) = hidden_lease_counts(&leases);
    let hidden = hidden_released + hidden_expired;
    let mut visible: Vec<&LeaseSummary> = if show_all {
        leases.iter().collect()
    } else {
        leases
            .iter()
            .filter(|lease| !is_status_hidden_phase(&lease.phase))
            .collect()
    };
    if show_all {
        visible.sort_by_key(|lease| is_status_hidden_phase(&lease.phase));
    }

    println!("\x1b[1mLeases\x1b[0m");
    if visible.is_empty() {
        if hidden == 0 {
            println!("  none");
        } else {
            println!(
                "  none live  ({}; `kobe status --all` to list)",
                format_hidden_lease_parts(hidden_released, hidden_expired)
            );
        }
    } else {
        for lease in visible {
            println!("  {}", format_lease_status_line(lease));
            if !lease.is_sandbox() {
                println!("    cluster: {}", lease_cluster_label(lease));
            }
            if let Some(kubeconfig_path) = lease.kubeconfig_path.as_deref() {
                println!("    config:  {kubeconfig_path}");
            }
        }
        if !show_all && hidden > 0 {
            println!(
                "  ({} hidden; `kobe status --all`)",
                format_hidden_lease_parts(hidden_released, hidden_expired)
            );
        }
    }
    if !orphan_kubeconfigs.is_empty() {
        println!(
            "  \x1b[33m{} orphan kubeconfig(s) detected (lease no longer exists). Run `kobe purge --orphans-only` to clean up.\x1b[0m",
            orphan_kubeconfigs.len()
        );
    }
    println!();

    println!("\x1b[1mPools\x1b[0m");
    if let Some(err) = &pools_error {
        println!("  Error listing pools: {err}");
        println!();
        return Ok(());
    }

    if pool_details.is_empty() {
        println!("  No pools available");
        println!();
        return Ok(());
    }

    let pools: Vec<PoolSummary> = pool_details.into_iter().map(|detail| detail.pool).collect();
    print_pool_table(&pools, &leases, "  ");
    println!();

    Ok(())
}

async fn enrich_leases(
    config: &super::config::ResolvedConfig,
    leases: Vec<LeaseSummary>,
) -> Vec<LeaseSummary> {
    let mut enriched = Vec::with_capacity(leases.len());

    for lease in leases {
        let kubeconfig_path = resolve_kubeconfig_path(&config.endpoint, &lease.id);
        match fetch_lease(config, &lease.id).await {
            Ok(detail) => enriched.push(LeaseSummary {
                id: detail.id,
                phase: detail.phase,
                resource_kind: detail.resource_kind,
                capabilities: detail.capabilities,
                profile: detail.profile,
                cluster_name: detail.cluster_name.or(lease.cluster_name),
                expires_at: detail.expires_at.or(lease.expires_at),
                queue_position: if detail.queue_position == 0 {
                    lease.queue_position
                } else {
                    detail.queue_position
                },
                requester: lease.requester,
                kubeconfig_path,
                alias: lease.alias,
                metadata: detail.metadata.or(lease.metadata),
            }),
            Err(_) => enriched.push(LeaseSummary {
                kubeconfig_path,
                ..lease
            }),
        }
    }

    enriched
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SSH hint fires on the one failure it can actually explain, and
    /// stays quiet otherwise.
    ///
    /// "no key found in SSH agent" is the failure a user cannot diagnose from
    /// the message alone — the fix is environmental (`SSH_AUTH_SOCK`,
    /// `ssh-add -l`), not something they typed wrong. Attaching that hint to
    /// unrelated auth failures would send people chasing their agent when the
    /// real problem is an expired token or a bad issuer.
    #[test]
    fn status_header_is_one_line() {
        let line = format_status_header("https://kobe.example", "main", "ssh SHA256:DpBgx...hSK8");
        assert!(
            !line.contains('\n'),
            "header must be a single glance line, got {line:?}"
        );
        assert!(line.contains("https://kobe.example"));
        assert!(line.contains("cli "));
        assert!(line.contains("api main"));
        assert!(line.contains("ssh "));
    }

    #[test]
    fn hidden_lease_parts_name_released_and_expired() {
        let leases = vec![
            LeaseSummary {
                id: "sandbox-a".into(),
                phase: "Expired".into(),
                resource_kind: "Sandbox".into(),
                capabilities: Vec::new(),
                profile: "agent-trusted".into(),
                cluster_name: None,
                expires_at: None,
                queue_position: 0,
                requester: None,
                kubeconfig_path: None,
                alias: None,
                metadata: None,
            },
            LeaseSummary {
                id: "sandbox-b".into(),
                phase: "Released".into(),
                resource_kind: "Sandbox".into(),
                capabilities: Vec::new(),
                profile: "agent-trusted".into(),
                cluster_name: None,
                expires_at: None,
                queue_position: 0,
                requester: None,
                kubeconfig_path: None,
                alias: None,
                metadata: None,
            },
            LeaseSummary {
                id: "sandbox-c".into(),
                phase: "Ready".into(),
                resource_kind: "Sandbox".into(),
                capabilities: Vec::new(),
                profile: "agent-trusted".into(),
                cluster_name: None,
                expires_at: None,
                queue_position: 0,
                requester: None,
                kubeconfig_path: None,
                alias: None,
                metadata: None,
            },
        ];
        assert_eq!(hidden_lease_counts(&leases), (1, 1));
        assert_eq!(format_hidden_lease_parts(1, 2), "2 expired, 1 released");
        assert_eq!(format_hidden_lease_parts(0, 3), "3 expired");
        assert_eq!(format_hidden_lease_parts(1, 0), "1 released");
    }

    #[test]
    fn the_ssh_hint_is_offered_only_for_the_failure_it_explains() {
        assert!(
            auth_error_hint("no matching key found in SSH agent").is_some(),
            "the agent-lookup failure is the case this hint exists for"
        );

        for unrelated in [
            "token expired",
            "invalid issuer",
            "connection refused",
            "403 Forbidden",
            "",
        ] {
            assert!(
                auth_error_hint(unrelated).is_none(),
                "must not offer an SSH-agent hint for: {unrelated:?}"
            );
        }
    }
}
