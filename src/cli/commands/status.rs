use anyhow::Result;
use serde::Serialize;

use super::config::{AuthMode, CliConfig};
use super::leases::{
    LeaseSummary, fetch_lease, fetch_leases_path, lease_cluster_label, lease_phase_label,
    lease_when_label,
};
use super::pools::{PoolSummary, fetch_pools_for_config, print_pool_block};
use super::state::resolve_kubeconfig_path;
use super::{OutputFormat, authed_client, cli_version, get_auth_header, print_json, with_auth};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusAuthOutput {
    mode: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<String>,
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
}

pub async fn status(
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();

    // Fetch server status (unauthenticated — /v1/status supports OptionalAuth)
    let token = get_auth_header(&config, "GET", "/v1/status", b"")
        .await
        .ok()
        .flatten();

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

    let pools = fetch_pools_for_config(&config).await.unwrap_or_default();
    let leases = fetch_leases_path(&config, "/v1/leases")
        .await
        .unwrap_or_default();
    let leases = enrich_leases(&config, leases).await;

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
            },
            leases,
            pools: pool_details,
        });
    }

    println!();
    println!("\x1b[1mkobe\x1b[0m");
    println!("  cli version: {}", cli_version());
    if let Some(target) = &config.target {
        println!("  target: {target}");
    }
    println!("  endpoint: {endpoint}");
    println!("  endpoint version: {endpoint_version}");
    println!();

    println!("\x1b[1mAuth\x1b[0m");
    println!("  {auth_summary}");
    println!();

    println!("\x1b[1mLeases\x1b[0m");
    if leases.is_empty() {
        println!("  none");
    } else {
        for lease in &leases {
            println!(
                "  {:<24}  {:<12}  {:<8}  {}",
                lease.id,
                lease.profile,
                lease_phase_label(lease),
                lease_when_label(lease)
            );
            println!("    cluster: {}", lease_cluster_label(lease));
            if let Some(kubeconfig_path) = lease.kubeconfig_path.as_deref() {
                println!("    config:  {kubeconfig_path}");
            }
        }
    }
    println!();

    println!("\x1b[1mPools\x1b[0m");
    if pool_details.is_empty() {
        println!("  No pools available");
        println!();
        return Ok(());
    }

    for (index, pool_detail) in pool_details.iter().enumerate() {
        if index > 0 {
            println!();
        }

        print_pool_block(&pool_detail.pool, "  ");
    }
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
            }),
            Err(_) => enriched.push(LeaseSummary {
                kubeconfig_path,
                ..lease
            }),
        }
    }

    enriched
}
