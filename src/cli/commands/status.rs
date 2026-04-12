use anyhow::Result;

use super::config::{AuthMode, CliConfig};
use super::leases::{
    fetch_leases_path, lease_cluster_label, lease_phase_label, lease_when_label, shorten_requester,
};
use super::pools::{fetch_pools_for_config, print_pool_block};
use super::{authed_client, cli_version, get_auth_header, with_auth};

pub async fn status(context_override: Option<&str>, endpoint_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
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

    let pools = fetch_pools_for_config(&config).await.unwrap_or_default();
    let my_identity = config.ssh_fingerprint.clone();

    println!();
    println!("\x1b[1mkobe\x1b[0m");
    println!("  cli version: {}", cli_version());
    if let Some(context) = &config.context {
        println!("  context: {context}");
    }
    println!("  endpoint: {endpoint}");
    println!("  endpoint version: {endpoint_version}");
    println!();

    println!("\x1b[1mAuth\x1b[0m");
    println!("  {auth_summary}");
    println!();

    println!("\x1b[1mPools\x1b[0m");
    if pools.is_empty() {
        println!("  No pools available");
        println!();
        return Ok(());
    }

    for (index, pool) in pools.iter().enumerate() {
        if index > 0 {
            println!();
        }

        print_pool_block(pool, "  ");

        let pool_path = format!("/v1/pools/{}/leases", pool.name);
        let pool_leases = fetch_leases_path(&config, &pool_path)
            .await
            .unwrap_or_default();

        if pool_leases.is_empty() {
            println!("    leases:   none");
            continue;
        }

        println!("    leases:");
        for lease in &pool_leases {
            let owner = match lease.requester.as_deref() {
                Some(requester)
                    if my_identity
                        .as_deref()
                        .map(|identity| requester.contains(identity))
                        .unwrap_or(false) =>
                {
                    "(you)".to_string()
                }
                Some(requester) => shorten_requester(requester),
                None => "-".to_string(),
            };

            println!(
                "      {:<24}  {:<8}  {:<28}  {:<12}  {}",
                lease.id,
                lease_phase_label(lease),
                lease_cluster_label(lease),
                lease_when_label(lease),
                owner
            );
        }
    }
    println!();

    Ok(())
}
