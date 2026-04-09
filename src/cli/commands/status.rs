use anyhow::Result;

use super::config::{AuthMode, CliConfig};
use super::{authed_client, get_auth_header, with_auth};

pub async fn status() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();

    // Fetch server status (unauthenticated — /v1/status supports OptionalAuth)
    let token = get_auth_header(endpoint, "GET", "/v1/status", b"")
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
    let version = server["version"].as_str().unwrap_or("?");

    // Auth summary
    let auth_summary = match config.auth {
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
            format!("ssh \x1b[2m{fp}\x1b[0m")
        }
        AuthMode::Oidc => "oidc".to_string(),
        AuthMode::Token => "token".to_string(),
        AuthMode::None => "none".to_string(),
    };

    // Header
    println!();
    println!("\x1b[1mkobe {version}\x1b[0m");
    println!("  \x1b[2m{endpoint}\x1b[0m");
    println!();

    // Auth
    println!("\x1b[1mAuth\x1b[0m");
    println!("  {auth_summary}");
    println!();

    // Fetch pools
    let pools_token = get_auth_header(endpoint, "GET", "/v1/pools", b"")
        .await
        .ok()
        .flatten();
    let pools: Vec<serde_json::Value> =
        match with_auth(client.get(format!("{endpoint}/v1/pools")), &pools_token)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
            _ => Vec::new(),
        };

    // Fetch leases
    let leases_token = get_auth_header(endpoint, "GET", "/v1/leases", b"")
        .await
        .ok()
        .flatten();
    let leases: Vec<serde_json::Value> =
        match with_auth(client.get(format!("{endpoint}/v1/leases")), &leases_token)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
            _ => Vec::new(),
        };

    // Pools with leases grouped underneath
    println!("\x1b[1mPools\x1b[0m");
    if pools.is_empty() {
        println!("  \x1b[2mNo pools available\x1b[0m");
    } else {
        for p in &pools {
            let name = p["name"].as_str().unwrap_or("?");
            let ready = p["ready"].as_u64().unwrap_or(0);
            let claimed = p["claimed"].as_u64().unwrap_or(0);
            let ready_color = if ready > 0 { "\x1b[32m" } else { "\x1b[33m" };
            let claimed_str = if claimed > 0 {
                format!("  \x1b[33mleased={claimed}\x1b[0m")
            } else {
                String::new()
            };
            println!("  {name}  {ready_color}ready={ready}\x1b[0m{claimed_str}");

            // Show leases for this pool
            let pool_leases: Vec<&serde_json::Value> = leases
                .iter()
                .filter(|l| l["profile"].as_str() == Some(name))
                .collect();
            for l in &pool_leases {
                let id = l["id"].as_str().unwrap_or("?");
                let cluster = l["cluster_name"].as_str().unwrap_or("-");
                let phase = l["phase"].as_str().unwrap_or("?");
                let expires = l["expires_at"]
                    .as_str()
                    .map(format_relative_time)
                    .unwrap_or_else(|| phase.to_string());
                println!("    \x1b[2m{id}\x1b[0m  {cluster}  \x1b[2m{expires}\x1b[0m");
            }
        }
    }
    println!();

    Ok(())
}

/// Format an ISO timestamp as a relative time string (e.g., "28m left").
fn format_relative_time(iso: &str) -> String {
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
