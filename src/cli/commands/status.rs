use anyhow::Result;

use super::config::CliConfig;
use super::{authed_client, get_auth_header, with_auth};

pub async fn status() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
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

    let body: serde_json::Value = response.json().await?;

    // Version
    let version = body["version"].as_str().unwrap_or("?");
    println!("Endpoint: {} (v{version})", endpoint);
    println!();

    // Auth methods
    if let Some(methods) = body["auth"]["methods"].as_array() {
        if methods.is_empty() {
            println!("Auth:     no methods configured");
        } else {
            println!("Auth methods:");
            for m in methods {
                let t = m["type"].as_str().unwrap_or("?");
                let desc = m["description"]
                    .as_str()
                    .or(m["issuer"].as_str())
                    .unwrap_or("");
                println!("  {t:<8} {desc}");
            }
        }
    }

    // Sessions
    if let Some(sessions) = body["auth"]["sessions"].as_array() {
        if !sessions.is_empty() {
            println!();
            println!("Sessions:");
            for s in sessions {
                let method = s["method"].as_str().unwrap_or("?");
                let identity = s["identity"].as_str().unwrap_or("?");
                let pools: Vec<&str> = s["pools"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let expires = s["expiresAt"].as_str().unwrap_or("no expiry");
                println!("  {method:<8} {identity:<40} pools={pools:?}  {expires}");
            }
        }
    } else {
        println!();
        println!("Not authenticated. Run: kobe login");
    }

    // Pools
    if let Some(pools) = body["pools"].as_array() {
        if !pools.is_empty() {
            println!();
            println!("Pools:");
            for p in pools {
                let name = p["name"].as_str().unwrap_or("?");
                let ready = p["ready"].as_u64().unwrap_or(0);
                let claimed = p["claimed"].as_u64().unwrap_or(0);
                let total = p["total"].as_u64().unwrap_or(0);
                println!("  {name:<20} ready={ready}  claimed={claimed}  total={total}");
            }
        }
    }

    Ok(())
}
