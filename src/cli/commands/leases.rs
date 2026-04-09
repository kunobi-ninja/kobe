use anyhow::Result;

use super::config::CliConfig;
use super::{authed_client, get_auth_header, with_auth};

pub async fn leases() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
    let token = get_auth_header(endpoint, "GET", "/v1/leases", b"").await?;

    let client = authed_client();
    let response = with_auth(client.get(format!("{endpoint}/v1/leases")), &token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to list leases (HTTP {})", response.status());
    }

    let body: serde_json::Value = response.json().await?;
    if let Some(items) = body.as_array() {
        if items.is_empty() {
            println!("No active leases.");
        } else {
            for lease in items {
                let id = lease["id"].as_str().unwrap_or("?");
                let cluster = lease["cluster_name"].as_str().unwrap_or("-");
                let phase = lease["phase"].as_str().unwrap_or("?");
                let expires = lease["expires_at"]
                    .as_str()
                    .map(format_relative_time)
                    .unwrap_or_else(|| phase.to_string());
                println!("{id}  {cluster}  {expires}");
            }
        }
    }
    Ok(())
}

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
