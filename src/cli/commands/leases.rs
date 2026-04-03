use anyhow::Result;

use super::config::CliConfig;
use super::{authed_client, get_auth_header, with_auth};

pub async fn leases() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
    let token = get_auth_header(endpoint).await?;

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
                let cluster = lease["clusterName"]
                    .as_str()
                    .or(lease["cluster_name"].as_str())
                    .unwrap_or("-");
                let phase = lease["phase"].as_str().unwrap_or("?");
                let expires = lease["expiresAt"].as_str().unwrap_or("-");
                println!("{id}  cluster={cluster}  phase={phase}  expires={expires}");
            }
        }
    }
    Ok(())
}
