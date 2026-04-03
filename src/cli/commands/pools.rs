use anyhow::Result;

use super::config::CliConfig;

pub async fn pools() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
    let token = crate::commands::get_token(endpoint).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{endpoint}/v1/pools"))
        .bearer_auth(&token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to list pools (HTTP {})", response.status());
    }

    let body: serde_json::Value = response.json().await?;
    if let Some(items) = body.as_array() {
        if items.is_empty() {
            println!("No pools available.");
        } else {
            for pool in items {
                let name = pool["metadata"]["name"].as_str().unwrap_or("?");
                let ready = pool["status"]["ready"].as_u64().unwrap_or(0);
                let claimed = pool["status"]["claimed"].as_u64().unwrap_or(0);
                println!("{name}  ready={ready}  claimed={claimed}");
            }
        }
    }
    Ok(())
}
