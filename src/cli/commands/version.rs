use anyhow::Result;

use super::config::CliConfig;
use super::{authed_client, cli_version};

pub async fn version(
    context_override: Option<&str>,
    endpoint_override: Option<&str>,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    let client = authed_client();

    let endpoint_version = match client.get(format!("{endpoint}/v1/status")).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            body["version"].as_str().unwrap_or("?").to_string()
        }
        Ok(resp) => format!("unavailable (HTTP {})", resp.status()),
        Err(e) => format!("unavailable ({e})"),
    };

    println!("cli version: {}", cli_version());
    if let Some(context) = &config.context {
        println!("context: {context}");
    }
    println!("endpoint: {endpoint}");
    println!("endpoint version: {endpoint_version}");

    Ok(())
}
