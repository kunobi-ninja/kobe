use anyhow::Result;
use serde::Serialize;

use super::config::CliConfig;
use super::{OutputFormat, authed_client, cli_version, print_json};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionOutput {
    cli_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    endpoint: String,
    endpoint_version: String,
}

pub async fn version(
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
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

    match output {
        OutputFormat::Text => {
            println!("cli version: {}", cli_version());
            if let Some(target) = &config.target {
                println!("target: {target}");
            }
            println!("endpoint: {endpoint}");
            println!("endpoint version: {endpoint_version}");
        }
        OutputFormat::Json => print_json(&VersionOutput {
            cli_version: cli_version().to_string(),
            target: config.target.clone(),
            endpoint: endpoint.to_string(),
            endpoint_version,
        })?,
    }

    Ok(())
}
