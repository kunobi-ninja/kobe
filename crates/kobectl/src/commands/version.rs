use anyhow::Result;
use serde::Serialize;

use super::config::{CliConfig, ResolvedConfig};
use super::{OutputFormat, authed_client, cli_version, print_json};

/// Compare dotted versions, ignoring a leading `v` and any `+metadata` /
/// `-prerelease` suffix. Returns true when `cli` is strictly older than
/// `endpoint`. Unparseable values never warn.
pub(crate) fn cli_is_behind_endpoint(cli: &str, endpoint: &str) -> bool {
    match (parse_dotted_version(cli), parse_dotted_version(endpoint)) {
        (Some(cli), Some(endpoint)) => cli < endpoint,
        _ => false,
    }
}

fn parse_dotted_version(raw: &str) -> Option<(u64, u64, u64)> {
    let core = raw
        .trim()
        .trim_start_matches(['v', 'V'])
        .split(['-', '+'])
        .next()
        .unwrap_or("");
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// Warn on stderr when this binary is older than the operator it talks to.
pub(crate) fn warn_if_cli_behind_endpoint(endpoint_version: &str) {
    let cli = cli_version();
    if cli_is_behind_endpoint(cli, endpoint_version) {
        eprintln!("warning: CLI {cli} is older than endpoint {endpoint_version}. Upgrade the CLI.");
    }
}

pub(crate) async fn fetch_endpoint_version(config: &ResolvedConfig) -> Option<String> {
    let response = authed_client()
        .get(format!("{}/v1/status", config.endpoint))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body: serde_json::Value = response.json().await.ok()?;
    body["version"].as_str().map(str::to_string)
}

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
            warn_if_cli_behind_endpoint(&endpoint_version);
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

#[cfg(test)]
mod tests {
    use super::cli_is_behind_endpoint;

    #[test]
    fn older_cli_is_behind() {
        assert!(cli_is_behind_endpoint("0.40.0", "v0.40.2"));
        assert!(cli_is_behind_endpoint("0.39.2", "0.40.0"));
        assert!(!cli_is_behind_endpoint("0.40.2", "v0.40.2"));
        assert!(!cli_is_behind_endpoint("0.41.0", "0.40.2"));
        assert!(!cli_is_behind_endpoint("dev", "v0.40.2"));
        assert!(!cli_is_behind_endpoint("0.40.0", "unavailable"));
    }
}
