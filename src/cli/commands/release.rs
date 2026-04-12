use anyhow::Result;
use serde::Serialize;

use super::config::CliConfig;
use super::state::forget_kubeconfig;
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseOutput<'a> {
    lease_id: &'a str,
    status: &'a str,
}

pub async fn release(
    lease_id: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/leases/{lease_id}");
    let token = get_auth_header(&config, "DELETE", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(
        client.delete(format!("{endpoint}/v1/leases/{lease_id}")),
        &token,
    )
    .send()
    .await?;

    if response.status().is_success() {
        if let Err(err) = forget_kubeconfig(&config.endpoint, lease_id) {
            eprintln!("Warning: failed to forget local kubeconfig path for {lease_id}: {err}");
        }
        match output {
            OutputFormat::Text => println!("Released lease {lease_id}"),
            OutputFormat::Json => print_json(&ReleaseOutput {
                lease_id,
                status: "released",
            })?,
        }
    } else if response.status().as_u16() == 404 {
        if let Err(err) = forget_kubeconfig(&config.endpoint, lease_id) {
            eprintln!("Warning: failed to forget local kubeconfig path for {lease_id}: {err}");
        }
        match output {
            OutputFormat::Text => {
                println!("Lease {lease_id} not found (already released or expired)")
            }
            OutputFormat::Json => print_json(&ReleaseOutput {
                lease_id,
                status: "not_found",
            })?,
        }
    } else {
        anyhow::bail!("Failed to release lease (HTTP {})", response.status());
    }

    Ok(())
}
