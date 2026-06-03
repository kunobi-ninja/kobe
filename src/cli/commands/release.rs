use anyhow::Result;
use serde::Serialize;

use super::config::CliConfig;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::state::remove_kubeconfig;
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseOutput<'a> {
    lease_id: &'a str,
    status: &'a str,
}

pub async fn release(
    lease_id: Option<&str>,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    // An explicit id is used verbatim (the server handles 404 gracefully, so
    // releasing a just-expired id still works). Otherwise resolve against the
    // active leases, falling back to the first one in non-interactive mode to
    // preserve the prior behavior.
    let selected_lease = match lease_id {
        Some(id) => id.to_string(),
        None => resolve_lease_id(&config, None, output, OnAmbiguous::FirstActive).await?,
    };
    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/leases/{selected_lease}");
    let token = get_auth_header(&config, "DELETE", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(
        client.delete(format!("{endpoint}/v1/leases/{selected_lease}")),
        &token,
    )
    .send()
    .await?;

    if response.status().is_success() {
        if let Err(err) = remove_kubeconfig(&config.endpoint, &selected_lease) {
            eprintln!(
                "Warning: failed to remove local kubeconfig for {}: {err}",
                selected_lease
            );
        }
        match output {
            OutputFormat::Text => println!("Released lease {}", selected_lease),
            OutputFormat::Json => print_json(&ReleaseOutput {
                lease_id: &selected_lease,
                status: "released",
            })?,
        }
    } else if response.status().as_u16() == 404 {
        if let Err(err) = remove_kubeconfig(&config.endpoint, &selected_lease) {
            eprintln!(
                "Warning: failed to remove local kubeconfig for {}: {err}",
                selected_lease
            );
        }
        match output {
            OutputFormat::Text => {
                println!(
                    "Lease {} not found (already released or expired)",
                    selected_lease
                )
            }
            OutputFormat::Json => print_json(&ReleaseOutput {
                lease_id: &selected_lease,
                status: "not_found",
            })?,
        }
    } else {
        anyhow::bail!("Failed to release lease (HTTP {})", response.status());
    }

    Ok(())
}
