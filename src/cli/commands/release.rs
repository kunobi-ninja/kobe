use anyhow::Result;
use serde::Serialize;

use super::config::CliConfig;
use super::leases::{
    LeaseSummary, fetch_leases_path, lease_cluster_label, lease_phase_label, lease_when_label,
};
use super::picker::{PickerItem, run_picker};
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
    let selected_lease = match lease_id {
        Some(id) => id.to_string(),
        None => select_lease_for_release(&config, output).await?,
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

async fn select_lease_for_release(
    config: &super::config::ResolvedConfig,
    output: OutputFormat,
) -> Result<String> {
    let leases = fetch_leases_path(config, "/v1/leases").await?;
    let active_leases: Vec<LeaseSummary> = leases
        .into_iter()
        .filter(|lease| {
            !lease.phase.eq_ignore_ascii_case("released")
                && !lease.phase.eq_ignore_ascii_case("expired")
                && !lease.phase.eq_ignore_ascii_case("recycling")
        })
        .collect();

    if active_leases.is_empty() {
        anyhow::bail!("No releasable leases found");
    }

    if output == OutputFormat::Json {
        return Ok(active_leases[0].id.clone());
    }

    let items: Vec<PickerItem> = active_leases
        .iter()
        .map(|lease| PickerItem {
            primary: format!(
                "{}  {}  {}",
                lease.id,
                lease.profile,
                lease_when_label(lease)
            ),
            secondary: format!(
                "phase: {}   cluster: {}",
                lease_phase_label(lease),
                lease_cluster_label(lease)
            ),
        })
        .collect();

    let idx = run_picker(
        "Release Lease",
        "Use ↑/↓ and Enter. Press q or Esc to cancel.",
        &items,
    )?;
    Ok(active_leases[idx].id.clone())
}
