use anyhow::Result;
use serde::Serialize;

use super::config::{CliConfig, ResolvedConfig};
use super::extend::is_sandbox_lease;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::state::remove_kubeconfig;
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseOutcome {
    Released,
    NotFound,
}

/// Release a lease by id over `DELETE /v1/leases/{id}`, treating 404 as success
/// (already gone). Also drops the local kubeconfig record. Used by `with-lease`
/// (#107 P3) for guaranteed cleanup on exit.
pub(crate) async fn release_lease(
    config: &ResolvedConfig,
    lease_id: &str,
) -> Result<ReleaseOutcome> {
    let endpoint = config.endpoint.as_str();
    let sandbox = is_sandbox_lease(lease_id);
    let path = if sandbox {
        format!("/v1/sandbox-leases/{lease_id}")
    } else {
        format!("/v1/leases/{lease_id}")
    };
    let token = get_auth_header(config, "DELETE", &path, b"").await?;
    let client = authed_client();
    let response = with_auth(client.delete(format!("{endpoint}{path}")), &token)
        .send()
        .await?;
    let status = response.status();
    let outcome = if status.is_success() {
        ReleaseOutcome::Released
    } else if status.as_u16() == 404 {
        ReleaseOutcome::NotFound
    } else {
        anyhow::bail!("Failed to release lease {lease_id} (HTTP {status})");
    };
    if !sandbox {
        let _ = remove_kubeconfig(&config.endpoint, lease_id);
    }
    Ok(outcome)
}

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
    let outcome = release_lease(&config, &selected_lease).await?;
    match (outcome, output) {
        (ReleaseOutcome::Released, OutputFormat::Text) => {
            println!("Released lease {}", selected_lease)
        }
        (ReleaseOutcome::NotFound, OutputFormat::Text) => println!(
            "Lease {} not found (already released or expired)",
            selected_lease
        ),
        (outcome, OutputFormat::Json) => print_json(&ReleaseOutput {
            lease_id: &selected_lease,
            status: match outcome {
                ReleaseOutcome::Released => "released",
                ReleaseOutcome::NotFound => "not_found",
            },
        })?,
    }

    Ok(())
}
