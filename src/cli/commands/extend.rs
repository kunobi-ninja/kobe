//! `kobe extend` — extend the TTL of an active lease.
//!
//! Thin client over `PATCH /v1/leases/{id}`. The server adds the requested
//! duration to the current expiry, subject to the policy's `max_extensions`
//! count and the absolute `bound_at + max_ttl` ceiling.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::CliConfig;
use super::leases::format_relative_time;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

/// Request body for the extend endpoint. The server expects snake_case
/// `extend_ttl` (the handler struct has no rename).
#[derive(Serialize)]
struct ExtendRequest<'a> {
    extend_ttl: &'a str,
}

#[derive(Deserialize)]
struct ExtendResponse {
    expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtendOutput<'a> {
    lease_id: &'a str,
    expires_at: &'a str,
}

pub async fn extend(
    target: Option<&str>,
    by: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    // Mutating command: never act on an arbitrary lease when the choice is
    // ambiguous and we cannot prompt.
    let lease_id = resolve_lease_id(&config, target, output, OnAmbiguous::Reject).await?;

    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/leases/{lease_id}");
    let body = serde_json::to_vec(&ExtendRequest { extend_ttl: by })?;
    // Body signing is not yet supported server-side; sign with an empty body
    // for now (matches `lease_create`).
    let token = get_auth_header(&config, "PATCH", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(client.patch(format!("{endpoint}{path}")), &token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_string))
            .unwrap_or(text);
        anyhow::bail!("Failed to extend lease {lease_id} (HTTP {status}): {msg}");
    }

    let extended: ExtendResponse = response.json().await?;
    match output {
        OutputFormat::Text => println!(
            "Extended lease {lease_id} — expires {} ({})",
            extended.expires_at,
            format_relative_time(&extended.expires_at),
        ),
        OutputFormat::Json => print_json(&ExtendOutput {
            lease_id: &lease_id,
            expires_at: &extended.expires_at,
        })?,
    }

    Ok(())
}
