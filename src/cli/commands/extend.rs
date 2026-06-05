//! `kobe extend` — extend the TTL of an active lease.
//!
//! Thin client over `PATCH /v1/leases/{id}`. The server adds the requested
//! duration to the current expiry, subject to the policy's `max_extensions`
//! count and the absolute `bound_at + max_ttl` ceiling.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::{CliConfig, ResolvedConfig};
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

/// Extend a specific lease by `by` over `PATCH /v1/leases/{id}`, returning the
/// new `expires_at`. Shared by the `extend` command and by the #107 P3
/// idempotent-renew (`--ensure`) and keepalive paths.
pub(crate) async fn extend_lease(
    config: &ResolvedConfig,
    lease_id: &str,
    by: &str,
) -> Result<String> {
    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/leases/{lease_id}");
    let body = serde_json::to_vec(&ExtendRequest { extend_ttl: by })?;
    // Body signing is not yet supported server-side; sign with an empty body
    // for now (matches `lease_create`).
    let token = get_auth_header(config, "PATCH", &path, b"").await?;

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
    Ok(extended.expires_at)
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

    let expires_at = extend_lease(&config, &lease_id, by).await?;
    match output {
        OutputFormat::Text => println!(
            "Extended lease {lease_id} — expires {} ({})",
            expires_at,
            format_relative_time(&expires_at),
        ),
        OutputFormat::Json => print_json(&ExtendOutput {
            lease_id: &lease_id,
            expires_at: &expires_at,
        })?,
    }

    Ok(())
}
