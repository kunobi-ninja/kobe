//! `kobe extend` — extend the TTL of an active lease.
//!
//! Thin client over `PATCH /v1/leases/{id}` for cluster leases and
//! `PATCH /v1/sandbox-leases/{id}` for Sandbox leases. Both add the requested
//! duration to the current expiry, subject to the policy's `max_extensions`
//! count and an absolute ceiling — `bound_at + max_ttl` for a cluster,
//! `ready_at + max_ttl` for a Sandbox, whose runtime starts at readiness.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::{CliConfig, ResolvedConfig};
use super::leases::format_relative_time;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

/// Sandbox lease ids are self-identifying, so the client routes to the right
/// endpoint without a lookup. Mirrors the server's `LEASE_ID_PREFIX`.
const SANDBOX_LEASE_PREFIX: &str = "sandbox-";

pub(crate) fn is_sandbox_lease(id: &str) -> bool {
    id.starts_with(SANDBOX_LEASE_PREFIX)
}

/// Request body for both extend endpoints. Each accepts the other's spelling
/// as an alias, so one body works for either kind.
#[derive(Serialize)]
struct ExtendRequest<'a> {
    extend_ttl: &'a str,
}

/// The cluster endpoint answers in snake_case and the Sandbox endpoint in the
/// camelCase its API uses throughout; accept both rather than making callers
/// care which kind they extended.
#[derive(Deserialize)]
struct ExtendResponse {
    #[serde(alias = "expiresAt")]
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
    let path = if is_sandbox_lease(lease_id) {
        format!("/v1/sandbox-leases/{lease_id}")
    } else {
        format!("/v1/leases/{lease_id}")
    };
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
        let parsed = serde_json::from_str::<serde_json::Value>(&text).ok();
        let msg = parsed
            .as_ref()
            .and_then(|value| value["error"].as_str().map(str::to_string))
            .unwrap_or(text.clone());
        // The server's bounded reason (`conflict_retryable`,
        // `extension_budget_exhausted`, …) tells a script whether retrying
        // could ever succeed, without parsing the human message.
        let reason = parsed
            .as_ref()
            .and_then(|value| value["reason"].as_str())
            .map(|reason| format!(" [{reason}]"))
            .unwrap_or_default();
        anyhow::bail!("Failed to extend lease {lease_id} (HTTP {status}){reason}: {msg}");
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
    //
    // An explicit Sandbox lease id resolves itself. Sending it through the
    // cluster resolver would fail with "no active lease matching", because
    // that resolver only lists `/v1/leases`. Sandbox alias and pool
    // resolution, and the interactive picker, still cover cluster leases
    // only — they need a unified listing, which belongs with `kobe status`.
    let lease_id = match target {
        Some(target) if is_sandbox_lease(target) => target.to_string(),
        target => resolve_lease_id(&config, target, output, OnAmbiguous::Reject).await?,
    };

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
