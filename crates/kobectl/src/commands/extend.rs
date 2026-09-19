//! `kobe extend` — extend the TTL of an active lease.
//!
//! Thin client over `PATCH /v1/leases/{id}`, which serves both lease kinds
//! (see [`super::lease_request_paths`] for servers before v0.41.0). Both kinds
//! add the requested duration to the current expiry, subject to the policy's `max_extensions`
//! count and an absolute ceiling — `bound_at + max_ttl` for a cluster,
//! `ready_at + max_ttl` for a Sandbox, whose runtime starts at readiness.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::config::{CliConfig, ResolvedConfig};
use super::leases::format_relative_time;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::{OutputFormat, print_json, send_lease_request};

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
///
/// Both spellings are separate optional fields rather than a serde alias: an
/// alias treats them as one field, so a body carrying both fails as a
/// duplicate field, and the extension the server already applied looks failed.
#[derive(Deserialize)]
struct ExtendResponse {
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default, rename = "expiresAt")]
    expires_at_camel: Option<String>,
    /// Sandbox only: running executions whose deadline the extension does not
    /// reach. Absent from cluster leases and older servers.
    #[serde(default, alias = "runningExecutions")]
    running_executions: Vec<RunningExecution>,
}

impl ExtendResponse {
    fn expires_at(&self) -> Result<String> {
        self.expires_at
            .clone()
            .or_else(|| self.expires_at_camel.clone())
            .ok_or_else(|| anyhow::anyhow!("extend response has no expiry"))
    }
}

/// A running execution that still stops before the lease's new expiry.
#[derive(Deserialize, Serialize)]
struct RunningExecution {
    id: String,
    deadline: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtendOutput<'a> {
    lease_id: &'a str,
    expires_at: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    running_executions: &'a [RunningExecution],
}

/// Extend a specific lease by `by` over `PATCH /v1/leases/{id}`, returning the
/// new `expires_at`. Shared by the `extend` command and by the #107 P3
/// idempotent-renew (`--ensure`) and keepalive paths.
pub(crate) async fn extend_lease(
    config: &ResolvedConfig,
    lease_id: &str,
    by: &str,
) -> Result<String> {
    extend_lease_response(config, lease_id, by)
        .await?
        .expires_at()
}

async fn extend_lease_response(
    config: &ResolvedConfig,
    lease_id: &str,
    by: &str,
) -> Result<ExtendResponse> {
    let body = serde_json::to_vec(&ExtendRequest { extend_ttl: by })?;
    let response =
        send_lease_request(config, reqwest::Method::PATCH, lease_id, Some(&body)).await?;

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

    Ok(response.json().await?)
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
    // An explicit Sandbox lease id resolves itself even after it disappears
    // from the active inventory. Every other value goes through the unified
    // lease selector, which matches active ids, aliases and unique pool names
    // across both resource kinds.
    let lease_id = match target {
        Some(target) if is_sandbox_lease(target) => target.to_string(),
        target => resolve_lease_id(&config, target, output, OnAmbiguous::Reject).await?,
    };

    let extended = extend_lease_response(&config, &lease_id, by).await?;
    let expires_at = extended.expires_at()?;
    match output {
        OutputFormat::Text => {
            println!(
                "Extended lease {lease_id} — expires {} ({})",
                expires_at,
                format_relative_time(&expires_at),
            );
            // A command's deadline is fixed when it starts. Without this line,
            // extending looks like it bought the running command more time.
            for execution in &extended.running_executions {
                eprintln!(
                    "kobe: running execution {} still stops at {}; extending the lease does not move it",
                    execution.id,
                    super::sandbox::describe_deadline(&execution.deadline),
                );
            }
        }
        OutputFormat::Json => print_json(&ExtendOutput {
            lease_id: &lease_id,
            expires_at: &expires_at,
            running_executions: &extended.running_executions,
        })?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    /// A body carrying both spellings must still parse. With a serde alias it
    /// failed as a duplicate field, so a successful extension looked failed.
    #[test]
    fn extend_response_accepts_either_or_both_expiry_spellings() {
        for body in [
            r#"{"expires_at":"2026-09-18T23:30:00Z"}"#,
            r#"{"expiresAt":"2026-09-18T23:30:00Z"}"#,
            r#"{"expires_at":"2026-09-18T23:30:00Z","expiresAt":"2026-09-18T23:30:00Z"}"#,
        ] {
            let parsed: ExtendResponse = serde_json::from_str(body).unwrap();
            assert_eq!(parsed.expires_at().unwrap(), "2026-09-18T23:30:00Z");
        }
        let empty: ExtendResponse = serde_json::from_str("{}").unwrap();
        assert!(empty.expires_at().is_err());
    }

    use super::*;

    /// The Sandbox endpoint names running executions the extension does not
    /// reach; the cluster endpoint and older servers omit the field.
    #[test]
    fn running_executions_are_read_when_present_and_empty_otherwise() {
        let sandbox: ExtendResponse = serde_json::from_value(serde_json::json!({
            "expiresAt": "2026-09-18T23:30:00Z",
            "extensionsCount": 1,
            "maxExtensions": 3,
            "runningExecutions": [{ "id": "sbxe-1", "deadline": "2026-09-18T21:30:00Z" }]
        }))
        .unwrap();
        assert_eq!(sandbox.running_executions.len(), 1);
        assert_eq!(sandbox.running_executions[0].id, "sbxe-1");

        let cluster: ExtendResponse =
            serde_json::from_value(serde_json::json!({ "expires_at": "2026-09-18T23:30:00Z" }))
                .unwrap();
        assert!(cluster.running_executions.is_empty());
    }
}
