use anyhow::Result;
use serde::Serialize;

use super::config::{CliConfig, ResolvedConfig};
use super::extend::is_sandbox_lease;
use super::select::{OnAmbiguous, resolve_lease_id};
use super::state::remove_kubeconfig;
use super::{OutputFormat, print_json, send_lease_request};

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
    let sandbox = is_sandbox_lease(lease_id);
    let response = send_lease_request(config, reqwest::Method::DELETE, lease_id, None).await?;
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
    // Generated ids identify their kind and remain usable after the lease has
    // disappeared from the active inventory, so keep sending those verbatim.
    // Every other explicit value is a selector: resolve aliases and unique
    // pool names across all lease kinds before choosing the DELETE endpoint.
    // This keeps `kobe release dev` symmetric with `exec dev` and `extend dev`
    // without giving up idempotent release of an already-expired concrete id.
    let selected_lease = match lease_id {
        Some(id) if is_self_identifying_lease_id(id) => id.to_string(),
        Some(selector) => {
            resolve_lease_id(&config, Some(selector), output, OnAmbiguous::Reject).await?
        }
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

fn is_self_identifying_lease_id(value: &str) -> bool {
    value.starts_with("lease-") || is_sandbox_lease(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answer each connection with the next canned status and record the
    /// request line it answered.
    fn status_server(
        statuses: Vec<&'static str>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for status in statuses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                lines.push(line.trim().to_string());
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                }
                let body = r#"{"error":"Lease not found","reason":"not_found"}"#;
                write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            lines
        });
        (format!("http://{address}"), handle)
    }

    fn test_config(endpoint: String) -> ResolvedConfig {
        ResolvedConfig {
            target: None,
            endpoint,
            auth: crate::commands::config::AuthMode::None,
            token: None,
            ssh_fingerprint: None,
            default_pool: None,
        }
    }

    #[tokio::test]
    async fn a_sandbox_release_uses_the_canonical_path() {
        let (endpoint, server) = status_server(vec!["204 No Content"]);
        let outcome = release_lease(&test_config(endpoint), "sandbox-abc")
            .await
            .unwrap();
        assert_eq!(outcome, ReleaseOutcome::Released);
        assert_eq!(
            server.join().unwrap(),
            vec!["DELETE /v1/leases/sandbox-abc HTTP/1.1"]
        );
    }

    /// A server before v0.41.0 answers `/v1/leases/sandbox-*` with 404. The
    /// release falls back to the old path instead of reporting the lease gone.
    #[tokio::test]
    async fn a_sandbox_release_falls_back_for_an_older_server() {
        let (endpoint, server) = status_server(vec!["404 Not Found", "204 No Content"]);
        let outcome = release_lease(&test_config(endpoint), "sandbox-abc")
            .await
            .unwrap();
        assert_eq!(outcome, ReleaseOutcome::Released);
        assert_eq!(
            server.join().unwrap(),
            vec![
                "DELETE /v1/leases/sandbox-abc HTTP/1.1",
                "DELETE /v1/sandbox-leases/sandbox-abc HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn a_cluster_404_is_final() {
        let (endpoint, server) = status_server(vec!["404 Not Found"]);
        let outcome = release_lease(&test_config(endpoint), "lease-abc")
            .await
            .unwrap();
        assert_eq!(outcome, ReleaseOutcome::NotFound);
        assert_eq!(server.join().unwrap().len(), 1);
    }
}
