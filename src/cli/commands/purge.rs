use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

use super::config::CliConfig;
use super::leases::{LeaseSummary, fetch_leases_path};
use super::state::{
    endpoint_kubeconfigs, forget_endpoint_kubeconfigs, local_kubeconfig_candidates,
    remove_kubeconfig,
};
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PurgeOutput {
    released_leases: Vec<String>,
    removed_kubeconfigs: Vec<String>,
}

pub async fn purge(
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
    yes: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let leases = fetch_leases_path(&config, "/v1/leases").await?;
    let active_leases: Vec<LeaseSummary> = leases.into_iter().filter(is_active_lease).collect();

    let tracked = endpoint_kubeconfigs(&config.endpoint)?;
    let local = local_kubeconfig_candidates()?;
    let removable_files = dedupe_paths(tracked.into_iter().chain(local));

    if active_leases.is_empty() && removable_files.is_empty() {
        match output {
            OutputFormat::Text => println!("Nothing to purge."),
            OutputFormat::Json => print_json(&PurgeOutput {
                released_leases: Vec::new(),
                removed_kubeconfigs: Vec::new(),
            })?,
        }
        return Ok(());
    }

    if output == OutputFormat::Text && !yes {
        confirm_purge(active_leases.len(), removable_files.len())?;
    }

    let endpoint = config.endpoint.as_str();
    let client = authed_client();
    let mut released = Vec::new();
    for lease in &active_leases {
        let path = format!("/v1/leases/{}", lease.id);
        let token = get_auth_header(&config, "DELETE", &path, b"").await?;
        let response = with_auth(client.delete(format!("{endpoint}{path}")), &token)
            .send()
            .await?;
        match response.status().as_u16() {
            200..=299 | 404 => {
                let _ = remove_kubeconfig(endpoint, &lease.id);
                released.push(lease.id.clone());
            }
            status => anyhow::bail!("Failed to purge lease {} (HTTP {status})", lease.id),
        }
    }

    forget_endpoint_kubeconfigs(endpoint)?;
    let mut removed_paths = Vec::new();
    for path in dedupe_paths(removable_files) {
        if path.exists() {
            std::fs::remove_file(&path)?;
            removed_paths.push(path);
        }
    }

    match output {
        OutputFormat::Text => {
            if !released.is_empty() {
                println!("Released {} lease(s):", released.len());
                for lease in &released {
                    println!("  {lease}");
                }
            }
            if !removed_paths.is_empty() {
                println!("Removed {} kubeconfig file(s):", removed_paths.len());
                for path in &removed_paths {
                    println!("  {}", path.display());
                }
            }
        }
        OutputFormat::Json => print_json(&PurgeOutput {
            released_leases: released,
            removed_kubeconfigs: removed_paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        })?,
    }

    Ok(())
}

fn is_active_lease(lease: &LeaseSummary) -> bool {
    !lease.phase.eq_ignore_ascii_case("released")
        && !lease.phase.eq_ignore_ascii_case("expired")
        && !lease.phase.eq_ignore_ascii_case("recycling")
}

fn dedupe_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    deduped
}

fn confirm_purge(active_leases: usize, kubeconfigs: usize) -> Result<()> {
    eprintln!(
        "Purge {} active lease(s) and remove {} local kubeconfig file(s)? [y/N]",
        active_leases, kubeconfigs
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        return Ok(());
    }
    anyhow::bail!("Purge cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_lease_filter_rejects_terminal_phases() {
        let base = LeaseSummary {
            id: "lease-1".to_string(),
            phase: "Bound".to_string(),
            profile: "ci".to_string(),
            cluster_name: None,
            expires_at: None,
            queue_position: 0,
            requester: None,
            kubeconfig_path: None,
        };

        assert!(is_active_lease(&base));
        assert!(!is_active_lease(&LeaseSummary {
            phase: "Released".to_string(),
            ..base.clone()
        }));
        assert!(!is_active_lease(&LeaseSummary {
            phase: "Expired".to_string(),
            ..base.clone()
        }));
        assert!(!is_active_lease(&LeaseSummary {
            phase: "Recycling".to_string(),
            ..base
        }));
    }
}
