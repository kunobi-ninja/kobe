use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

use super::config::CliConfig;
use super::leases::{LeaseSummary, fetch_leases_path};
use super::state::{
    endpoint_kubeconfigs, find_orphan_kubeconfigs, forget_endpoint_kubeconfigs, forget_kubeconfig,
    local_kubeconfig_candidates, remove_kubeconfig,
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
    orphans_only: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let leases = fetch_leases_path(&config, "/v1/leases").await?;
    let active_leases: Vec<LeaseSummary> = leases
        .iter()
        .filter(|l| is_active_lease(l))
        .cloned()
        .collect();

    if orphans_only {
        // Use the FULL lease list (not just active) so a Recycling lease —
        // which still has a live cluster behind it server-side — does not
        // count as an orphan. See `live_lease_ids` for the exact filter.
        return purge_orphans_only(&config.endpoint, &leases, output, yes).await;
    }

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

/// Remove only kubeconfigs whose lease no longer exists server-side. Active
/// leases are left untouched (no DELETE calls). Conservative: only acts on
/// state-tracked entries — freestanding ~/.kube/kobe-*.yaml files we never
/// recorded are not assumed to be orphans.
async fn purge_orphans_only(
    endpoint: &str,
    all_leases: &[LeaseSummary],
    output: OutputFormat,
    yes: bool,
) -> Result<()> {
    let live_ids = live_lease_ids(all_leases);
    let orphans = find_orphan_kubeconfigs(endpoint, &live_ids)?;

    if orphans.is_empty() {
        match output {
            OutputFormat::Text => println!("No orphan kubeconfigs found."),
            OutputFormat::Json => print_json(&PurgeOutput {
                released_leases: Vec::new(),
                removed_kubeconfigs: Vec::new(),
            })?,
        }
        return Ok(());
    }

    if output == OutputFormat::Text && !yes {
        confirm_orphans(orphans.len())?;
    }

    // Per-orphan ordering: remove the file first, then drop the tracking
    // entry only on success. The previous ordering (forget then remove)
    // turned a single I/O error into a permanent silent leak — the state
    // entry was gone so subsequent runs would not re-detect the file.
    // Errors are collected and reported at the end so one bad file does
    // not abort the whole batch.
    let mut removed_paths = Vec::new();
    let mut failures: Vec<(std::path::PathBuf, std::io::Error)> = Vec::new();
    for orphan in orphans {
        match std::fs::remove_file(&orphan.path) {
            Ok(()) => {
                let _ = forget_kubeconfig(endpoint, &orphan.lease_id);
                removed_paths.push(orphan.path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // File vanished between detection and removal — clean up
                // the dangling state entry so we don't keep flagging it.
                let _ = forget_kubeconfig(endpoint, &orphan.lease_id);
            }
            Err(err) => {
                failures.push((orphan.path, err));
            }
        }
    }

    match output {
        OutputFormat::Text => {
            println!("Removed {} orphan kubeconfig file(s):", removed_paths.len());
            for path in &removed_paths {
                println!("  {}", path.display());
            }
            if !failures.is_empty() {
                eprintln!("Failed to remove {} file(s):", failures.len());
                for (path, err) in &failures {
                    eprintln!("  {}: {err}", path.display());
                }
            }
        }
        OutputFormat::Json => print_json(&PurgeOutput {
            released_leases: Vec::new(),
            removed_kubeconfigs: removed_paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        })?,
    }

    if !failures.is_empty() {
        anyhow::bail!(
            "Failed to remove {} orphan kubeconfig file(s)",
            failures.len()
        );
    }

    Ok(())
}

fn confirm_orphans(count: usize) -> Result<()> {
    eprintln!("Remove {count} orphan kubeconfig file(s)? [y/N]");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        return Ok(());
    }
    anyhow::bail!("Purge cancelled")
}

fn is_active_lease(lease: &LeaseSummary) -> bool {
    !lease.phase.eq_ignore_ascii_case("released")
        && !lease.phase.eq_ignore_ascii_case("expired")
        && !lease.phase.eq_ignore_ascii_case("recycling")
}

/// Lease IDs whose cluster is still considered to exist server-side.
///
/// Used for orphan detection. Includes everything except terminal phases
/// (`Released`, `Expired`). Critically includes `Recycling`: a lease in
/// that phase is mid-teardown but the kubeconfig may still authenticate
/// against a live cluster, so deleting the local file would race the
/// server-side cleanup.
pub(crate) fn live_lease_ids(leases: &[LeaseSummary]) -> BTreeSet<String> {
    leases
        .iter()
        .filter(|l| {
            !l.phase.eq_ignore_ascii_case("released") && !l.phase.eq_ignore_ascii_case("expired")
        })
        .map(|l| l.id.clone())
        .collect()
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

    #[test]
    fn live_lease_ids_treats_recycling_as_live() {
        // Recycling leases must be considered live for orphan detection,
        // otherwise we delete a kubeconfig whose cluster is still mid-teardown
        // server-side (race window can authenticate against a live API).
        let base = LeaseSummary {
            id: String::new(),
            phase: String::new(),
            profile: "ci".to_string(),
            cluster_name: None,
            expires_at: None,
            queue_position: 0,
            requester: None,
            kubeconfig_path: None,
        };
        let leases = vec![
            LeaseSummary {
                id: "bound".to_string(),
                phase: "Bound".to_string(),
                ..base.clone()
            },
            LeaseSummary {
                id: "pending".to_string(),
                phase: "Pending".to_string(),
                ..base.clone()
            },
            LeaseSummary {
                id: "recycling".to_string(),
                phase: "Recycling".to_string(),
                ..base.clone()
            },
            LeaseSummary {
                id: "released".to_string(),
                phase: "Released".to_string(),
                ..base.clone()
            },
            LeaseSummary {
                id: "expired".to_string(),
                phase: "Expired".to_string(),
                ..base
            },
        ];
        let live = live_lease_ids(&leases);
        assert!(live.contains("bound"));
        assert!(live.contains("pending"));
        assert!(
            live.contains("recycling"),
            "Recycling must be treated as live"
        );
        assert!(!live.contains("released"));
        assert!(!live.contains("expired"));
    }
}
