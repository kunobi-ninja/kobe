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

    let (removed_paths, failures) = remove_kubeconfig_files(dedupe_paths(removable_files));

    // Drop the tracking entries only once the files are actually gone. Wiping
    // them up front means a failed removal leaves a file on disk that nothing
    // points at any more — the same silent leak `purge_orphans_only` was fixed
    // for. Leaving them lets the next run re-detect the stragglers.
    if failures.is_empty() {
        forget_endpoint_kubeconfigs(endpoint)?;
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
            if !failures.is_empty() {
                eprintln!("Failed to remove {} file(s):", failures.len());
                for (path, err) in &failures {
                    eprintln!("  {}: {err}", path.display());
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

    if !failures.is_empty() {
        anyhow::bail!("Failed to remove {} kubeconfig file(s)", failures.len());
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

/// Remove each file, collecting failures instead of aborting on the first.
///
/// Same policy as `purge_orphans_only`: one unremovable file must not abandon
/// every file after it. Returns the paths actually removed and the ones that
/// could not be.
fn remove_kubeconfig_files(paths: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<(PathBuf, std::io::Error)>) {
    let mut removed_paths = Vec::new();
    let mut failures = Vec::new();
    for path in paths {
        // Attempt the removal unconditionally rather than gating on
        // `Path::exists()`. That call follows symlinks and reports false for a
        // broken one, and also returns false when the metadata lookup itself
        // fails (a permission error on the parent, say) — both of which then
        // looked like "already gone" and let the caller clear its tracking
        // state for a file still on disk. NotFound from the removal is the only
        // thing that actually proves absence.
        match std::fs::remove_file(&path) {
            Ok(()) => removed_paths.push(path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => failures.push((path, err)),
        }
    }
    (removed_paths, failures)
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

    /// A batch of paths where the middle entry cannot be removed.
    ///
    /// `remove_file` on a *directory* fails on every supported platform and
    /// needs no permission games, so it stays correct when the suite runs as
    /// root (a chmod-based fixture would silently stop failing there).
    fn batch_with_an_unremovable_middle() -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("kobe-lease-first.yaml");
        let blocked = dir.path().join("kobe-lease-blocked.yaml");
        let last = dir.path().join("kobe-lease-last.yaml");
        std::fs::write(&first, "a").unwrap();
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(&last, "c").unwrap();
        (dir, vec![first, blocked, last])
    }

    /// The regression this fixes.
    ///
    /// `purge_orphans_only` collects per-file failures and keeps going,
    /// deliberately — its comment records that aborting "turned a single I/O
    /// error into a permanent silent leak". The full-purge path had never
    /// adopted that policy: it propagated with `?`, so one unremovable file
    /// abandoned every file after it, while `forget_endpoint_kubeconfigs` had
    /// already dropped the tracking entries for all of them.
    #[test]
    fn one_unremovable_file_does_not_abandon_the_rest_of_the_batch() {
        let (dir, paths) = batch_with_an_unremovable_middle();
        let (first, blocked, last) = (paths[0].clone(), paths[1].clone(), paths[2].clone());

        let (removed, failures) = remove_kubeconfig_files(paths);

        assert_eq!(removed, vec![first.clone(), last.clone()]);
        assert!(!first.exists());
        assert!(!last.exists(), "the file after the failure must still go");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, blocked);
        drop(dir);
    }

    #[test]
    fn missing_paths_are_skipped_without_being_reported_as_failures() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("kobe-lease-here.yaml");
        std::fs::write(&present, "x").unwrap();
        let absent = dir.path().join("kobe-lease-gone.yaml");

        let (removed, failures) = remove_kubeconfig_files(vec![absent, present.clone()]);

        assert_eq!(removed, vec![present]);
        assert!(
            failures.is_empty(),
            "an already-absent file is the goal state"
        );
    }

    #[test]
    fn an_empty_batch_is_not_a_failure() {
        let (removed, failures) = remove_kubeconfig_files(Vec::new());
        assert!(removed.is_empty());
        assert!(failures.is_empty());
    }

    /// `purge` chains state-tracked paths with the ~/.kube glob, so the same
    /// file arrives twice whenever a tracked kubeconfig also matches the
    /// naming pattern. Deduping is what stops the second pass reporting a
    /// spurious failure for a file the first pass already removed.
    #[test]
    fn dedupe_paths_keeps_first_occurrence_order() {
        let a = PathBuf::from("/tmp/kobe-a.yaml");
        let b = PathBuf::from("/tmp/kobe-b.yaml");
        let deduped = dedupe_paths(vec![a.clone(), b.clone(), a.clone(), b.clone()]);
        assert_eq!(deduped, vec![a, b]);
    }

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
            alias: None,
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
            alias: None,
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

    /// `Path::exists()` follows symlinks and returns false for a broken one,
    /// so a dangling kubeconfig symlink was skipped, counted as absent, and
    /// left on disk forever — while the caller saw no failure and cleared the
    /// endpoint's tracking state. `remove_file` unlinks the symlink itself.
    #[test]
    #[cfg(unix)]
    fn a_dangling_symlink_is_removed_not_silently_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("kobe-lease-dangling.yaml");
        std::os::unix::fs::symlink(dir.path().join("no-such-target"), &link).unwrap();
        assert!(!link.exists(), "precondition: exists() is false for it");
        assert!(link.symlink_metadata().is_ok(), "precondition: it is there");

        let (removed, failures) = remove_kubeconfig_files(vec![link.clone()]);

        assert!(failures.is_empty());
        assert_eq!(removed, vec![link.clone()], "it should be reported removed");
        assert!(link.symlink_metadata().is_err(), "the link must be gone");
    }
}
