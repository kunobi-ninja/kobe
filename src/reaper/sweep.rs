//! Sweep orchestration: read live-set file → list lease-root dirs →
//! classify → per-stale: synchronous GET → unmount mounts → rm -rf.

use crate::reaper::classify::{FileKind, HostEntry, StaleEntry, classify_entries};
use crate::reaper::mounts::collect_mounts_under;
use crate::reaper::unmount::Unmount;
use anyhow::{Context, Result};
use kube::{Client, api::Api};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Inputs for one sweep tick, bundled so the entry point stays readable.
pub struct SweepParams<'a> {
    pub lease_root: &'a Path,
    pub live_set_path: &'a Path,
    pub mountinfo_path: &'a Path,
    pub mtime_skip: Duration,
    pub dry_run: bool,
    /// Skip the synchronous apiserver check in `process_stale`. Read from
    /// `KOBE_REAPER_SKIP_GET` at the composition root and threaded through as
    /// data, so tests never mutate the process environment.
    pub skip_get: bool,
}

/// One sweep tick. Returns the number of stale entries actually reaped.
pub async fn sweep_once(
    client: &Client,
    unmounter: &dyn Unmount,
    params: &SweepParams<'_>,
) -> Result<usize> {
    let SweepParams {
        lease_root,
        live_set_path,
        mountinfo_path,
        mtime_skip,
        dry_run,
        skip_get,
    } = *params;
    if std::env::var("KOBE_REAPER_DISABLE").as_deref() == Ok("1") {
        info!("KOBE_REAPER_DISABLE=1 set; sweep skipped");
        return Ok(0);
    }
    if !lease_root.is_dir() {
        debug!(?lease_root, "lease_root not present, nothing to do");
        return Ok(0);
    }
    let live = match read_live_set(live_set_path) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "live-set file unreadable; refusing to act this tick");
            return Ok(0);
        }
    };

    let entries = list_host_entries(lease_root)?;
    let now = SystemTime::now();
    let stale = classify_entries(&live, entries, now, mtime_skip);

    let mut cleaned = 0;
    for s in stale {
        match process_stale(client, &s, mountinfo_path, dry_run, unmounter, skip_get).await {
            Ok(SweepOutcome::Reaped) => cleaned += 1,
            // Deliberate skips — apiserver unreachable, the CR still exists,
            // umount failed, rm -rf failed, or this is a dry run. None of
            // them removed anything, so none of them may be counted.
            Ok(SweepOutcome::Skipped) => {}
            Err(e) => warn!(name = s.name, error = %e, "process_stale failed"),
        }
    }
    Ok(cleaned)
}

/// Whether an entry's tree was actually removed.
///
/// `process_stale` returns `Ok` for several outcomes that delete nothing —
/// the safety skips are the whole point of the design. Collapsing them into
/// `Ok(())` made the caller count them as cleaned, so the reaper reported
/// `cleaned = N` while the apiserver was unreachable, while a mount was busy,
/// and in dry-run mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepOutcome {
    Reaped,
    Skipped,
}

fn read_live_set(path: &Path) -> Result<HashSet<String>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("read live-set file {path:?}"))?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn list_host_entries(root: &Path) -> Result<Vec<HostEntry>> {
    let mut out = vec![];
    for entry in fs::read_dir(root)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "read_dir item failed (continuing)");
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let md = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(?path, error = %e, "symlink_metadata failed (skipping entry)");
                continue;
            }
        };
        let kind = if md.is_dir() && !md.file_type().is_symlink() {
            FileKind::RealDir
        } else {
            FileKind::SymlinkOrOther
        };
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        out.push(HostEntry {
            name,
            path,
            mtime,
            kind,
        });
    }
    Ok(out)
}

async fn process_stale(
    client: &Client,
    stale: &StaleEntry,
    mountinfo_path: &Path,
    dry_run: bool,
    unmounter: &dyn Unmount,
    skip_get: bool,
) -> Result<SweepOutcome> {
    if skip_get {
        tracing::warn!(
            name = stale.name,
            "KOBE_REAPER_SKIP_GET=1; proceeding without apiserver final check (TEST USE ONLY)"
        );
    } else {
        // Synchronous cluster-wide LIST with `fieldSelector=metadata.name=<n>`.
        // `Api::all<T>::get(name)` would hit `/apis/.../resource/name` which is
        // a cluster-scoped path and unreliable for namespaced resources — it
        // 404s even when the CR exists. A name-filtered list is namespace-
        // agnostic and remains a single round-trip.
        use crate::crd::ClusterInstance;
        use kube::api::ListParams;
        let cis: Api<ClusterInstance> = Api::all(client.clone());
        let lp = ListParams::default().fields(&format!("metadata.name={}", stale.name));
        match cis.list(&lp).await {
            Ok(list) if !list.items.is_empty() => {
                warn!(
                    name = stale.name,
                    found = list.items.len(),
                    "live_set_lag: CR exists but missing from live-set CM; skipping",
                );
                return Ok(SweepOutcome::Skipped);
            }
            Ok(_) => {}
            Err(e) => {
                warn!(error = %e, "apiserver LIST failed; skipping destructive action this tick");
                metrics::REAPER_APISERVER_UNREACHABLE.inc();
                return Ok(SweepOutcome::Skipped);
            }
        }
    }

    // Collect mounts under this stale path.
    let mountinfo =
        fs::read_to_string(mountinfo_path).with_context(|| format!("read {mountinfo_path:?}"))?;
    let mounts = collect_mounts_under(&stale.path, &mountinfo);

    if dry_run {
        info!(
            name = stale.name,
            mounts = mounts.len(),
            "DRY RUN: would unmount and rm -rf"
        );
        return Ok(SweepOutcome::Skipped);
    }

    // Unmount deepest-first. Any failure aborts rm-rf for this entry.
    for m in mounts {
        match unmounter.umount(&m.mountpoint) {
            Ok(_) => debug!(?m.mountpoint, "unmounted"),
            Err(e) => {
                warn!(
                    name = stale.name,
                    mountpoint = ?m.mountpoint,
                    error = %e,
                    "umount2 failed; skipping rm -rf for this entry"
                );
                return Ok(SweepOutcome::Skipped);
            }
        }
    }

    // Remove the directory tree.
    if let Err(e) = fs::remove_dir_all(&stale.path) {
        warn!(name = stale.name, path = ?stale.path, error = %e, "rm -rf failed");
        return Ok(SweepOutcome::Skipped);
    }
    info!(name = stale.name, path = ?stale.path, "reaped stale lease dir");
    Ok(SweepOutcome::Reaped)
}

mod metrics {
    use prometheus::IntCounter;
    use std::sync::LazyLock;
    pub static REAPER_APISERVER_UNREACHABLE: LazyLock<IntCounter> = LazyLock::new(|| {
        prometheus::register_int_counter!(
            "kobe_reaper_skipped_apiserver_unreachable_total",
            "Number of reaper sweep ticks where a synchronous GET against \
             the apiserver failed and destructive action was skipped."
        )
        .expect("register kobe_reaper_skipped_apiserver_unreachable_total")
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reaper::unmount::testing::MockUnmount;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_dir(root: &Path, name: &str) -> PathBuf {
        let p = root.join(name);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_live_set(root: &Path, content: &str) -> PathBuf {
        let p = root.join("live");
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn read_live_set_strips_blanks_and_whitespace() {
        let tmp = TempDir::new().unwrap();
        let p = make_live_set(tmp.path(), "  a\nb\n\n  c  \n");
        let set = read_live_set(&p).unwrap();
        assert_eq!(
            set,
            ["a".to_string(), "b".to_string(), "c".to_string()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn list_host_entries_classifies_symlink_as_symlink_or_other() {
        let tmp = TempDir::new().unwrap();
        let lease_root = make_dir(tmp.path(), "leases");
        make_dir(&lease_root, "real-dir");
        // Skip symlink test on platforms where it requires admin.
        let target = make_dir(tmp.path(), "target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, lease_root.join("symlink")).unwrap();
        let entries = list_host_entries(&lease_root).unwrap();
        let symlink_entry = entries.iter().find(|e| e.name == "symlink");
        #[cfg(unix)]
        {
            let sl = symlink_entry.expect("symlink found");
            assert_eq!(sl.kind, FileKind::SymlinkOrOther);
        }
        let real = entries
            .iter()
            .find(|e| e.name == "real-dir")
            .expect("real-dir present");
        assert_eq!(real.kind, FileKind::RealDir);
    }

    /// A client that is never dialled.
    ///
    /// Every test here passes `skip_get = true`, so `process_stale` returns
    /// before touching the apiserver. The address is unroutable on purpose, but
    /// note it is defence in depth only, NOT an assertion: a request to it
    /// fails, and the failure branch returns `Skipped` — which is what the
    /// EBUSY test already expects. Do not read these tests as proving the
    /// apiserver is never dialled.
    fn offline_client() -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let kubeconfig = kube::config::Kubeconfig {
            clusters: vec![kube::config::NamedCluster {
                name: "offline".to_string(),
                cluster: Some(kube::config::Cluster {
                    server: Some("https://127.0.0.1:1".to_string()),
                    ..Default::default()
                }),
            }],
            contexts: vec![kube::config::NamedContext {
                name: "offline".to_string(),
                context: Some(kube::config::Context {
                    cluster: "offline".to_string(),
                    ..Default::default()
                }),
            }],
            current_context: Some("offline".to_string()),
            ..Default::default()
        };
        let config = futures::executor::block_on(kube::Config::from_custom_kubeconfig(
            kubeconfig,
            &Default::default(),
        ))
        .unwrap();
        Client::try_from(config).unwrap()
    }

    /// A stale entry rooted at a fresh directory, with one mount underneath.
    fn stale_fixture(tmp: &TempDir, name: &str) -> (StaleEntry, PathBuf, PathBuf) {
        let lease_root = make_dir(tmp.path(), "leases");
        let stale_path = make_dir(&lease_root, name);
        let mp = stale_path.join("kubelets/podX/vol");
        fs::create_dir_all(&mp).unwrap();
        let mountinfo_path = tmp.path().join(format!("mountinfo-{name}"));
        fs::write(
            &mountinfo_path,
            format!("36 35 98:0 / {} rw -\n", mp.display()),
        )
        .unwrap();
        let stale = StaleEntry {
            name: name.to_string(),
            path: stale_path.clone(),
        };
        (stale, stale_path, mountinfo_path)
    }

    // Integration-y test: tempdir + offline classify + mock unmounter +
    // no apiserver. Exercises `process_stale` itself, so it actually
    // constrains the umount EBUSY → skip rm path.
    #[tokio::test]
    async fn umount_ebusy_aborts_rm_and_leaves_dir_for_retry() {
        let tmp = TempDir::new().unwrap();
        let (stale, stale_path, mountinfo_path) = stale_fixture(&tmp, "stale-a");
        let mp = stale_path.join("kubelets/podX/vol");

        let unmounter = MockUnmount::new().fail_on(&mp);
        let outcome = process_stale(
            &offline_client(),
            &stale,
            &mountinfo_path,
            false,
            &unmounter,
            true,
        )
        .await
        .unwrap();

        assert!(
            stale_path.exists(),
            "umount failed, so rm -rf must not have run"
        );
        assert_eq!(
            outcome,
            SweepOutcome::Skipped,
            "a skipped entry must not be reported as cleaned"
        );
    }

    /// The control case. Without it the test above passes for a directory
    /// that was never going to be removed anyway.
    #[tokio::test]
    async fn successful_unmount_reaps_the_directory() {
        let tmp = TempDir::new().unwrap();
        let (stale, stale_path, mountinfo_path) = stale_fixture(&tmp, "stale-b");

        let outcome = process_stale(
            &offline_client(),
            &stale,
            &mountinfo_path,
            false,
            &MockUnmount::new(),
            true,
        )
        .await
        .unwrap();

        assert!(!stale_path.exists(), "the tree should be gone");
        assert_eq!(outcome, SweepOutcome::Reaped);
    }

    /// Dry run must touch nothing — and must not claim it cleaned anything.
    #[tokio::test]
    async fn dry_run_removes_nothing_and_reports_skipped() {
        let tmp = TempDir::new().unwrap();
        let (stale, stale_path, mountinfo_path) = stale_fixture(&tmp, "stale-c");

        let outcome = process_stale(
            &offline_client(),
            &stale,
            &mountinfo_path,
            true,
            &MockUnmount::new(),
            true,
        )
        .await
        .unwrap();

        assert!(stale_path.exists(), "dry run must not remove anything");
        assert_eq!(outcome, SweepOutcome::Skipped);
    }

    /// The accounting fix lives in `sweep_once`, not in `process_stale`, and
    /// every other test here calls the latter. Without this, re-adding
    /// `cleaned += 1` for the Skipped arm would pass the whole suite — the
    /// same gap that made the original umount test worthless.
    #[tokio::test]
    async fn sweep_once_counts_only_entries_it_actually_reaped() {
        let tmp = TempDir::new().unwrap();
        let lease_root = make_dir(tmp.path(), "leases");
        // Two stale dirs: neither is in the live set, both are old enough.
        let reapable = make_dir(&lease_root, "gone-a");
        let blocked = make_dir(&lease_root, "gone-b");
        let blocked_mp = blocked.join("kubelets/podX/vol");
        fs::create_dir_all(&blocked_mp).unwrap();

        let live_set = make_live_set(tmp.path(), "");
        let mountinfo_path = tmp.path().join("mountinfo");
        fs::write(
            &mountinfo_path,
            format!("36 35 98:0 / {} rw -\n", blocked_mp.display()),
        )
        .unwrap();

        // gone-b has a mount that refuses to unmount, so it must be skipped.
        let unmounter = MockUnmount::new().fail_on(&blocked_mp);

        let cleaned = sweep_once(
            &offline_client(),
            &unmounter,
            &SweepParams {
                lease_root: &lease_root,
                live_set_path: &live_set,
                mountinfo_path: &mountinfo_path,
                mtime_skip: Duration::from_secs(0),
                dry_run: false,
                skip_get: true,
            },
        )
        .await
        .unwrap();

        assert!(!reapable.exists(), "the unblocked entry should be gone");
        assert!(blocked.exists(), "the blocked entry must survive");
        assert_eq!(cleaned, 1, "only the reaped entry may be counted");
    }
}
