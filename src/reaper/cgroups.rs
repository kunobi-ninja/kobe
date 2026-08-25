//! Reap stale cgroup-v2 directories left by nested k3s containerd instances.
//!
//! Privileged k3s pool members share the host cgroup hierarchy. With the
//! cgroupfs driver, containerd creates `/sys/fs/cgroup/k8s.io/<container-id>`
//! directories. Abrupt member teardown can leave those directories behind
//! until the kernel's hierarchy-wide cgroup limit prevents any new Pod from
//! starting. Cleanup is deliberately conservative: only aged, direct children
//! named like full container IDs are considered, and the kernel must report
//! the cgroup unpopulated with no processes before a non-recursive `rmdir`.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Remove aged, empty container cgroups directly below `root`.
///
/// `remove_dir` is intentionally non-recursive. Even after the explicit
/// process/population checks, the kernel remains the final race-safe guard: a
/// cgroup that gains a process or child before removal is rejected rather than
/// disturbed.
pub fn reap_empty_container_cgroups(
    root: &Path,
    now: SystemTime,
    mtime_skip: Duration,
    dry_run: bool,
) -> Result<usize> {
    if std::env::var("KOBE_REAPER_DISABLE").as_deref() == Ok("1") {
        return Ok(0);
    }
    if !root.is_dir() {
        debug!(?root, "container cgroup root not present, nothing to do");
        return Ok(0);
    }

    let entries =
        fs::read_dir(root).with_context(|| format!("read container cgroup root {root:?}"))?;
    let mut cleaned = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, "read container cgroup entry failed (continuing)");
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_full_container_id(name) {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                warn!(?path, %error, "read cgroup file type failed (skipping)");
                continue;
            }
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        if !is_reapable(&path, now, mtime_skip) {
            continue;
        }
        if dry_run {
            info!(?path, "DRY RUN: would remove empty stale container cgroup");
            continue;
        }
        match fs::remove_dir(&path) {
            Ok(()) => {
                cleaned += 1;
                debug!(?path, "removed empty stale container cgroup");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                // Expected when a process/child raced into the cgroup. The
                // non-recursive removal is the final safety gate.
                debug!(?path, %error, "container cgroup removal refused; keeping it");
            }
        }
    }
    Ok(cleaned)
}

fn is_full_container_id(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_reapable(path: &Path, now: SystemTime, mtime_skip: Duration) -> bool {
    let modified = match fs::metadata(path).and_then(|metadata| metadata.modified()) {
        Ok(modified) => modified,
        Err(_) => return false,
    };
    if now
        .duration_since(modified)
        .is_ok_and(|age| age < mtime_skip)
    {
        return false;
    }

    let events = match fs::read_to_string(path.join("cgroup.events")) {
        Ok(events) => events,
        Err(_) => return false,
    };
    let unpopulated = events
        .lines()
        .any(|line| line.split_whitespace().eq(["populated", "0"]));
    if !unpopulated {
        return false;
    }

    fs::read_to_string(path.join("cgroup.procs")).is_ok_and(|processes| processes.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn container_dir(tmp: &TempDir, name: &str, events: &str, procs: &str) -> std::path::PathBuf {
        let path = tmp.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.events"), events).unwrap();
        fs::write(path.join("cgroup.procs"), procs).unwrap();
        path
    }

    #[test]
    fn full_container_id_requires_64_lower_hex_characters() {
        assert!(is_full_container_id(&"a".repeat(64)));
        assert!(!is_full_container_id(&"a".repeat(63)));
        assert!(!is_full_container_id(&"A".repeat(64)));
        assert!(!is_full_container_id(&"g".repeat(64)));
    }

    #[test]
    fn reapable_requires_unpopulated_and_empty_processes() {
        let tmp = TempDir::new().unwrap();
        let empty = container_dir(&tmp, &"a".repeat(64), "populated 0\nfrozen 0\n", "");
        let populated = container_dir(&tmp, &"b".repeat(64), "populated 1\n", "42\n");
        let inconsistent = container_dir(&tmp, &"c".repeat(64), "populated 0\n", "42\n");
        let now = SystemTime::now();

        assert!(is_reapable(&empty, now, Duration::ZERO));
        assert!(!is_reapable(&populated, now, Duration::ZERO));
        assert!(!is_reapable(&inconsistent, now, Duration::ZERO));
    }

    #[test]
    fn reapable_respects_mtime_gate_and_missing_kernel_files() {
        let tmp = TempDir::new().unwrap();
        let fresh = container_dir(&tmp, &"d".repeat(64), "populated 0\n", "");
        let missing = tmp.path().join("e".repeat(64));
        fs::create_dir(&missing).unwrap();
        let now = SystemTime::now();

        assert!(!is_reapable(&fresh, now, Duration::from_secs(300)));
        assert!(!is_reapable(&missing, now, Duration::ZERO));
    }

    #[test]
    fn dry_run_identifies_but_does_not_remove_candidate() {
        let tmp = TempDir::new().unwrap();
        let path = container_dir(&tmp, &"f".repeat(64), "populated 0\n", "");

        let cleaned =
            reap_empty_container_cgroups(tmp.path(), SystemTime::now(), Duration::ZERO, true)
                .unwrap();

        assert_eq!(cleaned, 0);
        assert!(path.exists());
    }
}
