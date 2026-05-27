//! Classify host lease-root entries as stale or skip. Pure functions.

use regex::Regex;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    RealDir,
    SymlinkOrOther,
}

#[derive(Debug, Clone)]
pub struct HostEntry {
    pub name: String,
    pub path: PathBuf,
    pub mtime: SystemTime,
    pub kind: FileKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleEntry {
    pub name: String,
    pub path: PathBuf,
}

fn name_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$").unwrap())
}

/// Apply all gates and return entries that are stale candidates.
/// The caller is responsible for the final synchronous GET step
/// (`sweep` module) before destructive action.
pub fn classify_entries(
    live: &HashSet<String>,
    entries: Vec<HostEntry>,
    now: SystemTime,
    mtime_skip: Duration,
) -> Vec<StaleEntry> {
    entries
        .into_iter()
        .filter_map(|e| {
            if !name_re().is_match(&e.name) {
                return None;
            }
            if e.kind != FileKind::RealDir {
                return None;
            }
            if live.contains(&e.name) {
                return None;
            }
            // mtime gate: skip entries newer than mtime_skip.
            match now.duration_since(e.mtime) {
                Ok(age) if age < mtime_skip => return None,
                _ => {}
            }
            Some(StaleEntry {
                name: e.name,
                path: e.path,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn entry(name: &str, age_secs: u64, kind: FileKind) -> HostEntry {
        HostEntry {
            name: name.into(),
            path: PathBuf::from(format!("/var/lib/kobe/leases/{name}")),
            mtime: SystemTime::now() - Duration::from_secs(age_secs),
            kind,
        }
    }

    #[test]
    fn live_gate_excludes_live_entries() {
        let live: HashSet<String> = ["a".into(), "b".into()].into_iter().collect();
        let entries = vec![
            entry("a", 600, FileKind::RealDir),
            entry("b", 600, FileKind::RealDir),
            entry("c", 600, FileKind::RealDir),
            entry("d", 600, FileKind::RealDir),
        ];
        let stale = classify_entries(&live, entries, SystemTime::now(), Duration::from_secs(120));
        let names: Vec<_> = stale.iter().map(|s| s.name.clone()).collect();
        assert_eq!(names, vec!["c", "d"]);
    }

    #[test]
    fn empty_live_means_all_old_real_dirs_stale() {
        let live = HashSet::new();
        let entries = vec![
            entry("a", 600, FileKind::RealDir),
            entry("b", 600, FileKind::RealDir),
        ];
        let stale = classify_entries(&live, entries, SystemTime::now(), Duration::from_secs(120));
        assert_eq!(stale.len(), 2);
    }

    #[test]
    fn mtime_gate_skips_fresh_entries_even_if_missing_from_live() {
        let live = HashSet::new();
        let entries = vec![entry("fresh", 5, FileKind::RealDir)];
        let stale = classify_entries(&live, entries, SystemTime::now(), Duration::from_secs(120));
        assert!(stale.is_empty());
    }

    #[test]
    fn regex_gate_rejects_invalid_names() {
        let live = HashSet::new();
        // ".." and "..hidden" and "WithCaps" must NOT be classified stale
        // even though they're old and missing.
        let entries = vec![
            entry("..", 600, FileKind::RealDir),
            entry(".hidden", 600, FileKind::RealDir),
            entry("WithCaps", 600, FileKind::RealDir),
            entry("valid-1", 600, FileKind::RealDir),
        ];
        let stale = classify_entries(&live, entries, SystemTime::now(), Duration::from_secs(120));
        let names: Vec<_> = stale.iter().map(|s| s.name.clone()).collect();
        assert_eq!(names, vec!["valid-1"]);
    }

    #[test]
    fn symlink_or_other_kinds_are_skipped() {
        let live = HashSet::new();
        let entries = vec![entry("evil", 600, FileKind::SymlinkOrOther)];
        let stale = classify_entries(&live, entries, SystemTime::now(), Duration::from_secs(120));
        assert!(stale.is_empty());
    }
}
