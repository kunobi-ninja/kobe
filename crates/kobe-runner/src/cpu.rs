//! CPU-quota detection for the Sandbox container this runner executes inside
//! (#272).
//!
//! # The problem
//!
//! `nproc`, `getconf _NPROCESSORS_ONLN`, and `std::thread::available_parallelism`
//! all report the HOST's CPU count, because that is what `/proc/cpuinfo` and
//! the scheduler's affinity mask say. A Sandbox container is not the host: its
//! real ceiling is the cgroup v2 CPU quota Kubernetes wrote when it created
//! the Pod, and that quota is commonly a fraction of the host's — 8 CPUs on a
//! 64-CPU node was the case that opened #272. Nothing about the mismatch
//! errors: `cargo`, the Rust test harness, and `make -j` all size their
//! worker count from the CPU count they can see, so they oversubscribe the
//! real quota by whatever the ratio is, and a job that passes CI in three
//! minutes silently takes an hour in the Sandbox instead.
//!
//! # What this is, and is not
//!
//! This module makes the real number visible (`KOBE_CPUS`) and gives Rust's
//! own build/test tooling a sane default (`CARGO_BUILD_JOBS`,
//! `RUST_TEST_THREADS`). It is a MITIGATION, not a fix: a tool that reads
//! `nproc`, `/proc/cpuinfo`, or `sched_getaffinity` directly instead of one of
//! these variables is still wrong, and nothing here changes what `nproc`
//! prints inside the container. Making the *visible* count match the quota —
//! cpuset pinning, or an lxcfs-style `/proc`+`/sys` shim — would fix it for
//! every tool instead of the ones we remembered to name, at the cost of doing
//! that work. See #272 for the tradeoff as recorded when this was written.
//!
//! # Why this lives in Rust, not a container-start shell script
//!
//! Kobe's runner executes a tenant's argv directly with NO shell in between —
//! see `main.rs`'s module docs and the `agent-workspace.Dockerfile` comments
//! next to its `ENV PATH` line for the exact trap this avoids. A value a
//! container-start script `export`s, or drops into `/etc/profile.d`, is
//! invisible to that exec: `kubectl exec`-style transports (Kobe's own exec
//! protocol included) hand the new process the container's *declared*
//! environment, not whatever a still-running PID 1 shell has exported
//! internally after the fact. The only place a value computed at runtime can
//! still reach a shell-less exec is the process that actually calls `execve`
//! on the tenant's command — this runner — so [`apply_defaults`] sets it
//! there, at every spawn point, rather than relying on anything sourced by a
//! shell that may never run.

use std::io::Read;
use std::path::Path;

/// Where cgroup v2 publishes this container's CPU quota.
const CPU_MAX_PATH: &str = "/sys/fs/cgroup/cpu.max";

/// Parse cgroup v2's `cpu.max`: `"$QUOTA $PERIOD"` in microseconds, or
/// `"max $PERIOD"` when the group has no quota at all.
///
/// Returns `None` for "no quota" (`max`) and for anything that fails to
/// parse — the caller falls back to the host's own CPU count either way, and
/// a malformed read (a v1 host with some unrelated file at this path, a
/// truncated read) is not a case worth failing loudly over.
///
/// A quota that does not divide the period evenly is rounded DOWN
/// (`250000 100000`, 2.5 CPUs, becomes 2 — not 3). Rounding up would ask
/// cargo/rustc for one more worker than the quota can ever run at once,
/// which recreates the exact oversubscription this module exists to avoid:
/// a fractional CPU left idle is a far cheaper mistake than another
/// multi-times slowdown from workers fighting the throttle. The result is
/// never less than 1 — a quota that rounds to 0 would tell every tool to run
/// with zero workers, which is a different failure, not a smaller one.
pub fn parse_cpu_max(contents: &str) -> Option<u64> {
    let mut fields = contents.split_whitespace();
    let quota = fields.next()?;
    let period: u64 = fields.next()?.parse().ok()?;
    if quota == "max" || period == 0 {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    Some((quota / period).max(1))
}

/// The CPU count this container should size itself to.
///
/// Reads the live cgroup quota on every call rather than caching a value
/// computed once: the quota differs per pool (#272), so a value baked in at
/// image-build time, or even at this container's first start, would just be
/// a different way of being wrong if the pool ever changes it. Falls back to
/// the host's own CPU count — the same source `nproc` reads — when the file
/// is absent (a cgroup v1 host, or any runtime that has not mounted cgroup
/// v2 at this path) or reports no quota.
pub fn detected_cpus() -> u64 {
    detected_cpus_at(Path::new(CPU_MAX_PATH))
}

fn detected_cpus_at(path: &Path) -> u64 {
    read_small_file(path)
        .and_then(|contents| parse_cpu_max(&contents))
        .unwrap_or_else(host_cpus)
}

fn host_cpus() -> u64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
}

/// A bounded read. `cpu.max` is a kernel-provided pseudo-file, never
/// attacker-sized input, but there is no reason to trust it unconditionally.
fn read_small_file(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut buffer = String::new();
    file.take(256).read_to_string(&mut buffer).ok()?;
    Some(buffer)
}

/// Environment defaults every spawned tenant process should see.
///
/// `KOBE_CPUS` is always this runner's best current answer: it is a
/// diagnostic, not a tool argument, so there is nothing to defer to.
/// `CARGO_BUILD_JOBS` and `RUST_TEST_THREADS` are left alone when the runner's
/// own environment already sets them, so a caller — or a pool operator who
/// already tuned these on the Pod spec — is never second-guessed by a
/// generic default.
pub fn env_defaults() -> Vec<(&'static str, String)> {
    let cpus = detected_cpus().to_string();
    let mut defaults = vec![("KOBE_CPUS", cpus.clone())];
    for key in ["CARGO_BUILD_JOBS", "RUST_TEST_THREADS"] {
        if std::env::var_os(key).is_none() {
            defaults.push((key, cpus.clone()));
        }
    }
    defaults
}

/// Apply [`env_defaults`] to a [`std::process::Command`] about to spawn a
/// tenant process — the one place a value computed here can still reach a
/// shell-less `kobe exec` (see the module docs above).
pub fn apply_defaults(command: &mut std::process::Command) {
    for (key, value) in env_defaults() {
        command.env(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `800000 100000` is the exact reading from #272: an 8-CPU quota on a
    /// 64-CPU host.
    #[test]
    fn a_normal_quota_divides_evenly() {
        assert_eq!(parse_cpu_max("800000 100000\n"), Some(8));
        assert_eq!(parse_cpu_max("800000 100000"), Some(8));
    }

    /// `max` is cgroup v2's spelling of "no limit configured on this group",
    /// distinct from a quota of zero.
    #[test]
    fn max_means_no_quota_and_falls_back() {
        assert_eq!(parse_cpu_max("max 100000\n"), None);
        assert_eq!(parse_cpu_max("max 100000"), None);
    }

    /// A quota that does not divide the period evenly rounds DOWN, and never
    /// below 1. See `parse_cpu_max`'s doc comment for why oversubscription —
    /// what rounding up would do — is the worse of the two mistakes here.
    #[test]
    fn an_uneven_quota_rounds_down_never_to_zero() {
        assert_eq!(parse_cpu_max("250000 100000"), Some(2));
        assert_eq!(parse_cpu_max("50000 100000"), Some(1));
        assert_eq!(parse_cpu_max("99999 100000"), Some(1));
    }

    /// Anything unparseable, or a zero period, is treated the same as `max`:
    /// no opinion, let the caller fall back.
    #[test]
    fn garbage_is_refused_rather_than_guessed_at() {
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cpu_max("not-a-number 100000"), None);
        assert_eq!(parse_cpu_max("800000 not-a-number"), None);
        assert_eq!(parse_cpu_max("800000 0"), None);
        assert_eq!(parse_cpu_max("800000"), None);
    }

    /// A cgroup v1 host (or any runtime that hasn't mounted cgroup v2 here)
    /// has no `cpu.max` file at all. That must fall back quietly to the host
    /// count, not error.
    #[test]
    fn a_missing_file_falls_back_to_the_host_count() {
        assert_eq!(
            detected_cpus_at(Path::new("/does/not/exist/cpu.max")),
            host_cpus()
        );
    }

    /// `env_defaults` always reports `KOBE_CPUS`, and it is never the literal
    /// "0" a bad quota could otherwise produce.
    #[test]
    fn env_defaults_always_reports_a_positive_cpu_count() {
        let defaults = env_defaults();
        let kobe_cpus = defaults
            .iter()
            .find(|(key, _)| *key == "KOBE_CPUS")
            .map(|(_, value)| value)
            .expect("KOBE_CPUS is always present");
        let parsed: u64 = kobe_cpus.parse().expect("KOBE_CPUS is a plain integer");
        assert!(parsed >= 1);
    }
}
