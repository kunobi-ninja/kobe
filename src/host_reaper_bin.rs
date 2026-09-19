//! `kobe-host-reaper` — privileged DaemonSet entrypoint.
//! Runs an infinite sweep loop driven by the live-set ConfigMap and
//! /var/lib/kobe/leases/. See the `reaper` module docs for the sweep rules.
//!
//! # Module layout
//!
//! This binary re-declares `mod crd` and `mod reaper` with explicit `#[path]`
//! attributes so they resolve relative to the workspace src/ directory.
//! This is the same pattern used by `crdgen.rs` (`mod crd;`) — each binary
//! in this crate is its own crate root, so modules must be declared locally.

// The reaper only consumes `crd::ClusterInstance`, but `#[path]` pulls in
// the whole CRD tree (profile, lease, cidr, kobestore, etc.). Silence the
// resulting dead-code lints — they are noise in this bin's compilation
// context, not real unused code.
#[allow(dead_code, unused_imports)]
#[path = "crd/mod.rs"]
mod crd;

#[path = "reaper/mod.rs"]
mod reaper;

use clap::Parser;
use kube::Client;
use reaper::{
    cgroups::reap_empty_container_cgroups,
    sweep::{SweepParams, sweep_once},
    unmount::LibcUnmount,
};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "kobe-host-reaper",
    version,
    about = "Clean stale kobe lease-root subtrees on the host"
)]
struct Args {
    /// Lease-root host bind-mount path.
    #[arg(long, default_value = "/var/lib/kobe/leases")]
    lease_root: PathBuf,

    /// Path to the file mounted from the kobe-live-instances ConfigMap.
    #[arg(long, default_value = "/etc/kobe/live/instances")]
    live_set_path: PathBuf,

    /// Sweep cadence.
    #[arg(long, value_parser = parse_duration, default_value = "30s")]
    reconcile_interval: Duration,

    /// Don't touch entries newer than this.
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    mtime_skip: Duration,

    /// Host cgroup-v2 container root to clean. Omit to disable cgroup cleanup.
    #[arg(long)]
    cgroup_root: Option<PathBuf>,

    /// Don't touch empty container cgroups newer than this.
    #[arg(long, value_parser = parse_duration, default_value = "5m")]
    cgroup_mtime_skip: Duration,

    /// Log what would happen, don't act.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Path to mountinfo file (override for tests).
    #[arg(long, default_value = "/proc/self/mountinfo")]
    mountinfo_path: PathBuf,

    /// Run a single sweep tick and exit (test-only).
    #[arg(long, default_value_t = false)]
    one_shot: bool,

    /// Port for the Prometheus `/metrics` endpoint. 0 disables the server.
    ///
    /// Bound on all interfaces because the scrape arrives from off-node. The
    /// endpoint serves counters about the reaper's own work and exposes no
    /// lease names, paths or cluster contents.
    #[arg(long, default_value_t = 9109)]
    metrics_port: u16,
}

/// Serve `/metrics` until the process exits.
///
/// Failing to bind is logged and otherwise ignored: a reaper that cannot
/// publish metrics is degraded, but one that refuses to start over it would
/// stop cleaning the node — which is the failure this whole component exists to
/// prevent, and strictly worse than being unobservable.
async fn serve_metrics(port: u16) {
    use axum::{Router, routing::get};
    let app = Router::new().route("/metrics", get(|| async { reaper::metrics::gather() }));
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            info!(%addr, "serving reaper metrics");
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error = %e, "reaper metrics server stopped");
            }
        }
        Err(e) => {
            warn!(%addr, error = %e, "could not bind reaper metrics port; continuing without it")
        }
    }
}

/// Seconds since the epoch, or 0 if the clock is before it.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Directory entries directly under `root`, or 0 if it cannot be read.
///
/// An unreadable root reports 0 rather than failing the tick: the count is a
/// diagnostic, and losing it must not stop the cleaning.
fn count_dirs(root: &std::path::Path) -> i64 {
    match std::fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count() as i64,
        Err(_) => 0,
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    // Split on the last CHAR, not the last byte: `s.len()` counts bytes, so a
    // value ending in a multi-byte char (e.g. `10µ`) would slice mid-codepoint
    // and panic. Take the trailing char's UTF-8 length to find the boundary.
    let last = s.chars().next_back().expect("non-empty checked above");
    let (n, suffix) = s.split_at(s.len() - last.len_utf8());
    let n: u64 = n
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    // Use checked arithmetic so a large value overflows to an error rather than
    // silently wrapping to a tiny (or zero) duration.
    let secs = match suffix {
        "s" => n,
        "m" => n.checked_mul(60).ok_or("duration overflow")?,
        "h" => n.checked_mul(3600).ok_or("duration overflow")?,
        _ => return Err(format!("unknown duration suffix: {suffix}")),
    };
    Ok(Duration::from_secs(secs))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!(
        lease_root = ?args.lease_root,
        live_set_path = ?args.live_set_path,
        reconcile_interval_secs = args.reconcile_interval.as_secs(),
        mtime_skip_secs = args.mtime_skip.as_secs(),
        cgroup_root = ?args.cgroup_root,
        cgroup_mtime_skip_secs = args.cgroup_mtime_skip.as_secs(),
        dry_run = args.dry_run,
        one_shot = args.one_shot,
        "kobe-host-reaper starting"
    );

    // Register and seed every series before the first tick, so an alert on a
    // skip reason that has not happened yet reads zero rather than "no data".
    reaper::metrics::init();
    if args.metrics_port != 0 {
        tokio::spawn(serve_metrics(args.metrics_port));
    }

    let unmounter = LibcUnmount;

    // KOBE_REAPER_SKIP_GET=1 lets the binary skip the synchronous apiserver
    // GET in process_stale (test-only). Construction of the kube Client still
    // requires reaching the apiserver to discover server-side resources, so a
    // working kubeconfig is required even when SKIP_GET is set. In practice
    // the integration test environment always provides one; production
    // always has the in-cluster SA. If you genuinely need to run this
    // binary without any kubeconfig, file a follow-up to thread an
    // Option<Client> through sweep_once.
    let client = Client::try_default().await?;

    // Read the escape hatch once, here at the composition root. `set_var` is
    // unsafe because the harness runs tests on concurrent threads while other
    // threads call getenv, so the flag is threaded through as a parameter and
    // the tests never touch the environment.
    let skip_get = std::env::var("KOBE_REAPER_SKIP_GET").as_deref() == Ok("1");

    loop {
        let lease_cleaned = match sweep_once(
            &client,
            &unmounter,
            &SweepParams {
                lease_root: &args.lease_root,
                live_set_path: &args.live_set_path,
                mountinfo_path: &args.mountinfo_path,
                mtime_skip: args.mtime_skip,
                dry_run: args.dry_run,
                skip_get,
            },
        )
        .await
        {
            Ok(n) => {
                reaper::metrics::SWEEP_TICKS_TOTAL
                    .with_label_values(&["lease_root", "ok"])
                    .inc();
                n
            }
            Err(e) => {
                warn!(error = %e, "lease-root sweep tick failed");
                reaper::metrics::SWEEP_TICKS_TOTAL
                    .with_label_values(&["lease_root", "error"])
                    .inc();
                0
            }
        };
        let cgroups_cleaned = match args.cgroup_root.as_deref() {
            Some(root) => {
                let cleaned = match reap_empty_container_cgroups(
                    root,
                    std::time::SystemTime::now(),
                    args.cgroup_mtime_skip,
                    args.dry_run,
                ) {
                    Ok(n) => {
                        reaper::metrics::SWEEP_TICKS_TOTAL
                            .with_label_values(&["cgroups", "ok"])
                            .inc();
                        reaper::metrics::CGROUPS_REAPED_TOTAL
                            .with_label_values(&["ok"])
                            .inc_by(n as u64);
                        n
                    }
                    Err(e) => {
                        warn!(error = %e, "container cgroup sweep tick failed");
                        reaper::metrics::SWEEP_TICKS_TOTAL
                            .with_label_values(&["cgroups", "error"])
                            .inc();
                        reaper::metrics::CGROUPS_REAPED_TOTAL
                            .with_label_values(&["error"])
                            .inc();
                        0
                    }
                };
                // The level, after the tick. `CGROUPS_REAPED_TOTAL` says the
                // reaper is draining the leak; this says whether draining is
                // keeping up with it.
                reaper::metrics::CGROUPS_PRESENT.set(count_dirs(root));
                cleaned
            }
            None => 0,
        };
        if lease_cleaned > 0 || cgroups_cleaned > 0 {
            info!(lease_cleaned, cgroups_cleaned, "sweep tick done");
        }
        // Stamped on every tick, including the ones that changed nothing: a
        // quiet reaper and a dead one are otherwise identical, and that
        // ambiguity is what let a broken one go unnoticed.
        reaper::metrics::LAST_SWEEP_TIMESTAMP.set(unix_now());
        if args.one_shot {
            break;
        }
        tokio::time::sleep(args.reconcile_interval).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_handles_known_suffixes() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_empty_is_error() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_duration_unknown_suffix_is_error() {
        assert!(parse_duration("10d").is_err());
    }

    /// Regression: a value ending in a multi-byte char (`µ` is 2 bytes in
    /// UTF-8) must NOT panic on the `split_at` byte boundary — it should
    /// return a clean error instead.
    #[test]
    fn parse_duration_multibyte_suffix_does_not_panic() {
        // `µ` is an unknown unit, so we expect Err — the key property is
        // that this does not panic mid-codepoint.
        let result = parse_duration("10µ");
        assert!(result.is_err(), "multi-byte suffix should error, not panic");
    }

    /// A purely multi-byte (non-ASCII) input is still handled without panic.
    #[test]
    fn parse_duration_only_multibyte_char_does_not_panic() {
        assert!(parse_duration("µ").is_err());
    }

    #[test]
    fn parse_duration_overflow_is_error() {
        // u64::MAX hours would overflow when multiplied by 3600.
        assert!(parse_duration("18446744073709551615h").is_err());
    }
}
