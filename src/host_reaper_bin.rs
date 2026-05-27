//! `kobe-host-reaper` — privileged DaemonSet entrypoint.
//! Runs an infinite sweep loop driven by the live-set ConfigMap and
//! /var/lib/kobe/leases/. See spec at
//! docs/superpowers/specs/2026-05-26-kobe-host-reaper-design.md
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
use reaper::{sweep::sweep_once, unmount::LibcUnmount};
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

    /// Log what would happen, don't act.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Path to mountinfo file (override for tests).
    #[arg(long, default_value = "/proc/self/mountinfo")]
    mountinfo_path: PathBuf,

    /// Run a single sweep tick and exit (test-only).
    #[arg(long, default_value_t = false)]
    one_shot: bool,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (n, suffix) = s.split_at(s.len() - 1);
    let n: u64 = n
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok(match suffix {
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        _ => return Err(format!("unknown duration suffix: {suffix}")),
    })
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
        dry_run = args.dry_run,
        one_shot = args.one_shot,
        "kobe-host-reaper starting"
    );

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

    loop {
        match sweep_once(
            &client,
            &args.lease_root,
            &args.live_set_path,
            args.mtime_skip,
            args.dry_run,
            &unmounter,
            &args.mountinfo_path,
        )
        .await
        {
            Ok(n) if n > 0 => info!(cleaned = n, "sweep tick done"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "sweep tick failed"),
        }
        if args.one_shot {
            break;
        }
        tokio::time::sleep(args.reconcile_interval).await;
    }
    Ok(())
}
