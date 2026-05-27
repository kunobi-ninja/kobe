//! Integration test for the kobe-host-reaper binary.
//!
//! Gated by:
//!   - `#[cfg(target_os = "linux")]`   — Linux-only (requires /proc/self/mountinfo)
//!   - `#[ignore]`                     — opt-in via `cargo test -- --ignored`
//!   - `KOBE_REAPER_E2E=1`             — explicit env gate to avoid accidents
//!
//! Requires root or CAP_SYS_ADMIN (for `mount --bind`).
//! Apiserver GET is bypassed via `KOBE_REAPER_SKIP_GET=1`.
//!
//! Run with:
//!   KOBE_REAPER_E2E=1 cargo test --test reaper_integration -- --ignored

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

fn must_have_e2e() {
    if std::env::var("KOBE_REAPER_E2E").as_deref() != Ok("1") {
        panic!("set KOBE_REAPER_E2E=1 to run this test");
    }
}

#[test]
#[ignore]
fn stale_dir_is_unmounted_and_removed() {
    must_have_e2e();

    // ---- setup ----
    let lease_root = Path::new("/tmp/kobe-test/leases");
    let _ = std::fs::remove_dir_all("/tmp/kobe-test");
    std::fs::create_dir_all(lease_root.join("live-a")).unwrap();
    std::fs::create_dir_all(lease_root.join("stale-b/kubelets/x")).unwrap();
    std::fs::create_dir_all("/tmp/kobe-test/src").unwrap();

    // Bind-mount a path under stale-b so the reaper has something to unmount.
    let status = Command::new("mount")
        .args([
            "--bind",
            "/tmp/kobe-test/src",
            "/tmp/kobe-test/leases/stale-b/kubelets/x",
        ])
        .status()
        .expect("mount --bind");
    assert!(
        status.success(),
        "bind mount failed (need root or CAP_SYS_ADMIN)"
    );

    // Live-set file lists only live-a.
    std::fs::write("/tmp/kobe-test/live", "live-a\n").unwrap();

    // Age stale-b's mtime by 2 hours so it passes the mtime gate.
    let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
    let stamp = two_hours_ago.format("%Y%m%d%H%M.%S").to_string();
    let status = Command::new("touch")
        .args(["-t", &stamp, "/tmp/kobe-test/leases/stale-b"])
        .status()
        .expect("touch -t");
    assert!(status.success(), "touch -t failed");

    // Skip the apiserver GET so the test doesn't need a kubeconfig.
    // The subprocess inherits this via `.env()` on the Command below.

    // ---- invoke binary ----
    let status = Command::new(env!("CARGO_BIN_EXE_kobe-host-reaper"))
        .args([
            "--one-shot",
            "--lease-root",
            "/tmp/kobe-test/leases",
            "--live-set-path",
            "/tmp/kobe-test/live",
            "--mountinfo-path",
            "/proc/self/mountinfo",
            "--mtime-skip",
            "60s",
        ])
        .env("KOBE_REAPER_SKIP_GET", "1")
        .status()
        .expect("run kobe-host-reaper");
    assert!(status.success(), "reaper exit non-zero: {:?}", status);

    // ---- assertions ----
    assert!(
        lease_root.join("live-a").exists(),
        "live-a was removed (should be kept)"
    );
    assert!(
        !lease_root.join("stale-b").exists(),
        "stale-b was not removed by the reaper"
    );

    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
    assert!(
        !mounts.contains("/tmp/kobe-test/leases/stale-b/kubelets/x"),
        "bind mount still present in /proc/self/mounts after reaper run"
    );
}
