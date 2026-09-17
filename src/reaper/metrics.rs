//! What the reaper reports about itself.
//!
//! The reaper runs on every node and deletes things as root, and until now the
//! only way to tell a healthy one from a wedged one was to exec into the node
//! and look. It kept exactly one counter, which nothing exposed, so it could
//! not be read even in principle.
//!
//! The design rule here is that **silence must not be ambiguous**. A reaper
//! with nothing to do and a reaper that died produce the same empty log, so
//! every tick stamps [`LAST_SWEEP_TIMESTAMP`] whether or not it changed
//! anything: absence of a heartbeat is then a real signal rather than the
//! normal case.
//!
//! The skip counters matter more than the reap counter. Reaping is the reaper
//! working; skipping is the reaper alive and *not* working, which is the state
//! that ends with a full disk or an exhausted cgroup hierarchy, and the state
//! that has no other symptom until something unrelated fails.

use prometheus::{
    Encoder, IntCounterVec, IntGauge, TextEncoder, register_int_counter_vec, register_int_gauge,
};
use std::sync::LazyLock;

/// Stale lease-root entries the sweep resolved, by what happened to them.
///
/// `outcome` is `reaped` or `skipped`; `reason` names the skip
/// (`apiserver_unreachable`, `live_set_lag`, `umount_failed`, `rm_failed`,
/// `dry_run`) and is `reaped` on the success arm, so every entry the sweep
/// looked at is counted exactly once and the two arms sum to the work done.
pub static ENTRIES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_reaper_entries_total",
        "Stale lease-root entries resolved by the reaper, by outcome and reason",
        &["outcome", "reason"]
    )
    .expect("register kobe_reaper_entries_total")
});

/// Empty container cgroups removed.
///
/// Separate from `ENTRIES_TOTAL` because it answers a different question: the
/// leak this drains is what exhausts the kernel cgroup hierarchy and makes
/// unrelated Pods fail to start with `no space left on device` on a node with
/// free disk. A rate that goes to zero while the node keeps recycling k3s
/// members is the shape of that failure returning.
pub static CGROUPS_REAPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_reaper_cgroups_reaped_total",
        "Empty container cgroup directories removed by the reaper",
        &["result"]
    )
    .expect("register kobe_reaper_cgroups_reaped_total")
});

/// Sweep ticks, by whether the tick itself completed.
///
/// A tick that returns an error deleted nothing, and the old code logged it and
/// moved on with `0`, which is indistinguishable from a tick with nothing to do.
pub static SWEEP_TICKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_reaper_sweep_ticks_total",
        "Reaper sweep ticks by sweep kind and result",
        &["kind", "result"]
    )
    .expect("register kobe_reaper_sweep_ticks_total")
});

/// Unix seconds at the end of the last completed tick.
///
/// The heartbeat. Alert on its age, not on its value: a reaper that stopped
/// looping, lost its apiserver, or died leaves this frozen, and nothing else
/// about a quiet reaper distinguishes those from a node with nothing to clean.
pub static LAST_SWEEP_TIMESTAMP: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "kobe_reaper_last_sweep_timestamp_seconds",
        "Unix timestamp of the end of the last completed reaper sweep tick"
    )
    .expect("register kobe_reaper_last_sweep_timestamp_seconds")
});

/// Age of the oldest stale entry still on disk after a tick, in seconds.
///
/// Zero when nothing is stale. This is the backlog: a reaper that skips every
/// entry keeps reporting ticks and a flat `reaped` count, and only this number
/// grows. It is measured after the tick, so it describes what was left behind
/// rather than what was found.
pub static OLDEST_STALE_AGE_SECONDS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "kobe_reaper_oldest_stale_age_seconds",
        "Age of the oldest stale lease-root entry still present after the last tick"
    )
    .expect("register kobe_reaper_oldest_stale_age_seconds")
});

/// Container cgroup directories present under the cgroup root after a tick.
///
/// The level, not the rate. `CGROUPS_REAPED_TOTAL` says the reaper is draining
/// the leak; this says whether draining is keeping up.
pub static CGROUPS_PRESENT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "kobe_reaper_cgroups_present",
        "Container cgroup directories under the cgroup root after the last tick"
    )
    .expect("register kobe_reaper_cgroups_present")
});

/// Register every family and seed the label sets the alerts need.
///
/// Forcing a labelled family registers it but emits no series: Prometheus
/// produces nothing for a label combination until it is observed, so an alert
/// on a skip reason that has not happened yet reads "no data" during exactly
/// the window it exists to cover. Seeding at zero makes each one live from
/// startup, and a seeded series that never moves is honest — it says that fault
/// has not occurred.
pub fn init() {
    for reason in SKIP_REASONS {
        ENTRIES_TOTAL
            .with_label_values(&["skipped", reason])
            .inc_by(0);
    }
    ENTRIES_TOTAL
        .with_label_values(&["reaped", "reaped"])
        .inc_by(0);
    for result in ["ok", "error"] {
        CGROUPS_REAPED_TOTAL.with_label_values(&[result]).inc_by(0);
        for kind in ["lease_root", "cgroups"] {
            SWEEP_TICKS_TOTAL
                .with_label_values(&[kind, result])
                .inc_by(0);
        }
    }
    LazyLock::force(&LAST_SWEEP_TIMESTAMP);
    LazyLock::force(&OLDEST_STALE_AGE_SECONDS);
    LazyLock::force(&CGROUPS_PRESENT);
}

/// Every skip reason the sweep can record.
///
/// Kept next to the seeding that consumes it and asserted against
/// [`crate::reaper::sweep::SkipReason`] in that module's tests, so a new reason
/// cannot be added without a seeded series to go with it.
pub const SKIP_REASONS: &[&str] = &[
    "apiserver_unreachable",
    "live_set_lag",
    "umount_failed",
    "rm_failed",
    "dry_run",
];

/// Render the default registry in Prometheus text format.
pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        tracing::error!(error = %e, "failed to encode reaper metrics");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!(error = %e, "reaper metrics output is not valid UTF-8");
        String::new()
    })
}
