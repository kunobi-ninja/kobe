use std::sync::LazyLock;

use prometheus::{
    Encoder, HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder, register_histogram_vec,
    register_int_counter_vec, register_int_gauge_vec,
};

/// Pool state gauges — set at scrape time from shared pool state.
///
/// Labels: `profile` (e.g. "e2e-basic"), `state` (creating/ready/leased/unhealthy/recycling).
pub static POOL_CLUSTERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kunobi_clusters",
        "Number of clusters by profile and state",
        &["profile", "state"]
    )
    .unwrap()
});

/// Lease lifecycle counters.
///
/// Labels: `profile`, `event` (created_fast, created_queued, released, expired, extended).
pub static CLAIMS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kunobi_claims_total",
        "Claim lifecycle events",
        &["profile", "event"]
    )
    .unwrap()
});

/// Time to bind a lease (fast path only — slow path is asynchronous).
///
/// Labels: `profile`.
pub static CLAIM_BIND_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kunobi_claim_bind_duration_seconds",
        "Time to bind a claim to a vcluster (fast path)",
        &["profile"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .unwrap()
});

/// Pending leases per profile.
pub static QUEUE_DEPTH: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "kunobi_queue_depth",
        "Number of pending claims per profile",
        &["profile"]
    )
    .unwrap()
});

/// Health check result counters.
///
/// Labels: `profile`, `result` (pass, fail).
pub static HEALTH_CHECKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kunobi_health_checks_total",
        "Health check results",
        &["profile", "result"]
    )
    .unwrap()
});

/// Reconciliation counters.
///
/// Labels: `controller` (profile, lease), `result` (ok, error).
pub static RECONCILIATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kunobi_reconciliations_total",
        "Reconciliation loop runs",
        &["controller", "result"]
    )
    .unwrap()
});

/// Cluster provisioning method counters.
///
/// Labels: `profile`, `method` (fresh, restore).
pub static PROVISION_METHOD: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kunobi_provision_method_total",
        "Cluster provisioning method used",
        &["profile", "method"]
    )
    .unwrap()
});

/// Golden backup creation attempt counters.
///
/// Labels: `profile`, `result` (ok, error).
pub static GOLDEN_BACKUP_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kunobi_golden_backup_total",
        "Golden backup creation attempts",
        &["profile", "result"]
    )
    .unwrap()
});

/// Force all LazyLock statics to initialize, registering metrics
/// with the default Prometheus registry. Call once at startup.
pub fn init() {
    LazyLock::force(&POOL_CLUSTERS);
    LazyLock::force(&CLAIMS_TOTAL);
    LazyLock::force(&CLAIM_BIND_DURATION);
    LazyLock::force(&QUEUE_DEPTH);
    LazyLock::force(&HEALTH_CHECKS_TOTAL);
    LazyLock::force(&RECONCILIATIONS_TOTAL);
    LazyLock::force(&PROVISION_METHOD);
    LazyLock::force(&GOLDEN_BACKUP_TOTAL);
}

/// Encode all registered metrics in Prometheus text exposition format.
pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode metrics: {e}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!("Metrics output is not valid UTF-8: {e}");
        String::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: touch every metric so the Prometheus registry has something
    /// to emit. Gauges and counters only appear in gather() output after
    /// at least one observation.
    fn seed_metrics() {
        init();
        POOL_CLUSTERS.with_label_values(&["_test", "ready"]).set(0);
        CLAIMS_TOTAL
            .with_label_values(&["_test", "created_fast"])
            .inc();
        RECONCILIATIONS_TOTAL
            .with_label_values(&["_test", "ok"])
            .inc();
        PROVISION_METHOD
            .with_label_values(&["_test", "fresh"])
            .inc();
        GOLDEN_BACKUP_TOTAL
            .with_label_values(&["_test", "ok"])
            .inc();
    }

    /// Calling gather() after seeding metrics should return a non-empty
    /// string containing Prometheus text exposition output.
    #[test]
    fn test_gather_returns_string() {
        seed_metrics();
        let output = gather();
        assert!(
            !output.is_empty(),
            "gather() should return a non-empty string after seeding metrics"
        );
    }

    /// The gathered output must contain all key metric family names
    /// that the operator registers.
    #[test]
    fn test_gather_contains_expected_metrics() {
        seed_metrics();
        let output = gather();

        let expected = [
            "kunobi_clusters",
            "kunobi_claims_total",
            "kunobi_reconciliations_total",
            "kunobi_provision_method_total",
            "kunobi_golden_backup_total",
        ];

        for metric in &expected {
            assert!(
                output.contains(metric),
                "gather() output should contain metric '{metric}'"
            );
        }
    }

    /// Incrementing a counter should cause the metric to appear
    /// in the gathered output with its label values.
    #[test]
    fn test_metric_increment() {
        init();

        CLAIMS_TOTAL
            .with_label_values(&["test-profile", "created_fast"])
            .inc();

        let output = gather();
        assert!(
            output.contains("kunobi_claims_total"),
            "gather() should contain the kunobi_claims_total metric after increment"
        );
        assert!(
            output.contains("test-profile"),
            "gather() should contain the label value 'test-profile' after increment"
        );
    }
}
