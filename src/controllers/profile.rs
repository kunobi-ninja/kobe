use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backend::BackendFactory;
use crate::crd::{
    ClusterInstance, ClusterInstancePhase, ClusterInstanceStatus, ClusterLease, ClusterPool,
    ClusterPoolPhase, ClusterPoolStatus, LeasePhase, ResourceRef, SnapshotRefreshTrigger,
};
use crate::pool::{
    ClusterEntry, ClusterState, PoolAction, PoolState, compute_pool_actions, count_states,
    resolve_bootstrap_specs,
};
use crate::velero::VeleroCoordinator;

/// Shared state for the profile controller.
pub struct ProfileContext {
    pub client: Client,
    pub namespace: String,
    /// Per-profile pool state, shared with claim controller and API layer.
    pub pools: Arc<RwLock<HashMap<String, PoolState>>>,
    /// Optional Velero coordinator for golden backup/restore operations.
    pub velero: Option<VeleroCoordinator>,
    /// Optional backend factory for per-profile backend dispatch.
    /// When set, `backend_for(profile)` is used instead of `self.backend`
    /// for create/delete operations.
    pub factory: Option<BackendFactory>,
    /// Operator-level config that affects rendered backend resources
    /// (currently the kobe-sync sidecar image). Folded into
    /// `profile_spec_hash` so a sidecar bump triggers vkobe pool
    /// recycling automatically. See `pool::manager::RenderContext`.
    pub render_ctx: crate::pool::RenderContext,
    /// `(profile, generation)` pairs whose golden backup is currently being
    /// built. A golden backup runs for minutes and only records its generation
    /// on success, so without this guard every ~30s reconcile would respawn a
    /// duplicate task that races on the same temp cluster + Velero Backup name.
    pub golden_in_progress: Arc<std::sync::Mutex<std::collections::HashSet<(String, i64)>>>,
}

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    /// Quarantined capacity must never present as leasable: it must not map
    /// to `Ready` or `Leased`, or unproven capacity would be handed to the
    /// next caller.
    #[test]
    fn quarantined_never_maps_to_usable_capacity() {
        let state = cluster_state_from_phase(&ClusterInstancePhase::Quarantined);
        assert_ne!(state, ClusterState::Ready);
        assert_ne!(state, ClusterState::Leased);
    }
}

#[cfg(test)]
mod cluster_instance_tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn test_profile_context() -> (Arc<ProfileContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let pools = Arc::new(RwLock::new(HashMap::new()));

        let ctx = Arc::new(ProfileContext {
            client,
            namespace: "test-ns".to_string(),
            pools,
            velero: None,
            factory: None,
            render_ctx: crate::pool::RenderContext::with_kobe_sync_image("zondax/kobe-sync:test"),
            golden_in_progress: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        });
        (ctx, server)
    }

    fn make_test_profile(name: &str, min_size: u32, max_size: u32) -> Arc<ClusterPool> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "generation": 1
                },
                "spec": {
                    "minSize": min_size,
                    "maxSize": max_size,
                    "cluster": {
                        "version": "v1.28.0",
                        "serverCount": 1
                    },
                    "readinessGates": [],
                    "addons": []
                }
            }))
            .unwrap(),
        )
    }

    fn profile_with_status(status: serde_json::Value) -> ClusterPool {
        profile_with_status_named("p", status)
    }

    fn profile_with_status_named(name: &str, status: serde_json::Value) -> ClusterPool {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": { "name": name, "namespace": "test-ns" },
            "spec": {
                "minSize": 2, "maxSize": 5,
                "cluster": { "version": "v1.28.0", "serverCount": 1 },
                "readinessGates": [], "addons": []
            },
            "status": status
        }))
        .unwrap()
    }

    /// The instance controller routinely wins the first status write right
    /// after CREATE. Losing that optimistic race must not skip the initial
    /// status patch: `created_with` is written here and nowhere else, and a
    /// pool-managed instance without backend provenance is refused deletion
    /// fail-closed — a permanent recycle wedge, seen live in conformance.
    #[tokio::test]
    async fn initial_provenance_patch_retries_a_lost_optimistic_race() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let instances_api: Api<ClusterInstance> = Api::namespaced(client, "test-ns");
        let mut profile = (*make_test_profile("p", 1, 2)).clone();
        profile.metadata.uid = Some("pool-uid".into());

        let base = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances";
        let observed = |rv: &str| {
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "metadata": {
                    "name": "inst-1", "namespace": "test-ns",
                    "uid": "instance-uid", "resourceVersion": rv
                },
                "spec": { "poolRef": { "name": "p", "uid": "pool-uid" } }
            })
        };
        Mock::given(method("POST"))
            .and(path(base))
            .respond_with(ResponseTemplate::new(201).set_body_json(observed("1")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/inst-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(observed("2")))
            .mount(&server)
            .await;
        // First status write loses the race. The apiserver reports a failed
        // JSON-patch `test` op as 422 with EMPTY causes — not 409 — which is
        // exactly the live shape a 409-only retry sat out.
        Mock::given(method("PATCH"))
            .and(path(format!("{base}/inst-1/status")))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "Invalid", "code": 422,
                "message": "the server rejected our request due to an error in our request",
                "details": { "causes": [] }
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{base}/inst-1/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(observed("3")))
            .expect(1)
            .mount(&server)
            .await;

        ensure_cluster_instance(
            &instances_api,
            &profile,
            "inst-1",
            &crate::pool::RenderContext::with_kobe_sync_image("zondax/kobe-sync:test"),
            &std::collections::BTreeMap::new(),
            None,
        )
        .await
        .unwrap();

        let patches: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .collect();
        assert_eq!(patches.len(), 2, "the lost race must be retried");
        let body: serde_json::Value = serde_json::from_slice(&patches[1].body).unwrap();
        assert!(
            body[2]["value"]["createdWith"]["backend"].is_object(),
            "the landed status must carry backend provenance, got: {}",
            body[2]["value"]
        );
    }

    #[test]
    fn backoff_populates_last_failure_reason_when_failing() {
        // attempted up to index 3, only reached Ready at 1 → 2 failures.
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let pool_state = PoolState {
            clusters: HashMap::new(),
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
        assert!(backoff.consecutive_failures > 0);
        let reason = backoff
            .last_failure_reason
            .expect("last_failure_reason must be populated while failing");
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        assert!(reason.contains("pool=p"), "got: {reason}");
    }

    #[test]
    fn backoff_clears_last_failure_reason_on_recovery() {
        // Every attempted index has reached Ready → caught up → reason cleared.
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 0, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 3,
            "lastFailureReason": "stale reason"
        }));
        let pool_state = PoolState {
            clusters: HashMap::new(),
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
        assert_eq!(backoff.consecutive_failures, 0);
        assert!(backoff.last_failure_reason.is_none());
    }

    /// Minimal `ClusterEntry` for backoff/gauge tests, with `scheduling_blocked`
    /// configurable. Other fields are inert for these computations.
    fn entry_with_block(state: ClusterState, scheduling_blocked: bool) -> ClusterEntry {
        ClusterEntry {
            state,
            idle_since: None,
            health_failures: 0,
            state_since: None,
            spec_hash: None,
            scheduling_blocked,
            crashlooping: false,
            crash_message: None,
            cert_horizon_secs: None,
        }
    }

    #[test]
    fn oldest_quarantined_age_reads_only_quarantined_members() {
        let now = chrono::Utc::now();
        let at = |state, secs_ago: Option<i64>| ClusterEntry {
            state_since: secs_ago.map(|secs| now - chrono::Duration::seconds(secs)),
            ..entry_with_block(state, false)
        };
        let state = |entries: Vec<ClusterEntry>| PoolState {
            clusters: entries
                .into_iter()
                .enumerate()
                .map(|(index, entry)| (format!("c{index}"), entry))
                .collect(),
            queue_depth: 0,
        };

        assert_eq!(oldest_quarantined_age_secs(&state(vec![]), now), 0);
        let pool = state(vec![
            at(ClusterState::Leased, Some(9_000)),
            at(ClusterState::Quarantined, Some(600)),
            at(ClusterState::Quarantined, Some(3_600)),
            at(ClusterState::Quarantined, None),
        ]);
        assert_eq!(oldest_quarantined_age_secs(&pool, now), 3_600);
    }

    /// Guest-version guardrail: k8s ≤1.32 carries the ~23s fatal CSINode-init
    /// window; ≥1.33 (and non-1.x / unparseable) does not.
    #[test]
    fn guest_version_narrow_csinode_window_classification() {
        // The incident version and its neighbors.
        assert!(guest_version_has_narrow_csinode_window("v1.31.3+k3s1"));
        assert!(guest_version_has_narrow_csinode_window("v1.32.0-k3s1"));
        assert!(guest_version_has_narrow_csinode_window("1.28.9"));
        // Fixed upstream in 1.33.
        assert!(!guest_version_has_narrow_csinode_window("v1.33.13+k3s1"));
        assert!(!guest_version_has_narrow_csinode_window("v1.34.0"));
        // Unparseable / exotic → no advisory without evidence.
        assert!(!guest_version_has_narrow_csinode_window("latest"));
        assert!(!guest_version_has_narrow_csinode_window(""));
        assert!(!guest_version_has_narrow_csinode_window("v2.0.0"));

        // Parser corner cases.
        assert_eq!(guest_k8s_major_minor("v1.31.3+k3s1"), Some((1, 31)));
        assert_eq!(guest_k8s_major_minor("1.32"), Some((1, 32)));
        assert_eq!(guest_k8s_major_minor("v1.31+k0s.0"), Some((1, 31)));
        assert_eq!(guest_k8s_major_minor("v1..3"), None);
        assert_eq!(guest_k8s_major_minor("vx.y"), None);
    }

    /// #197 follow-up: a crashlooping member's captured crash message (incl.
    /// the distilled "last log" fatal line) is cited in the reason, so the
    /// lease-preflight 503 `detail` built from it answers *why* the pool is
    /// failing. Newest instance (highest name) wins when several crashloop.
    #[test]
    fn backoff_reason_cites_crashloop_evidence() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        let mut entry = entry_with_block(ClusterState::Creating, false);
        entry.crashlooping = true;
        entry.crash_message = Some(
            "guest server pod CrashLoopBackOff: Error exit 2 (x6); last log: \
             panic: Failed to initialize CSINode after retrying: timed out"
                .to_string(),
        );
        clusters.insert("pool-p-3".to_string(), entry);
        let mut older = entry_with_block(ClusterState::Creating, false);
        older.crashlooping = true;
        older.crash_message = Some("older crash".to_string());
        clusters.insert("pool-p-2".to_string(), older);
        let pool_state = PoolState {
            clusters,
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        let reason = backoff
            .last_failure_reason
            .expect("reason populated while failing");
        assert!(
            reason.contains("e.g. pool-p-3: guest server pod CrashLoopBackOff"),
            "expected crashloop evidence from the newest member, got: {reason}"
        );
        assert!(
            reason.contains("Failed to initialize CSINode"),
            "expected the distilled last-log line, got: {reason}"
        );
        assert!(!reason.contains("older crash"), "got: {reason}");
        // The generic triage pointer is still present.
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
    }

    /// #189 (observability): when the #191 scheduling-blocked backpressure is
    /// engaged, the reason string gains the `capacity-blocked:` wording so it's
    /// classifiable as `PoolFailureClass::Capacity`. This is a STRING-ONLY
    /// enrichment — the failure count (control-flow signal) is unchanged.
    #[test]
    fn backoff_reason_carries_capacity_wording_when_scheduling_blocked() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, true),
        );
        let pool_state = PoolState {
            clusters,
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        let reason = backoff
            .last_failure_reason
            .clone()
            .expect("reason populated while scheduling-blocked");
        assert!(
            reason.starts_with("capacity-blocked:"),
            "expected capacity wording, got: {reason}"
        );
        assert!(reason.contains("unschedulable"), "got: {reason}");
        // The original triage detail is preserved (only prefixed).
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        // The structural failure class reflects the capacity wedge.
        assert_eq!(
            backoff.failure_class,
            crate::metrics::PoolFailureClass::Capacity
        );
        // Control-flow signal (failure count) is still engaged, unchanged.
        assert!(backoff.consecutive_failures > 0);
    }

    /// A non-blocked failing pool produces the SAME backoff result it does
    /// today: no capacity wording, same failure count / reason content. Guards
    /// against the #189 string enrichment leaking into the non-blocked path.
    #[test]
    fn backoff_reason_unchanged_for_non_blocked_failing_pool() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, false),
        );
        let pool_state = PoolState {
            clusters,
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        let reason = backoff
            .last_failure_reason
            .expect("reason populated while failing");
        assert!(
            !reason.contains("capacity-blocked"),
            "non-blocked pool must not get capacity wording, got: {reason}"
        );
        assert!(reason.contains("not reaching Ready"), "got: {reason}");
        // Failure count is the plain index-gap (3 - 1 = 2), unchanged.
        assert_eq!(backoff.consecutive_failures, 2);
    }

    /// The generic (non-capacity) pool failure carries no attributable cause, so
    /// its structural `failure_class` MUST be `Other`.
    #[test]
    fn generic_failure_class_is_other() {
        let profile = profile_with_status(serde_json::json!({
            "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
        }));
        let mut clusters = HashMap::new();
        clusters.insert(
            "pool-p-0".to_string(),
            entry_with_block(ClusterState::Creating, false),
        );
        let pool_state = PoolState {
            clusters,
            queue_depth: 0,
        };
        let counts = crate::pool::manager::StateCounts::default();
        let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());

        assert_eq!(
            backoff.failure_class,
            crate::metrics::PoolFailureClass::Other
        );
    }

    /// The metric's `failure_class` is set STRUCTURALLY, so a pool whose NAME
    /// happens to contain a `from_reason` cause keyword must NOT be misclassified
    /// — even though the free-form reason text (which embeds the pool name) would
    /// trip that keyword if it were ever parsed. This is the general form of the
    /// `Unhealthy`→`health` collision: the reason string carries dynamic data and
    /// can never be a sound classification source.
    #[test]
    fn structural_failure_class_ignores_keyword_in_pool_name() {
        use crate::metrics::PoolFailureClass as P;
        // Each name embeds a distinct cause keyword; the generic failure class
        // must stay `Other` regardless, while `from_reason` on the same text
        // demonstrates the collision the structural approach avoids.
        let cases = [
            ("health-pool", P::Health),
            ("create-pool", P::BackendCreate),
            ("bootstrap-pool", P::Bootstrap),
            ("delete-pool", P::BackendDelete),
            ("ipam-pool", P::Ipam),
        ];
        for (name, collided) in cases {
            let profile = profile_with_status_named(
                name,
                serde_json::json!({
                    "consecutiveFailures": 2, "maxAttemptedIndex": 3, "lastReadyMaxIndex": 1
                }),
            );
            let mut clusters = HashMap::new();
            clusters.insert(
                format!("pool-{name}-0"),
                entry_with_block(ClusterState::Creating, false),
            );
            let pool_state = PoolState {
                clusters,
                queue_depth: 0,
            };
            let counts = crate::pool::manager::StateCounts::default();
            let backoff = compute_backoff_state(&profile, &pool_state, &counts, chrono::Utc::now());
            let reason = backoff
                .last_failure_reason
                .as_deref()
                .expect("reason populated while failing");

            // The string classifier WOULD mislabel it (documents the hazard)…
            assert_eq!(
                P::from_reason(reason),
                collided,
                "expected the string classifier to collide on name {name}"
            );
            // …but the structural class the metric actually uses is correct.
            assert_eq!(
                backoff.failure_class,
                P::Other,
                "structural class must ignore pool-name keyword for {name}"
            );
        }
    }

    /// `persisted_failure_class` recovers a prior reconcile's class from the
    /// capacity marker ONLY — never by keyword-parsing the free-form text, so a
    /// pool named with a cause keyword is still recovered as `Other`.
    #[test]
    fn persisted_failure_class_recovers_via_marker_not_keywords() {
        use crate::metrics::PoolFailureClass as P;
        assert_eq!(persisted_failure_class(None), P::Other);
        assert_eq!(
            persisted_failure_class(Some(
                "capacity-blocked: 2 instance(s) unschedulable; 2 instance(s) not reaching Ready"
            )),
            P::Capacity
        );
        // Generic reason — even one whose pool name embeds a keyword — is `Other`.
        assert_eq!(
            persisted_failure_class(Some(
                "2 instance(s) not reaching Ready ... kubectl get ci -l \
                 kobe.kunobi.ninja/pool=health-pool ..."
            )),
            P::Other
        );
    }

    /// The reason-change counter fires on a class TRANSITION even when the
    /// failure count is unchanged (`Other`→`Capacity` at the same count), but not
    /// on steady-state failure at an unchanged class.
    #[test]
    fn reason_change_counter_fires_on_class_transition_at_equal_count() {
        use crate::metrics::PoolFailureClass as P;
        crate::metrics::init();
        let counter = &crate::metrics::POOL_FAILURE_REASON_CHANGES_TOTAL;
        let profile = "xition-test-pool";

        // Steady state: same count, same class → no increment.
        let before_other = counter.with_label_values(&[profile, "other"]).get();
        emit_pool_failure_metrics(
            profile,
            &PoolFailureSignals {
                consecutive_failures: 2,
                prev_failures: 2,
                failure_class: P::Other,
                prev_failure_class: P::Other,
            },
        );
        assert_eq!(
            counter.with_label_values(&[profile, "other"]).get(),
            before_other,
            "unchanged class at unchanged count must not re-count"
        );

        // Class flip Other→Capacity at the SAME count → one increment on capacity.
        let before_cap = counter.with_label_values(&[profile, "capacity"]).get();
        emit_pool_failure_metrics(
            profile,
            &PoolFailureSignals {
                consecutive_failures: 2,
                prev_failures: 2,
                failure_class: P::Capacity,
                prev_failure_class: P::Other,
            },
        );
        assert_eq!(
            counter.with_label_values(&[profile, "capacity"]).get(),
            before_cap + 1,
            "a class transition at equal count must be counted"
        );
    }

    /// #189 (observability): the `kobe_pool_capacity_blocked` gauge reflects the
    /// presence of any scheduling-blocked instance in pool_state — 0 when none,
    /// 1 when present. Read-only mirror of the #191 backpressure signal.
    #[test]
    fn pool_capacity_blocked_gauge_reflects_scheduling_blocked_presence() {
        crate::metrics::init();
        let g = &crate::metrics::POOL_CAPACITY_BLOCKED;

        // No blocked instances → 0.
        let none = [
            entry_with_block(ClusterState::Ready, false),
            entry_with_block(ClusterState::Creating, false),
        ];
        let blocked_none = none.iter().any(|e| e.scheduling_blocked);
        g.with_label_values(&["gauge-test-none"])
            .set(i64::from(blocked_none));
        assert_eq!(g.with_label_values(&["gauge-test-none"]).get(), 0);

        // Any blocked instance → 1.
        let some = [
            entry_with_block(ClusterState::Ready, false),
            entry_with_block(ClusterState::Creating, true),
        ];
        let blocked_some = some.iter().any(|e| e.scheduling_blocked);
        g.with_label_values(&["gauge-test-some"])
            .set(i64::from(blocked_some));
        assert_eq!(g.with_label_values(&["gauge-test-some"]).get(), 1);
    }

    fn instance_response_json(
        name: &str,
        pool: &str,
        phase: ClusterInstancePhase,
        idle_since: Option<&str>,
        health_failures: u32,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "labels": {
                    "kobe.kunobi.ninja/pool": pool
                }
            },
            "spec": {
                "poolRef": {
                    "name": pool
                }
            },
            "status": {
                "phase": phase,
                "provisioned": true,
                "leaseRef": null,
                "idleSince": idle_since,
                "stateSince": "2026-04-13T10:00:00Z",
                "healthFailures": health_failures,
                "specHash": "002a000000000000"
            }
        })
    }

    #[tokio::test]
    async fn test_error_policy_returns_requeue_60s() {
        let (ctx, _server) = test_profile_context().await;
        let profile = make_test_profile("err-profile", 2, 5);
        let error = ProfileError::Lifecycle(anyhow::anyhow!("test error"));
        let action = error_policy(profile, &error, ctx);
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_build_pool_state_uses_cluster_instances() {
        let (ctx, server) = test_profile_context().await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    instance_response_json(
                        "pool-test-profile-0",
                        "test-profile",
                        ClusterInstancePhase::Ready,
                        Some("2026-04-13T10:01:00Z"),
                        0,
                    ),
                    instance_response_json(
                        "pool-test-profile-1",
                        "test-profile",
                        ClusterInstancePhase::Creating,
                        None,
                        0,
                    ),
                ]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;

        assert_eq!(pool_state.clusters.len(), 2);
        assert_eq!(
            pool_state.clusters["pool-test-profile-0"].state,
            ClusterState::Ready
        );
        assert_eq!(
            pool_state.clusters["pool-test-profile-1"].state,
            ClusterState::Creating
        );
    }

    #[tokio::test]
    async fn ready_with_reservation_handle_is_not_claimable_capacity() {
        let (ctx, server) = test_profile_context().await;
        let mut stale_binding = instance_response_json(
            "pool-test-profile-0",
            "test-profile",
            ClusterInstancePhase::Ready,
            None,
            0,
        );
        stale_binding["status"]["binding"] = serde_json::json!({
            "bindingId": "binding-old",
            "lease": { "name": "lease-old", "uid": "lease-old-uid" },
            "instance": {
                "name": "pool-test-profile-0",
                "uid": "instance-uid",
                "observedGeneration": 1
            },
            "pool": { "name": "test-profile", "uid": "pool-uid" },
            "backend": {
                "type": "k3s",
                "configDigest": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "instanceSpecDigest": "002a000000000000"
        });

        let mut stale_lease_ref = instance_response_json(
            "pool-test-profile-1",
            "test-profile",
            ClusterInstancePhase::Ready,
            None,
            0,
        );
        stale_lease_ref["status"]["leaseRef"] =
            serde_json::json!({ "name": "lease-old", "uid": "lease-old-uid" });

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![stale_binding, stale_lease_ref]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;
        let counts = count_states(&pool_state, None);

        assert_eq!(counts.ready, 0);
        assert_eq!(counts.quarantined, 2);
        assert!(
            pool_state
                .clusters
                .values()
                .all(|entry| entry.state == ClusterState::Quarantined),
            "a Ready instance with either reservation handle must fail closed"
        );
    }

    const INSTANCE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-test-profile-0";

    /// Serve `status` as the fresh on-disk instance and record every status
    /// PATCH body sent back.
    async fn mount_instance(
        server: &MockServer,
        status: serde_json::Value,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> {
        let body = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "pool-test-profile-0",
                "namespace": "test-ns",
                "uid": "instance-uid",
                "resourceVersion": "20"
            },
            "spec": { "poolRef": { "name": "test-profile" } },
            "status": status
        });
        Mock::given(method("GET"))
            .and(path(INSTANCE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(server)
            .await;
        let patched = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let sink = patched.clone();
        Mock::given(method("PATCH"))
            .and(path(format!("{INSTANCE_PATH}/status")))
            .respond_with(move |req: &wiremock::Request| {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                    sink.lock().unwrap().push(v);
                }
                ResponseTemplate::new(200).set_body_json(body.clone())
            })
            .mount(server)
            .await;
        patched
    }

    fn writes_to(ops: &serde_json::Value, target: &str) -> bool {
        ops.as_array().unwrap().iter().any(|op| {
            op["op"] != "test"
                && op["path"]
                    .as_str()
                    .is_some_and(|p| p == target || p.starts_with(&format!("{target}/")))
        })
    }

    /// The end-of-reconcile write must never revert a transition another
    /// controller made after the pool snapshot.
    ///
    /// The snapshot says Ready. Since then the instance controller failed
    /// the health check and moved it to Recycling, after which it deletes
    /// the backend. The pool used to copy the snapshot phase back, turning
    /// it into a leasable Ready instance with no backend. Now the only
    /// thing it may write at the end of a reconcile is a missing
    /// `specHash`.
    #[tokio::test]
    async fn end_of_reconcile_write_never_reverts_a_newer_phase() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({
                "phase": "Recycling",
                "stateSince": "2026-04-13T10:05:00Z",
                "provisioned": true
            }),
        )
        .await;

        backfill_spec_hashes(
            &ctx.client,
            "test-ns",
            &[("pool-test-profile-0".to_string(), "hash-new".to_string())],
        )
        .await;

        let writes = patched.lock().unwrap().clone();
        assert_eq!(writes.len(), 1, "the missing hash is still backfilled");
        let ops = &writes[0];
        assert!(
            !writes_to(ops, "/status/phase")
                && !writes_to(ops, "/status/stateSince")
                && !writes_to(ops, "/status/idleSince"),
            "the pool must not write phase or timers at end of reconcile: {ops}"
        );
        assert!(
            ops.as_array().unwrap().iter().any(|op| op["op"] == "add"
                && op["path"] == "/status/specHash"
                && op["value"] == "hash-new"),
            "expected a specHash add, got: {ops}"
        );
    }

    /// A hash already on disk is never replaced by the backfill.
    #[tokio::test]
    async fn spec_hash_backfill_leaves_an_existing_hash_alone() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({
                "phase": "Creating",
                "specHash": "hash-on-disk",
                "stateSince": "2026-04-13T10:05:00Z"
            }),
        )
        .await;

        backfill_spec_hashes(
            &ctx.client,
            "test-ns",
            &[("pool-test-profile-0".to_string(), "hash-other".to_string())],
        )
        .await;

        assert!(patched.lock().unwrap().is_empty());
    }

    /// A new instance whose initial status write was lost has no
    /// `stateSince`, and the stuck-Creating timeout only fires on an instance
    /// that has one. The backfill starts that clock, fenced on the version it
    /// read, and leaves an existing hash alone.
    #[tokio::test]
    async fn backfill_stamps_a_missing_state_since() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({ "phase": "Creating", "specHash": "hash-on-disk" }),
        )
        .await;

        backfill_spec_hashes(
            &ctx.client,
            "test-ns",
            &[("pool-test-profile-0".to_string(), "hash-other".to_string())],
        )
        .await;

        let writes = patched.lock().unwrap().clone();
        assert_eq!(writes.len(), 1, "a missing stateSince is backfilled");
        let ops = writes[0].as_array().unwrap();
        assert!(ops.iter().any(|op| op["op"] == "test"
            && op["path"] == "/metadata/resourceVersion"
            && op["value"] == "20"));
        assert!(
            ops.iter()
                .any(|op| op["op"] == "add" && op["path"] == "/status/stateSince"),
            "expected a stateSince add, got: {ops:?}"
        );
        assert!(!writes_to(&writes[0], "/status/specHash"));
        assert!(!writes_to(&writes[0], "/status/phase"));
    }

    /// With no status at all, the backfill writes both the hash and the
    /// clock, so the instance can still time out of `Creating`.
    #[tokio::test]
    async fn backfill_without_status_writes_hash_and_state_since() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(&server, serde_json::Value::Null).await;

        backfill_spec_hashes(
            &ctx.client,
            "test-ns",
            &[("pool-test-profile-0".to_string(), "hash-new".to_string())],
        )
        .await;

        let writes = patched.lock().unwrap().clone();
        assert_eq!(writes.len(), 1);
        let status = writes[0]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["path"] == "/status")
            .map(|op| op["value"].clone())
            .expect("a whole-status add");
        assert_eq!(status["specHash"], "hash-new");
        assert!(status["stateSince"].is_string(), "{status}");
    }

    /// A recycle decided against a stale snapshot must not land.
    ///
    /// The pool picked this member while it was Ready; by the time the
    /// status write runs, the instance controller has already moved it on.
    #[tokio::test]
    async fn recycle_mark_skips_an_instance_that_moved_on_since_the_snapshot() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({ "phase": "Unhealthy", "stateSince": "2026-04-13T10:05:00Z" }),
        )
        .await;

        let wrote = mark_instance_recycling(
            &ctx.client,
            "test-ns",
            "pool-test-profile-0",
            ClusterState::Ready,
        )
        .await
        .unwrap();

        assert!(!wrote);
        assert!(patched.lock().unwrap().is_empty());
    }

    /// A lease that reserved the instance after the snapshot owns it now.
    /// Recycling it would take a cluster away from a tenant.
    #[tokio::test]
    async fn recycle_mark_skips_an_instance_that_took_a_lease_mid_reconcile() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({
                "phase": "Leased",
                "leaseRef": { "name": "lease-abc123def456" },
                "stateSince": chrono::Utc::now().to_rfc3339()
            }),
        )
        .await;

        let wrote = mark_instance_recycling(
            &ctx.client,
            "test-ns",
            "pool-test-profile-0",
            ClusterState::Ready,
        )
        .await
        .unwrap();

        assert!(!wrote);
        assert!(patched.lock().unwrap().is_empty());
    }

    /// The recycle write is fenced on the phase it read and touches only the
    /// fields the pool owns for that transition.
    #[tokio::test]
    async fn recycle_mark_tests_the_from_phase_and_writes_only_its_own_fields() {
        let (ctx, server) = test_profile_context().await;
        let patched = mount_instance(
            &server,
            serde_json::json!({
                "phase": "Ready",
                "idleSince": "2026-04-13T10:01:00Z",
                "stateSince": "2026-04-13T10:00:00Z",
                "provisioned": true,
                "healthFailures": 2,
                "specHash": "hash-old"
            }),
        )
        .await;

        let wrote = mark_instance_recycling(
            &ctx.client,
            "test-ns",
            "pool-test-profile-0",
            ClusterState::Ready,
        )
        .await
        .unwrap();

        assert!(wrote);
        let writes = patched.lock().unwrap().clone();
        assert_eq!(writes.len(), 1);
        let ops = writes[0].as_array().unwrap();
        let has = |op: &str, path: &str| {
            ops.iter()
                .find(|o| o["op"] == op && o["path"] == path)
                .map(|o| o["value"].clone())
        };
        assert_eq!(has("test", "/metadata/uid"), Some("instance-uid".into()));
        assert_eq!(has("test", "/metadata/resourceVersion"), Some("20".into()));
        assert_eq!(has("test", "/status/phase"), Some("Ready".into()));
        assert_eq!(has("replace", "/status/phase"), Some("Recycling".into()));
        assert!(has("add", "/status/stateSince").is_some());
        assert!(has("remove", "/status/idleSince").is_some());
        assert!(
            ops.iter().all(|o| o["path"] != "/status"),
            "must not replace the whole status: {ops:?}"
        );
    }

    /// Queue depth must count *unmet* demand only.
    ///
    /// A `Pending` lease that already carries a `clusterName` has had an
    /// instance reserved for it — the lease controller recognises that
    /// state and repairs it to `Bound`. Counting it as queued demand
    /// during the reserve → patch-status window makes the pool
    /// provision a replacement for a claim that is already served. The same
    /// holds for a `Pending` lease that has written `status.binding` but not
    /// yet `clusterName`.
    #[tokio::test]
    async fn queue_depth_excludes_pending_leases_that_already_hold_a_cluster() {
        let (ctx, server) = test_profile_context().await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        let lease = |name: &str, phase: &str, cluster: serde_json::Value| {
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": name, "namespace": "test-ns" },
                "spec": { "poolRef": "test-profile", "ttl": "1h",
                          "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": phase, "clusterName": cluster }
            })
        };
        // Reserved an instance and is waiting to bind it: `binding` is set,
        // `clusterName` is not (it is only written at Bound).
        let mut reserving = lease("reserving", "Pending", serde_json::json!(null));
        reserving["status"]["binding"] = serde_json::json!({
            "bindingId": "binding-1",
            "lease": { "name": "reserving", "uid": "lease-uid" },
            "instance": {
                "name": "pool-test-profile-2",
                "uid": "instance-uid",
                "observedGeneration": 1
            },
            "pool": { "name": "test-profile", "uid": "pool-uid" },
            "backend": {
                "type": "k3s",
                "configDigest": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "instanceSpecDigest": "002a000000000000"
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    // Genuinely queued — nothing reserved yet.
                    lease("waiting", "Pending", serde_json::json!(null)),
                    // Already reserved, mid two-phase bind. Not demand.
                    lease(
                        "assigned",
                        "Pending",
                        serde_json::json!("pool-test-profile-0"),
                    ),
                    // Reserved via binding, mid-bind. Not demand.
                    reserving,
                    // Bound and Expired are not demand either.
                    lease("bound", "Bound", serde_json::json!("pool-test-profile-1")),
                    lease("expired", "Expired", serde_json::json!(null)),
                ]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;

        assert_eq!(
            pool_state.queue_depth, 1,
            "only the unreserved Pending lease is unmet demand"
        );
    }

    #[tokio::test]
    async fn test_build_pool_state_preserves_instance_status_fields() {
        let (ctx, server) = test_profile_context().await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .and(query_param(
                "labelSelector",
                "kobe.kunobi.ninja/pool=test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![instance_response_json(
                    "pool-test-profile-0",
                    "test-profile",
                    ClusterInstancePhase::Leased,
                    Some("2026-04-13T10:01:00Z"),
                    2,
                )]),
            ))
            .mount(&server)
            .await;

        let pool_state = build_pool_state(&ctx, "test-profile").await;
        let entry = pool_state.clusters.get("pool-test-profile-0").unwrap();
        assert_eq!(entry.state, ClusterState::Leased);
        assert_eq!(entry.health_failures, 2);
        assert_eq!(entry.spec_hash.as_deref(), Some("002a000000000000"));
        assert!(entry.idle_since.is_some());
    }
}

/// Error type for the profile controller.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] anyhow::Error),
}

/// Start the profile reconciler controller.
pub async fn run_profile_controller(
    client: Client,
    namespace: &str,
    pools: Arc<RwLock<HashMap<String, PoolState>>>,
    velero: Option<VeleroCoordinator>,
    factory: Option<BackendFactory>,
    render_ctx: crate::pool::RenderContext,
    shutdown: CancellationToken,
) {
    let profiles: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);

    let ctx = Arc::new(ProfileContext {
        client: client.clone(),
        namespace: namespace.to_string(),
        pools,
        velero,
        factory,
        render_ctx,
        golden_in_progress: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
    });

    info!("Starting profile controller");

    let controller = Controller::new(profiles, Config::default())
        .owns(instances, Config::default())
        .owns(leases, Config::default());
    // A deleted pool is never reconciled again; prune its gauges against the
    // controller's own view of which pools exist.
    let pool_store = controller.store();
    let controller = controller
        .run(reconcile_profile, error_policy, ctx)
        .for_each(move |result| {
            let live: std::collections::HashSet<String> = pool_store
                .state()
                .iter()
                .map(|pool| pool.name_any())
                .collect();
            crate::metrics::prune_quarantine_gauges(&live);
            async move {
                match result {
                    Ok((obj, _action)) => {
                        crate::metrics::RECONCILIATIONS_TOTAL
                            .with_label_values(&["profile", "ok"])
                            .inc();
                        debug!(profile = %obj.name, "Profile reconciled");
                    }
                    Err(e) => {
                        crate::metrics::RECONCILIATIONS_TOTAL
                            .with_label_values(&["profile", "error"])
                            .inc();
                        error!("Profile reconciliation error: {e:?}");
                    }
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Profile controller shutting down");
        },
    }
}

/// Main reconciliation logic for a ClusterPool.
///
/// 1. Build current pool state from cluster observations
/// 2. Evaluate readiness gates and discovery health for Creating clusters
/// 3. Compute desired actions via pool manager (scale up/down)
/// 4. Execute actions (create/delete clusters)
/// 5. Update profile status
#[tracing::instrument(skip_all, fields(profile = %profile.name_any()))]
async fn reconcile_profile(
    profile: Arc<ClusterPool>,
    ctx: Arc<ProfileContext>,
) -> Result<Action, ProfileError> {
    let name = profile.name_any();
    // The timer's Drop records `error` for every early `?` return. Keeping
    // it here makes the full reconcile path observable without manually
    // instrumenting each exit.
    let reconcile_timer =
        crate::metrics::Timer::start(&crate::metrics::POOL_RECONCILE_DURATION, [name.as_str()]);
    let ns = profile.namespace().unwrap_or_else(|| ctx.namespace.clone());

    info!(profile = %name, "Reconciling profile");

    // Build current pool state
    let mut pool_state = build_pool_state(&ctx, &name).await;

    // Check if golden backup needs rebuilding on profile spec change.
    if let (Some(velero), Some(snapshot)) = (&ctx.velero, &profile.spec.snapshot)
        && snapshot.enabled
        && let SnapshotRefreshTrigger::ProfileChange = snapshot.refresh_on
    {
        let profile_gen = profile.metadata.generation.unwrap_or(1);
        let golden_gen = profile
            .status
            .as_ref()
            .and_then(|s| s.golden_generation)
            .unwrap_or(0);

        if profile_gen > golden_gen {
            // Skip if a backup for this generation is already running. The guard
            // is released by the spawned task on completion (success OR failure).
            // status.goldenGeneration is only written on success, so without this
            // every ~30s reconcile during the multi-minute backup would respawn a
            // duplicate task racing on the same temp cluster + Velero Backup name.
            let key = (name.clone(), profile_gen);
            let newly_started = ctx.golden_in_progress.lock().unwrap().insert(key.clone());
            if !newly_started {
                debug!(
                    profile = %name,
                    generation = profile_gen,
                    "Golden backup already in progress for this generation, not respawning"
                );
            } else {
                info!(
                    profile = %name,
                    profile_generation = profile_gen,
                    golden_generation = golden_gen,
                    "Profile generation changed, triggering golden backup rebuild"
                );

                let velero = velero.clone();
                let snapshot = snapshot.clone();
                let profile_name = name.clone();
                let spec = profile.spec.clone();
                let backend = if let Some(ref f) = ctx.factory {
                    f.backend_for(&profile)?
                } else {
                    crate::backend::BackendDispatch::K3s(crate::backend::K3sBackend::new(
                        ctx.client.clone(),
                        Default::default(),
                    ))
                };
                let client = ctx.client.clone();
                let ns = ns.clone();
                let in_progress = ctx.golden_in_progress.clone();

                tokio::spawn(async move {
                    let generation = profile_gen;
                    match velero
                        .create_golden_backup(&profile_name, &spec, &backend, &snapshot, generation)
                        .await
                    {
                        Ok(backup_name) => {
                            info!(
                                profile = %profile_name,
                                backup = %backup_name,
                                generation = profile_gen,
                                "Golden backup created successfully"
                            );

                            crate::metrics::GOLDEN_BACKUP_TOTAL
                                .with_label_values(&[profile_name.as_str(), "ok"])
                                .inc();

                            let profiles_api: Api<ClusterPool> =
                                Api::namespaced(client.clone(), &ns);
                            let status_patch = serde_json::json!({
                                "status": {
                                    "goldenBackup": backup_name,
                                    "goldenGeneration": profile_gen,
                                }
                            });
                            if let Err(e) = profiles_api
                                .patch_status(
                                    &profile_name,
                                    &PatchParams::apply("kobe-operator"),
                                    &Patch::Merge(&status_patch),
                                )
                                .await
                            {
                                error!(
                                    profile = %profile_name,
                                    error = %e,
                                    "Failed to patch profile status with golden backup info"
                                );
                            }

                            if let Err(e) = velero
                                .cleanup_old_backups(&profile_name, &snapshot, generation)
                                .await
                            {
                                warn!(
                                    profile = %profile_name,
                                    error = %e,
                                    "Failed to clean up old golden backups"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                profile = %profile_name,
                                error = %e,
                                "Failed to create golden backup"
                            );
                            crate::metrics::GOLDEN_BACKUP_TOTAL
                                .with_label_values(&[profile_name.as_str(), "error"])
                                .inc();
                        }
                    }

                    // Release the guard so a later generation (or a retry after
                    // failure) can rebuild.
                    in_progress.lock().unwrap().remove(&key);
                });
            }
        }
    }

    let now = chrono::Utc::now();

    // Resolve every BootstrapConfig CR this pool references so the
    // hash captures their CONTENT, not just their names. A user
    // editing a bootstrap (new flux install manifest, different
    // shell script, …) without touching the pool spec would
    // otherwise silently apply only to NEW pool members, leaving
    // existing idle ones running stale logic. Failures here are
    // logged and skipped — a missing bootstrap maps to an
    // "<unresolved>" sentinel inside the hasher, so the hash flips
    // deterministically rather than depending on whether the lookup
    // happened to succeed at this exact reconcile.
    let bootstrap_specs = resolve_bootstrap_specs(&ctx.client, &ns, &profile).await;

    // #19 recycle-before-expiry: for kobe-managed-PKI backends, read
    // per-instance cert horizons (also emits the `kobe_cert_expiry_seconds`
    // gauge) and stamp them BEFORE evaluation, so this reconcile's actions
    // already treat in-horizon members as drifted (surge-replace, recycle
    // unclaimed soonest-expiry-first, never leased — the standard drift
    // machinery). Skipped entirely for self-managed-PKI backends
    // (k3s/k0s/capi): no `{name}-certs` Secret exists, so probing would only
    // add per-member API calls to the reconcile path.
    if matches!(
        profile.spec.backend.backend_type,
        crate::crd::BackendType::Vkobe | crate::crd::BackendType::Vcluster
    ) {
        let cert_horizons =
            collect_and_emit_cert_expiry(&ctx.client, &ns, &name, &pool_state).await;
        for (cluster_name, entry) in pool_state.clusters.iter_mut() {
            let Some(horizon) = cert_horizons.get(cluster_name) else {
                continue;
            };
            entry.cert_horizon_secs = Some(*horizon);
            if entry.cert_expiring() {
                warn!(
                    profile = %name,
                    cluster = %cluster_name,
                    horizon_days = horizon / 86_400,
                    "instance PKI certificate within the recycle-before-expiry \
                     horizon; scheduling drift-style recycle (#19)"
                );
            }
        }
    }

    // Computed ONCE per reconcile and threaded to every consumer — the drift
    // comparison below and both stamp sites. Recomputing it independently at
    // each site would risk stamped != compared, which recycles every member on
    // every reconcile forever (bounded only by `maxRecycling`). One value
    // cannot disagree with itself.
    //
    // `None` whenever no factory is configured or the backend has no
    // fingerprint, which leaves the hash exactly as it was before #149.
    let render_fingerprint: Option<String> = ctx
        .factory
        .as_ref()
        .and_then(|factory| factory.backend_for(&profile).ok())
        .and_then(|backend| {
            use crate::backend::ClusterBackend;
            backend.render_fingerprint(&profile.spec.cluster)
        });

    // Fields the pool sets that its backend would ignore. Such a pool gets no
    // new members until the spec is fixed; see `hold_unsupported_config`.
    let unsupported_fields = crate::backend::unsupported_pool_fields(&profile.spec);
    if !unsupported_fields.is_empty() {
        warn!(
            profile = %name,
            fields = ?unsupported_fields,
            "Pool sets fields its backend ignores; not creating members"
        );
    }

    let actions = hold_unsupported_config(
        compute_pool_actions(
            &profile,
            &pool_state,
            now,
            &ctx.render_ctx,
            &bootstrap_specs,
            render_fingerprint.as_deref(),
        ),
        &unsupported_fields,
    );

    // Check whether the backend datastore is degraded. When kine/etcd
    // is OOMKilling or in a restart loop, every new ClusterInstance we
    // create will fail to bootstrap (apiserver lease writes time out
    // → kube-controller-manager loses its lease → flux install hangs
    // → BackoffLimitExceeded → recycle), and the recycle adds more
    // load to the already-broken backend. Refusing to spawn new
    // instances breaks that cycle. Other actions (Delete, Recycle of
    // already-failed instances) still proceed so we don't strand
    // resources.
    //
    // `None` means OK-to-create; `Some(reason)` means halt creates for this
    // reconcile. The reason is LOGGED only — it is deliberately NOT written into
    // `ClusterPool.status` and does NOT feed the pool-failure metrics: a
    // degraded datastore is not a per-pool provision failure, and it already has
    // its own first-class signal (`kobe_kobestore_healthy`, emitted by
    // `controllers::kobestore_health`, which is also the condition this reads
    // from). Folding it into `consecutiveFailures`/`failure_class` would double-
    // count a cluster-wide outage as N pool failures and perturb backoff/phase.
    let backend_block = pool_creation_blocked_by_backend(&ctx.client, &ns, &profile).await;
    if let Some(ref reason) = backend_block {
        warn!(profile = %name, reason = %reason,
              "Pool creates paused: backend datastore is degraded");
    }

    // Instances created this reconcile, with the hash they were stamped
    // with, so a lost initial status write can be backfilled below.
    let mut created: Vec<(String, String)> = Vec::new();
    for action in &actions {
        match action {
            PoolAction::Create(cluster_name) => {
                if let Some(ref reason) = backend_block {
                    debug!(
                        profile = %name, cluster = %cluster_name,
                        reason = %reason,
                        "Skipping Create: backend datastore degraded"
                    );
                    continue;
                }
                info!(profile = %name, cluster = %cluster_name, "Creating cluster");
                let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ns);
                ensure_cluster_instance(
                    &instances_api,
                    &profile,
                    cluster_name,
                    &ctx.render_ctx,
                    &bootstrap_specs,
                    render_fingerprint.as_deref(),
                )
                .await?;
                let spec_hash = crate::pool::profile_spec_hash(
                    &profile,
                    &ctx.render_ctx,
                    &bootstrap_specs,
                    render_fingerprint.as_deref(),
                );
                created.push((cluster_name.clone(), spec_hash.clone()));
                pool_state.clusters.insert(
                    cluster_name.clone(),
                    ClusterEntry {
                        state: ClusterState::Creating,
                        idle_since: None,
                        health_failures: 0,
                        state_since: Some(chrono::Utc::now()),
                        spec_hash: Some(spec_hash),
                        // Freshly created — it hasn't had a chance to report a
                        // scheduling block or crashloop yet; build_pool_state
                        // recomputes both from status.message next reconcile.
                        scheduling_blocked: false,
                        crashlooping: false,
                        crash_message: None,
                        cert_horizon_secs: None,
                    },
                );
            }
            PoolAction::Delete(cluster_name, reason) => {
                info!(
                    profile = %name, cluster = %cluster_name, reason = reason.as_str(),
                    "Recycling cluster"
                );
                // The snapshot state this decision was made against. The
                // status write below only lands if the instance is still in
                // it, so a transition another controller made since the
                // snapshot is never overwritten.
                let Some(expected) = pool_state.clusters.get(cluster_name).map(|e| e.state) else {
                    continue;
                };
                match mark_instance_recycling(&ctx.client, &ns, cluster_name, expected).await {
                    Ok(true) => {
                        crate::metrics::INSTANCE_RECYCLES_TOTAL
                            .with_label_values(&[name.as_str(), reason.as_str()])
                            .inc();
                        if let Some(entry) = pool_state.clusters.get_mut(cluster_name) {
                            entry.state = ClusterState::Recycling;
                        }
                    }
                    Ok(false) => {
                        debug!(
                            profile = %name, cluster = %cluster_name,
                            "Skipping recycle: instance changed since the pool snapshot"
                        );
                    }
                    Err(err) => {
                        warn!(
                            profile = %name, cluster = %cluster_name, error = %err,
                            "Failed to mark cluster Recycling; next reconcile will retry"
                        );
                    }
                }
            }
        }
    }

    ctx.pools
        .write()
        .await
        .insert(name.clone(), pool_state.clone());
    backfill_spec_hashes(&ctx.client, &ns, &created).await;

    // Phase metrics here only need the base state taxonomy — pass
    // `None` for `current_hash` so the drift-aware buckets stay 0.
    // `compute_pool_actions` above does its own hash-aware count.
    let counts = count_states(&pool_state, None);

    // Phase 3 state gauges: per-pool size by dimension.
    // `min`/`max` come from the spec; the rest are observed phase
    // counts. Single emit per reconcile, capacity ~10 series per pool
    // — well within Prometheus's comfort zone.
    let pool_size_set = |dim: &str, val: u32| {
        crate::metrics::POOL_SIZE
            .with_label_values(&[name.as_str(), dim])
            .set(val as i64);
    };
    // `desired` is the size target (legacy field) OR the scaling.min_ready
    // floor. `max` is unset for non-scaling pools (gauge stays at default).
    pool_size_set("desired", profile.spec.size);
    if let Some(scaling) = profile.spec.scaling.as_ref() {
        pool_size_set("min", scaling.min_ready);
        pool_size_set("max", scaling.max_clusters);
    }
    pool_size_set("creating", counts.creating);
    pool_size_set("ready", counts.ready);
    pool_size_set("leased", counts.leased);
    pool_size_set("unhealthy", counts.unhealthy);
    pool_size_set("recycling", counts.recycling);
    // Emitted separately from `unhealthy` so an alert can distinguish capacity
    // that is churning from capacity that is stuck holding unproven state.
    // A rising `quarantined` means teardown evidence is failing, which no
    // other dimension reveals.
    pool_size_set("quarantined", counts.quarantined);
    crate::metrics::QUARANTINED
        .with_label_values(&[name.as_str(), "instance"])
        .set(counts.quarantined as i64);
    crate::metrics::QUARANTINED_OLDEST_AGE_SECONDS
        .with_label_values(&[name.as_str()])
        .set(oldest_quarantined_age_secs(&pool_state, chrono::Utc::now()));

    // Surface hidden CPU over-reservation (issue #189): a pool that sets
    // `resources.limits` with empty `requests` makes the kubelet copy each
    // limit into the request, reserving the full limit on every guest pod
    // (server AND agent). This silently wedged ci-k3s-kunobi (8c → 16/cluster).
    // Meter the effective CPU request and warn so it's visible before the
    // nodes saturate.
    let (effective_cpu_millicores, effective_memory_bytes) =
        if let Some(res) = profile.spec.resources.as_ref() {
            let defaulted = res.limits_without_requests();
            if !defaulted.is_empty() {
                warn!(
                    profile = %name,
                    keys = ?defaulted,
                    "ClusterPool sets resource limits without explicit requests; \
                     Kubernetes reserves the full limit as the request on every guest \
                     pod (server + agent). Set spec.resources.requests to avoid silent \
                     over-reservation."
                );
            }
            (
                res.effective_cpu_millicores().unwrap_or(0),
                res.effective_memory_bytes().unwrap_or(0),
            )
        } else {
            (0, 0)
        };
    crate::metrics::POOL_EFFECTIVE_CPU_REQUEST_MILLICORES
        .with_label_values(&[name.as_str()])
        .set(effective_cpu_millicores);
    crate::metrics::POOL_EFFECTIVE_MEMORY_REQUEST_BYTES
        .with_label_values(&[name.as_str()])
        .set(effective_memory_bytes);

    // Guest-version guardrail (2026-07-20 incident): a guest k8s ≤1.32 kubelet
    // has only a ~23s FATAL CSINode-init retry window; nested containerd
    // cold-start can exceed it, panicking the guest server/agent into a
    // crashloop. k8s 1.33 widened the window to ~140s. kobe can't patch the
    // kubelet, so for old versions the posture is: (a) this warning + the
    // `kobe_pool_guest_version_advisory` gauge, and (b) the built-in
    // mitigation of an emptyDir-backed guest data dir, which makes each
    // restart resume (warm state) instead of replaying the race from zero.
    let narrow_window = guest_version_has_narrow_csinode_window(&profile.spec.cluster.version);
    if narrow_window {
        warn!(
            profile = %name,
            guest_version = %profile.spec.cluster.version,
            "guest Kubernetes ≤1.32 has a ~23s fatal CSINode-init window: slow \
             nested-containerd cold starts can panic-crashloop guest pods \
             (2026-07-20 ci-k3s-kunobi incident). Upgrade spec.cluster.version \
             to >= v1.33 (window widened to ~140s). Until then the emptyDir \
             data-dir mitigation limits the blast to self-healing restarts."
        );
    }
    crate::metrics::POOL_GUEST_VERSION_ADVISORY
        .with_label_values(&[name.as_str(), "narrow_csinode_window"])
        .set(i64::from(narrow_window));

    // #189 (observability): surface "this pool is wedged on capacity" derived
    // from the existing #191 scheduling-blocked state. 1 when any instance is
    // scheduling-blocked (guest Pods unschedulable), else 0. Read-only mirror
    // of the backpressure signal — it does NOT gate admission or alter any
    // create/recycle/backoff decision.
    let capacity_blocked = pool_state.clusters.values().any(|e| e.scheduling_blocked);
    crate::metrics::POOL_CAPACITY_BLOCKED
        .with_label_values(&[name.as_str()])
        .set(i64::from(capacity_blocked));

    // Same value the warm target was computed against in
    // `build_pool_state` — reused rather than re-LISTed so the status
    // and metric can never disagree with the scale-up decision.
    //
    // One consequence of counting it there: if the ClusterInstance LIST
    // fails, `build_pool_state` bails early and this reports 0 rather
    // than the true depth. That is a degraded reconcile either way (the
    // pool state it would act on is empty), and it recovers on the next
    // pass — but the queueDepth metric does read 0 for that interval.
    let queue_depth = pool_state.queue_depth;

    crate::metrics::QUEUE_DEPTH
        .with_label_values(&[&name])
        .set(queue_depth as i64);

    let profiles_api: Api<ClusterPool> = Api::namespaced(ctx.client.clone(), &ns);

    let (existing_golden_backup, existing_golden_generation) = profile
        .status
        .as_ref()
        .map(|s| (s.golden_backup.clone(), s.golden_generation))
        .unwrap_or((None, None));

    let existing_golden_template_db = profile
        .status
        .as_ref()
        .and_then(|s| s.golden_template_db.clone());

    let backoff = compute_backoff_state(&profile, &pool_state, &counts, now);

    // Snapshot the P0 pool-failure observability inputs BEFORE `backoff` is
    // partially moved into `ClusterPoolStatus` below. `prev_failures` comes
    // from the pre-reconcile status so the reason-change counter fires only on
    // the rising edge; `failure_class` is the bounded class decided
    // structurally in `compute_backoff_state` (never parsed from the free-form
    // reason text). Emitted after the status patch.
    let pool_failure_signals = PoolFailureSignals {
        consecutive_failures: backoff.consecutive_failures,
        prev_failures: profile
            .status
            .as_ref()
            .map(|s| s.consecutive_failures)
            .unwrap_or(0),
        failure_class: backoff.failure_class,
        prev_failure_class: persisted_failure_class(
            profile
                .status
                .as_ref()
                .and_then(|s| s.last_failure_reason.as_deref()),
        ),
    };

    // An unsupported spec reports `Failing`: it needs operator attention, and
    // the lease pre-flight already refuses a `Failing` pool with nothing Ready
    // while still serving any Ready members it has.
    let phase = if unsupported_fields.is_empty() {
        crate::pool::manager::compute_pool_phase(
            &profile,
            &counts,
            queue_depth,
            backoff.consecutive_failures,
            backoff.next_attempt_at.as_deref(),
            now,
        )
    } else {
        crate::crd::ClusterPoolPhase::Failing
    };

    let conditions = pool_conditions(
        profile
            .status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default(),
        config_supported_condition(&profile.spec.backend.backend_type, &unsupported_fields),
        now,
    );

    let status = ClusterPoolStatus {
        conditions,
        phase: Some(phase),
        ready: counts.ready,
        leased: counts.leased,
        creating: counts.creating,
        recycling: counts.recycling,
        unhealthy: counts.unhealthy,
        quarantined: counts.quarantined,
        queue_depth,
        golden_backup: existing_golden_backup,
        golden_generation: existing_golden_generation,
        golden_template_db: existing_golden_template_db,
        consecutive_failures: backoff.consecutive_failures,
        next_attempt_at: backoff.next_attempt_at,
        last_failure_reason: backoff.last_failure_reason,
        max_attempted_index: backoff.max_attempted_index,
        last_ready_max_index: backoff.last_ready_max_index,
    };

    let patch = serde_json::json!({ "status": status });
    let written = profiles_api
        .patch_status(
            &name,
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await;
    match written {
        Ok(_) => {}
        // The installed CRD predates `Exhausted` and its enum rejects it.
        // Helm does not upgrade `crds/`, so this happens whenever the operator
        // is upgraded before the CRDs are applied. Write the phase older
        // builds report for the same state rather than freezing the whole
        // pool status on every reconcile.
        Err(kube::Error::Api(error))
            if error.code == 422 && status.phase == Some(ClusterPoolPhase::Exhausted) =>
        {
            warn!(
                profile = %name,
                "ClusterPool CRD rejects phase Exhausted; reporting ScalingUp. Apply the chart's CRDs"
            );
            let mut fallback = status;
            fallback.phase = Some(ClusterPoolPhase::ScalingUp);
            let patch = serde_json::json!({ "status": fallback });
            profiles_api
                .patch_status(
                    &name,
                    &PatchParams::apply("kobe-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;
        }
        Err(error) => return Err(error.into()),
    }

    // P0 observability: pool failure gauge + reason-change edge counter.
    // Emitted after the status patch so the gauge mirrors the value we just
    // persisted (signals snapshotted above before `backoff` was consumed).
    emit_pool_failure_metrics(&name, &pool_failure_signals);

    reconcile_timer.finish("ok");
    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// Pre-extracted inputs for the P0 pool-failure metrics, captured before the
/// `BackoffState` is partially moved into `ClusterPoolStatus`.
struct PoolFailureSignals {
    consecutive_failures: u32,
    prev_failures: u32,
    failure_class: crate::metrics::PoolFailureClass,
    prev_failure_class: crate::metrics::PoolFailureClass,
}

/// Emit the P0 pool-failure observability signals for one reconcile.
///
/// - `kobe_pool_consecutive_failures{profile}` — gauge set to the current
///   `consecutive_failures`.
/// - `kobe_pool_failure_reason_changes_total{profile, failure_class}` —
///   incremented on a *new failure edge* (`new > prev`) OR a *class transition
///   while still failing* (e.g. `Other`→`Capacity` when a wedge becomes visible
///   without the count rising). Steady-state failures at an unchanged class
///   aren't re-counted, so this stays a "something changed" signal rather than a
///   reconcile-frequency counter. `failure_class` is the bounded
///   [`crate::metrics::PoolFailureClass`] set structurally on `BackoffState`
///   where the cause is known — never parsed from the reason string.
fn emit_pool_failure_metrics(profile: &str, signals: &PoolFailureSignals) {
    crate::metrics::POOL_CONSECUTIVE_FAILURES
        .with_label_values(&[profile])
        .set(signals.consecutive_failures as i64);

    let new_failure_edge = signals.consecutive_failures > signals.prev_failures;
    let class_transition =
        signals.consecutive_failures > 0 && signals.failure_class != signals.prev_failure_class;
    if new_failure_edge || class_transition {
        crate::metrics::POOL_FAILURE_REASON_CHANGES_TOTAL
            .with_label_values(&[profile, signals.failure_class.as_str()])
            .inc();
    }
}

/// Build pool state from ClusterInstance inventory.
/// Parse the guest Kubernetes `(major, minor)` out of a cluster version
/// string as kobe accepts them: `v1.31.3+k3s1`, `v1.33.13-k3s1`, `1.32.0`,
/// `v1.31.3+k0s.0`, … Returns `None` for anything it can't confidently parse
/// (callers must then make no version-based claims).
fn guest_k8s_major_minor(version: &str) -> Option<(u32, u32)> {
    let v = version.trim().trim_start_matches('v');
    let mut parts = v.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    // Minor may be followed by a patch (`.3+k3s1`) or carry a suffix directly
    // (`1.31+k3s1`); stop at the first non-digit.
    let minor_raw = parts.next()?;
    let digits: String = minor_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    Some((major, digits.parse().ok()?))
}

/// True when the guest kubelet carries the ~23s fatal CSINode-init retry
/// window (k8s ≤1.32; csi_plugin.go backoff 6 steps/15ms/×6). k8s 1.33
/// widened it to ~140s (30ms/×8), which is what makes nested cold starts
/// safe. Unparseable versions return `false` — no advisory without evidence.
fn guest_version_has_narrow_csinode_window(version: &str) -> bool {
    matches!(guest_k8s_major_minor(version), Some((1, minor)) if minor <= 32)
}

async fn build_pool_state(ctx: &ProfileContext, profile_name: &str) -> PoolState {
    info!(
        profile = profile_name,
        "Refreshing pool state from ClusterInstances"
    );

    let ns = &ctx.namespace;
    let mut clusters = HashMap::new();
    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), ns);
    let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/pool={profile_name}"));
    let instances = match instances_api.list(&lp).await {
        Ok(list) => list,
        Err(e) => {
            warn!(
                profile = profile_name,
                "Failed to list ClusterInstances during pool rebuild: {e}"
            );
            return PoolState {
                clusters,
                queue_depth: 0,
            };
        }
    };

    for instance in &instances {
        let cluster_name = instance.name_any();
        let status = instance.status.clone().unwrap_or_default();
        let state = pool_state_from_status(&status);

        // #189: a Creating instance whose backend reported its guest Pods are
        // Unschedulable stamps a known prefix on `status.message`. Surface it
        // as `scheduling_blocked` so the pool manager holds it (backpressure)
        // instead of recycling it on the creating-timeout. Only meaningful
        // while Creating — a Ready/Leased instance has long since scheduled.
        let scheduling_blocked = state == ClusterState::Creating
            && status.message.as_deref().is_some_and(|m| {
                m.starts_with(crate::pool::manager::SCHEDULING_BLOCKED_MESSAGE_PREFIX)
            });

        // #197: a Creating instance whose backend reported its guest container
        // is crashlooping carries the CRASHLOOP marker in `status.message`.
        // Surface it as `crashlooping` so the stuck-Creating recycle is
        // *labelled* `CrashLooping` — but, unlike scheduling_blocked, it is NOT
        // held: a crashlooper still recycles on the creating-timeout as before.
        // Only meaningful while Creating.
        let crashlooping = state == ClusterState::Creating
            && status
                .message
                .as_deref()
                .is_some_and(|m| m.contains(crate::pool::manager::CRASHLOOP_MESSAGE_MARKER));

        debug!(
            profile = profile_name,
            cluster = %cluster_name,
            ?state,
            scheduling_blocked,
            crashlooping,
            "Discovered cluster from ClusterInstance"
        );

        clusters.insert(
            cluster_name,
            ClusterEntry {
                state,
                idle_since: parse_optional_time(status.idle_since.as_deref()),
                health_failures: status.health_failures,
                state_since: parse_optional_time(status.state_since.as_deref()),
                spec_hash: status.spec_hash,
                scheduling_blocked,
                crashlooping,
                // Carry the evidence (crash message incl. the distilled "last
                // log" line) so `compute_backoff_state` can cite it in the
                // pool's `lastFailureReason` instead of a bare pointer to
                // kubectl.
                crash_message: crashlooping.then(|| status.message.clone()).flatten(),
                cert_horizon_secs: None,
            },
        );
    }

    let queue_depth = count_pending_claims(ctx, profile_name).await;

    info!(
        profile = profile_name,
        discovered = clusters.len(),
        queue_depth,
        "Pool state refreshed from ClusterInstances"
    );

    PoolState {
        clusters,
        queue_depth,
    }
}

/// Seconds since the longest-quarantined member entered quarantine, or 0.
/// A member without a parseable `stateSince` counts as just entered: the age
/// is a lower bound, never invented.
fn oldest_quarantined_age_secs(state: &PoolState, now: chrono::DateTime<chrono::Utc>) -> i64 {
    state
        .clusters
        .values()
        .filter(|entry| entry.state == ClusterState::Quarantined)
        .map(|entry| {
            entry
                .state_since
                .map(|since| (now - since).num_seconds().max(0))
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
}

/// Count claims queued against `profile_name` — `Pending` leases that
/// do not yet hold a cluster, i.e. demand nothing has been reserved for.
///
/// A `Pending` lease is already served, and must not count, when it
/// carries either handle of a reservation:
///
/// - `status.binding`: the lease reserved an instance and is waiting to
///   bind it. `clusterName` is only set at `Bound`, so without this check
///   every reservation in flight is counted as demand.
/// - `status.clusterName`: the window between `reserve_ready_instance`
///   claiming an instance and the lease's status patch landing, which the
///   lease controller repairs to `Bound` on sight.
///
/// Counting either as demand would make the pool provision a second
/// cluster for the same claim.
///
/// Feeds both the warm target in [`crate::pool::manager::compute_pool_actions`]
/// (so a scale-to-zero pool provisions on demand) and the pool's
/// `queueDepth` status/metric, which is why it is read once per
/// reconcile rather than at each use site.
///
/// Best-effort: a failed LIST reports 0 rather than failing the
/// reconcile. Under-reporting only delays scale-up to the next pass,
/// whereas failing here would block every other pool action.
///
/// Also sets `kobe_quarantined{kind="lease"}` from the same LIST, so the
/// gauge costs no extra request. A failed LIST leaves it at its last value.
async fn count_pending_claims(ctx: &ProfileContext, profile_name: &str) -> u32 {
    let leases_api: Api<ClusterLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/profile={profile_name}"));
    match leases_api.list(&lp).await {
        Ok(leases) => {
            let quarantined = leases
                .iter()
                .filter(|lease| {
                    lease.status.as_ref().map(|status| &status.phase)
                        == Some(&LeasePhase::Quarantined)
                })
                .count();
            crate::metrics::QUARANTINED
                .with_label_values(&[profile_name, "lease"])
                .set(quarantined as i64);
            count_queued(&leases.items)
        }
        Err(e) => {
            warn!(profile = %profile_name, "Failed to list leases for queue depth: {e:?}");
            0
        }
    }
}

/// Leases that are queued demand; see [`count_pending_claims`].
fn count_queued(leases: &[ClusterLease]) -> u32 {
    leases
        .iter()
        .filter(|c| {
            // A lease with no status yet has certainly not been
            // reserved against, so it counts as demand.
            c.status
                .as_ref()
                .map(|s| {
                    s.phase == LeasePhase::Pending
                        && s.cluster_name.is_none()
                        && s.binding.is_none()
                })
                .unwrap_or(true)
        })
        .count() as u32
}

/// Returns `Some(reason)` when the pool's backend datastore (a)
/// `KobeStore`, currently only relevant for vkobe pools) is in a
/// `Healthy=False` state, so the profile controller should refuse to
/// create new ClusterInstances against it. `None` means either the
/// pool doesn't reference a KobeStore (k3s/k0s/CAPI) or the backend
/// is healthy / unknown / unevaluated.
///
/// Why not just always check the KobeStore? For vkobe pools we look
/// up `profile.spec.backend.vkobe.data_store_ref.name` and read its
/// status. For non-vkobe pools, the concept doesn't apply, so we skip.
///
/// Why "Unknown" doesn't block: the `Unknown` state is what the health
/// controller writes for externally-managed KobeStores it can't
/// observe. Blocking creates against external stores would be a
/// regression — the operator has no basis to claim they're degraded.
async fn pool_creation_blocked_by_backend(
    client: &Client,
    namespace: &str,
    profile: &ClusterPool,
) -> Option<String> {
    let store_name = profile
        .spec
        .backend
        .vkobe
        .as_ref()
        .map(|v| v.data_store_ref.name.clone())?;

    let stores: Api<crate::crd::KobeStore> = Api::namespaced(client.clone(), namespace);
    let store = stores.get(&store_name).await.ok()?;
    crate::controllers::kobestore_health::unhealthy_reason(&store)
}

/// Condition type reporting whether the pool's backend honors its spec.
const CONFIG_SUPPORTED: &str = "ConfigSupported";

/// Drop the actions that would act on a spec the backend cannot honor.
///
/// With `unsupported` non-empty, no member is created and no member is
/// recycled for spec drift: the edit that introduced the unsupported field
/// would otherwise drain Ready members with nothing to replace them. Every
/// other recycle (unhealthy, timeouts, scale-down, released leases) still
/// runs.
fn hold_unsupported_config(actions: Vec<PoolAction>, unsupported: &[&str]) -> Vec<PoolAction> {
    if unsupported.is_empty() {
        return actions;
    }
    actions
        .into_iter()
        .filter(|action| match action {
            PoolAction::Create(_) => false,
            PoolAction::Delete(_, reason) => *reason != crate::metrics::RecycleReason::SpecDrift,
        })
        .collect()
}

/// The `ConfigSupported` condition for a pool, without a transition time.
fn config_supported_condition(
    backend: &crate::crd::BackendType,
    unsupported: &[&str],
) -> crate::crd::ClusterPoolCondition {
    let (status, reason, message) = if unsupported.is_empty() {
        ("True", "AllFieldsSupported", String::new())
    } else {
        (
            "False",
            "UnsupportedFields",
            format!(
                "backend {} ignores {}; remove them or pick a backend that \
                 supports them. No new members are created until then.",
                format!("{backend:?}").to_lowercase(),
                unsupported.join(", ")
            ),
        )
    };
    crate::crd::ClusterPoolCondition {
        condition_type: CONFIG_SUPPORTED.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: None,
    }
}

/// Merge `condition` into the pool's previous conditions.
///
/// Conditions of other types are kept as they are. `lastTransitionTime`
/// carries over while the status is unchanged and is set to `now` when it
/// flips.
fn pool_conditions(
    previous: &[crate::crd::ClusterPoolCondition],
    mut condition: crate::crd::ClusterPoolCondition,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<crate::crd::ClusterPoolCondition> {
    let prior = previous
        .iter()
        .find(|c| c.condition_type == condition.condition_type);
    condition.last_transition_time = match prior {
        Some(p) if p.status == condition.status && p.last_transition_time.is_some() => {
            p.last_transition_time.clone()
        }
        _ => Some(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    };
    let mut conditions: Vec<_> = previous
        .iter()
        .filter(|c| c.condition_type != condition.condition_type)
        .cloned()
        .collect();
    conditions.push(condition);
    conditions
}

fn error_policy(
    _profile: Arc<ClusterPool>,
    error: &ProfileError,
    _ctx: Arc<ProfileContext>,
) -> Action {
    error!("Profile reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(60))
}

async fn ensure_cluster_instance(
    instances_api: &Api<ClusterInstance>,
    profile: &ClusterPool,
    cluster_name: &str,
    render_ctx: &crate::pool::RenderContext,
    bootstrap_specs: &std::collections::BTreeMap<String, crate::crd::BootstrapConfigSpec>,
    render_fingerprint: Option<&str>,
) -> Result<(), ProfileError> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/pool".to_string(), profile.name_any());

    // Stamp provenance on the initial status. `created_with` is set
    // here once and never overwritten — every subsequent
    // `patch_instance_status` constructs a fresh status with
    // `created_with: None` (via `..Default::default()`). Its fenced full-status
    // writer copies this field from the observed object before replacement;
    // this controller's own writer does the same after a fresh GET. See the
    // field doc comment in `crd::instance::ClusterInstanceStatus`.
    //
    // `kobe_sync_image` is stamped only for vkobe pools — other
    // backends don't run the sync sidecar, so the field would be
    // misleading noise.
    //
    // We read `BUILD_VERSION` (stamped by `build.rs` from the
    // CI-injected env var, falling back to `CARGO_PKG_VERSION` then
    // `"dev"`), NOT `CARGO_PKG_VERSION` directly. `Cargo.toml` keeps
    // `version = "0.0.0"` as a deliberate placeholder so the same
    // workspace builds for every release tag without manual edits;
    // CI sets `BUILD_VERSION=v0.17.0` (etc.) to override. Reading
    // `CARGO_PKG_VERSION` here would always stamp `"0.0.0"`, defeating
    // the entire point of provenance. Same env var that
    // `kobe --version` prints, so the two surfaces stay in sync.
    let pool_uid = profile
        .metadata
        .uid
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ClusterPool {} has no UID", profile.name_any()))?;
    let backend_provenance = crate::crd::BackendProvenance::from_config(&profile.spec.backend)
        .map_err(|err| anyhow::anyhow!("failed to encode backend provenance: {err}"))?;
    let provenance = crate::crd::ClusterInstanceProvenance {
        operator_version: env!("BUILD_VERSION").to_string(),
        // Record what this instance is about to create, while we still know.
        // Recomputing this at teardown would read whatever the pool config says
        // *then* — so a pool that stopped setting `registryMirrors` after this
        // instance was built would silently drop that ConfigMap from the plan
        // and never verify it. Only k3s can be verified, so only k3s gets a
        // plan; anything else stays `None` and is refused a receipt-required
        // lease at bind time.
        teardown_plan: matches!(
            profile.spec.backend.backend_type,
            crate::crd::BackendType::K3s
        )
        .then(|| {
            crate::crd::k3s_teardown_plan(
                &profile.spec.cluster,
                profile.spec.backend.datastore.is_some(),
            )
        }),
        kobe_sync_image: matches!(
            profile.spec.backend.backend_type,
            crate::crd::BackendType::Vkobe
        )
        .then(|| render_ctx.kobe_sync_image.clone()),
        // Pin the backend that created this instance so future
        // delete / health / addon dispatches use the right backend
        // even after a pool-level backend migration.
        backend_type: Some(profile.spec.backend.backend_type.clone()),
        pool_uid: Some(pool_uid.clone()),
        backend: Some(backend_provenance),
    };

    let initial_status = ClusterInstanceStatus {
        phase: ClusterInstancePhase::Creating,
        provisioned: false,
        bootstrapped: false,
        lease_ref: None,
        active_bootstrap: None,
        idle_since: None,
        state_since: Some(chrono::Utc::now().to_rfc3339()),
        health_failures: 0,
        spec_hash: Some(crate::pool::profile_spec_hash(
            profile,
            render_ctx,
            bootstrap_specs,
            render_fingerprint,
        )),
        created_with: Some(provenance),
        ..Default::default()
    };

    let instance = ClusterInstance {
        metadata: kube::core::ObjectMeta {
            name: Some(cluster_name.to_string()),
            namespace: profile.namespace(),
            labels: Some(labels),
            owner_references: profile.controller_owner_ref(&()).map(|owner| vec![owner]),
            ..Default::default()
        },
        spec: crate::crd::ClusterInstanceSpec {
            pool_ref: Some(ResourceRef {
                name: profile.name_any(),
                uid: Some(pool_uid),
            }),
            backend: None,
            cluster: None,
            addons: Vec::new(),
            bootstraps: Vec::new(),
            health_check: None,
            readiness_gates: Vec::new(),
            snapshot: None,
        },
        // The status field set here is silently dropped by the apiserver —
        // status is a subresource and only `patch_status` / `update_status`
        // persist it. We follow up with an explicit status patch below so the
        // initial spec_hash is actually written, instead of staying `None`
        // until the next reconcile sync (which previously could overwrite
        // with `None` if in-memory pool_state lost the entry across an
        // operator restart). See drift detection in
        // `pool::compute_pool_actions`.
        status: Some(initial_status.clone()),
    };

    let created = match instances_api.create(&Default::default(), &instance).await {
        Ok(_) => true,
        Err(kube::Error::Api(ae)) if ae.code == 409 => false,
        Err(e) => return Err(ProfileError::Kube(e)),
    };

    if created {
        // Retried on optimistic 409s: the instance controller routinely wins
        // the first status write right after CREATE, and losing that race
        // must not skip this patch — `created_with` is written here and
        // nowhere else (the post-create backfill writes only `spec_hash` and
        // a missing `stateSince`), and a pool-managed instance without
        // backend provenance is refused deletion fail-closed, wedging recycle
        // permanently.
        let mut attempts = 0;
        let patch_result = loop {
            attempts += 1;
            let attempt = async {
                let observed = instances_api.get(cluster_name).await?;
                let uid = observed.metadata.uid.as_deref().ok_or_else(|| {
                    kube::Error::Service(Box::new(std::io::Error::other("instance has no UID")))
                })?;
                let rv = observed.resource_version().ok_or_else(|| {
                    kube::Error::Service(Box::new(std::io::Error::other(
                        "instance has no resourceVersion",
                    )))
                })?;
                let mut status = match observed.status {
                    Some(status) => status,
                    None => initial_status.clone(),
                };
                // The instance controller may win immediately after CREATE. Start
                // from that fresh status and fill only the profile-owned immutable
                // provenance; never roll provisioning/bootstrap state back to the
                // initial Creating snapshot under a newer resourceVersion.
                if status.spec_hash.is_none() {
                    status.spec_hash = initial_status.spec_hash.clone();
                }
                if status.created_with.is_none() {
                    status.created_with = initial_status.created_with.clone();
                }
                let patch = crate::controllers::lease::json_patch(serde_json::json!([
                    { "op": "test", "path": "/metadata/uid", "value": uid },
                    { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
                    { "op": "add", "path": "/status", "value": status }
                ]));
                instances_api
                    .patch_status(
                        cluster_name,
                        &PatchParams::default(),
                        &Patch::<()>::Json(patch),
                    )
                    .await?;
                Ok::<(), kube::Error>(())
            }
            .await;
            match attempt {
                // A failed `test` op arrives as 422-with-empty-causes, not
                // 409 — proven live when the first shipped retry (409-only)
                // sat out the exact race it existed for.
                Err(ref error)
                    if crate::controllers::lease::optimistic_conflict(error) && attempts < 5 =>
                {
                    continue;
                }
                other => break other,
            }
        };
        if let Err(err) = patch_result {
            // The end-of-reconcile backfill (`backfill_spec_hashes`) makes one
            // more attempt at `spec_hash` and `stateSince`. Nothing retries
            // `created_with`, so log loudly: an instance without it is refused
            // deletion until an operator repairs it.
            warn!(
                cluster = %cluster_name,
                error = %err,
                "Failed to write initial status after create; end-of-reconcile backfill retries spec_hash and stateSince only"
            );
        }
    }

    Ok(())
}

/// The pool's view of an instance, derived from its status.
///
/// `Ready` counts as claimable only when both reciprocal reservation handles
/// are absent. If either survives a stale status write, the member fails
/// closed as `Quarantined` so it is neither advertised nor recycled.
fn pool_state_from_status(status: &ClusterInstanceStatus) -> ClusterState {
    if status.phase == ClusterInstancePhase::Ready
        && (status.lease_ref.is_some() || status.binding.is_some())
    {
        ClusterState::Quarantined
    } else {
        cluster_state_from_phase(&status.phase)
    }
}

/// Move an instance to `Recycling` for a [`PoolAction::Delete`].
///
/// This is the only phase the pool controller writes on an existing
/// instance. Every other transition belongs to the instance or lease
/// controller. The pool decided to recycle against a snapshot taken
/// seconds earlier, so the write only lands if a fresh read still shows
/// the instance in `expected` with no lease handle. The JSON patch then
/// tests the uid, resourceVersion and phase it read, and changes only
/// `phase`, `stateSince` and `idleSince`.
///
/// Returns `Ok(false)` without writing when the instance has moved on (for
/// example the instance controller already sent it to `Recycling` after a
/// failed health check, or a lease reserved it). The next reconcile
/// re-evaluates it from fresh state.
async fn mark_instance_recycling(
    client: &Client,
    namespace: &str,
    cluster_name: &str,
    expected: ClusterState,
) -> Result<bool, kube::Error> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let mut attempts = 0;
    loop {
        attempts += 1;
        let attempt = async {
            let instance = instances_api.get(cluster_name).await?;
            let uid = instance.metadata.uid.as_deref().ok_or_else(|| {
                kube::Error::Service(Box::new(std::io::Error::other("instance has no UID")))
            })?;
            let rv = instance.resource_version().ok_or_else(|| {
                kube::Error::Service(Box::new(std::io::Error::other(
                    "instance has no resourceVersion",
                )))
            })?;
            let status = instance.status.clone().unwrap_or_default();
            let lease_held = status.lease_ref.is_some() || status.binding.is_some();
            if lease_held || pool_state_from_status(&status) != expected {
                return Ok(false);
            }
            let now = chrono::Utc::now().to_rfc3339();
            let mut ops = vec![
                serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
                serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": rv }),
            ];
            if instance.status.is_some() {
                ops.push(serde_json::json!({
                    "op": "test", "path": "/status/phase", "value": status.phase
                }));
                ops.push(serde_json::json!({
                    "op": "replace", "path": "/status/phase",
                    "value": ClusterInstancePhase::Recycling
                }));
                ops.push(serde_json::json!({
                    "op": "add", "path": "/status/stateSince", "value": now
                }));
                if status.idle_since.is_some() {
                    ops.push(serde_json::json!({ "op": "remove", "path": "/status/idleSince" }));
                }
            } else {
                let status = ClusterInstanceStatus {
                    phase: ClusterInstancePhase::Recycling,
                    state_since: Some(now),
                    ..Default::default()
                };
                ops.push(serde_json::json!({ "op": "add", "path": "/status", "value": status }));
            }
            instances_api
                .patch_status(
                    cluster_name,
                    &PatchParams::default(),
                    &Patch::<()>::Json(crate::controllers::lease::json_patch(
                        serde_json::Value::Array(ops),
                    )),
                )
                .await?;
            Ok::<bool, kube::Error>(true)
        }
        .await;
        match attempt {
            Err(ref error)
                if crate::controllers::lease::optimistic_conflict(error) && attempts < 5 =>
            {
                continue;
            }
            other => return other,
        }
    }
}

/// Stamp `spec_hash` and `stateSince` on an instance whose status is missing
/// them.
///
/// Each field is added only when absent, and the patch is fenced on the uid
/// and `resourceVersion` it read, so it can never replace or erase a value
/// written by anyone else. `stateSince` matters because the stuck-Creating
/// timeout in [`crate::pool::compute_pool_actions`] only fires on an instance
/// that has one: without it, a new instance whose initial status write was
/// lost could sit in `Creating` forever.
async fn backfill_spec_hash(
    client: &Client,
    namespace: &str,
    cluster_name: &str,
    spec_hash: &str,
) -> Result<(), kube::Error> {
    let instances_api: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instance = instances_api.get(cluster_name).await?;
    let (has_hash, has_since) = instance.status.as_ref().map_or((false, false), |s| {
        (s.spec_hash.is_some(), s.state_since.is_some())
    });
    if has_hash && has_since {
        return Ok(());
    }
    let uid = instance.metadata.uid.as_deref().ok_or_else(|| {
        kube::Error::Service(Box::new(std::io::Error::other("instance has no UID")))
    })?;
    let rv = instance.resource_version().ok_or_else(|| {
        kube::Error::Service(Box::new(std::io::Error::other(
            "instance has no resourceVersion",
        )))
    })?;
    let now = chrono::Utc::now().to_rfc3339();
    let mut ops = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({ "op": "test", "path": "/metadata/resourceVersion", "value": rv }),
    ];
    if instance.status.is_some() {
        if !has_hash {
            ops.push(
                serde_json::json!({ "op": "add", "path": "/status/specHash", "value": spec_hash }),
            );
        }
        if !has_since {
            ops.push(
                serde_json::json!({ "op": "add", "path": "/status/stateSince", "value": now }),
            );
        }
    } else {
        let status = ClusterInstanceStatus {
            spec_hash: Some(spec_hash.to_string()),
            state_since: Some(now),
            ..Default::default()
        };
        ops.push(serde_json::json!({ "op": "add", "path": "/status", "value": status }));
    }
    let patch = crate::controllers::lease::json_patch(serde_json::Value::Array(ops));
    instances_api
        .patch_status(
            cluster_name,
            &PatchParams::default(),
            &Patch::<()>::Json(patch),
        )
        .await?;
    Ok(())
}

/// Best-effort: read each instance's `{name}-certs` Secret, emit
/// `kobe_cert_expiry_seconds` per component (worst across the pool), and
/// return each instance's soonest cert horizon in seconds — the input for
/// recycle-before-expiry (#19). Only meaningful for backends using the
/// kobe-managed PKI (vkobe / vcluster) — callers skip it entirely for
/// self-managed-PKI backends (k3s/k0s/capi), keeping Secret reads off those
/// pools' reconcile path. Never fails a reconcile: a missing Secret (instance
/// not yet provisioned) is skipped silently; a read ERROR is skipped
/// fail-open but logged, so a persistent RBAC/API problem is visible instead
/// of silently disabling expiry protection. See #169.
async fn collect_and_emit_cert_expiry(
    client: &Client,
    namespace: &str,
    profile: &str,
    pool_state: &PoolState,
) -> HashMap<String, i64> {
    use k8s_openapi::api::core::v1::Secret;

    // Secret data key -> metric `component` label.
    const COMPONENTS: [(&str, &str); 3] = [
        ("ca.crt", "ca"),
        ("apiserver.crt", "apiserver"),
        ("front-proxy-ca.crt", "front_proxy_ca"),
    ];

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let now = chrono::Utc::now().timestamp();
    let mut worst: HashMap<&str, i64> = HashMap::new();
    let mut per_instance: HashMap<String, i64> = HashMap::new();

    for cluster_name in pool_state.clusters.keys() {
        let secret = match secrets.get_opt(&format!("{cluster_name}-certs")).await {
            Ok(Some(s)) => s,
            // Not yet provisioned → nothing to measure yet.
            Ok(None) => continue,
            // Fail-open (this pass must never wedge a reconcile) but VISIBLE:
            // a persistent read failure would otherwise silently disable
            // recycle-before-expiry for this member.
            Err(e) => {
                warn!(
                    profile = %profile,
                    cluster = %cluster_name,
                    error = %e,
                    "cert-expiry probe: failed to read certs Secret (fail-open, \
                     no expiry protection for this member this reconcile)"
                );
                continue;
            }
        };
        let Some(data) = secret.data else { continue };
        for (key, component) in COMPONENTS {
            let Some(pem) = data.get(key).and_then(|b| std::str::from_utf8(&b.0).ok()) else {
                continue;
            };
            let Some(not_after) = crate::pki::cert_not_after_unix(pem) else {
                continue;
            };
            let horizon = not_after - now;
            worst
                .entry(component)
                .and_modify(|m| *m = (*m).min(horizon))
                .or_insert(horizon);
            per_instance
                .entry(cluster_name.clone())
                .and_modify(|m| *m = (*m).min(horizon))
                .or_insert(horizon);
        }
    }

    for (component, horizon) in worst {
        crate::metrics::CERT_EXPIRY_SECONDS
            .with_label_values(&[profile, component])
            .set(horizon);
    }

    per_instance
}

/// Backfill `spec_hash` and a missing `stateSince` on instances created this
/// reconcile.
///
/// [`ensure_cluster_instance`] writes the initial status right after
/// CREATE and retries lost races, but it can still give up. Without a hash
/// the instance is drift-blind until the unstamped grace elapses, and without
/// `stateSince` the stuck-Creating timeout never fires, so this gives it one
/// more try with the hash it was created for.
///
/// This is the only end-of-reconcile status write the pool controller
/// makes. Phase, `idleSince` and an existing `stateSince` belong to the
/// instance and lease controllers: copying them from the pool snapshot could
/// revert a newer transition, such as a health-failed `Ready → Recycling`
/// whose backend is then deleted, back to a leasable `Ready`. The pool only
/// fills a `stateSince` nobody has written, and otherwise writes only its own
/// intent, in [`mark_instance_recycling`].
async fn backfill_spec_hashes(client: &Client, namespace: &str, created: &[(String, String)]) {
    for (cluster_name, spec_hash) in created {
        if let Err(err) = backfill_spec_hash(client, namespace, cluster_name, spec_hash).await {
            warn!(
                cluster = %cluster_name,
                error = %err,
                "Failed to backfill spec_hash on a new instance"
            );
        }
    }
}

/// Marker prefix stamped on `last_failure_reason` when the #191 capacity wedge
/// is engaged. It is the ONLY structured marker in the otherwise free-form
/// reason text, so it doubles as the sound inverse used by
/// [`persisted_failure_class`] to recover a prior reconcile's class.
pub(crate) const CAPACITY_BLOCKED_REASON_PREFIX: &str = "capacity-blocked:";

/// Recover the [`crate::metrics::PoolFailureClass`] a *previously persisted*
/// pool reason was emitted with. Only `Capacity` carries a marker
/// ([`CAPACITY_BLOCKED_REASON_PREFIX`]); every other persisted reason was
/// `Other`. This is a marker-based inverse of the structural class — NOT the
/// unsound keyword parsing of [`crate::metrics::PoolFailureClass::from_reason`].
fn persisted_failure_class(reason: Option<&str>) -> crate::metrics::PoolFailureClass {
    match reason {
        Some(r) if r.starts_with(CAPACITY_BLOCKED_REASON_PREFIX) => {
            crate::metrics::PoolFailureClass::Capacity
        }
        _ => crate::metrics::PoolFailureClass::Other,
    }
}

/// Backoff bookkeeping computed once per reconcile.
pub(crate) struct BackoffState {
    pub consecutive_failures: u32,
    pub next_attempt_at: Option<String>,
    pub last_failure_reason: Option<String>,
    /// Bounded failure class for the `kobe_pool_failure_reason_changes_total`
    /// label, set STRUCTURALLY here where the cause is known — never parsed back
    /// out of `last_failure_reason` (that string embeds dynamic data such as the
    /// pool name, so substring classification is unsound: a pool named e.g.
    /// `…-health…` or `create-…` would mislabel the metric).
    pub failure_class: crate::metrics::PoolFailureClass,
    pub max_attempted_index: u32,
    pub last_ready_max_index: u32,
}

/// Compute the next backoff state for a pool.
///
/// Index-based detection:
/// - `max_attempted_index` is the high-water mark of every cluster index the
///   pool has tried (sticky across reconciles).
/// - `last_ready_max_index` is the highest index that ever reached `Ready`
///   (sticky too).
/// - `consecutive_failures` is then derived as the gap:
///   `max_attempted_index - last_ready_max_index`.
///
/// This counts failed attempts correctly even during rapid create→recycle
/// churn, where the previous "no creating, only recycling" detector would
/// never trigger because the next attempt has already started.
///
/// Window gate: `next_attempt_at` is only refreshed when `consecutive_failures`
/// increases — repeated reconciles inside the same window do not over-extend
/// the wait.
fn compute_backoff_state(
    profile: &ClusterPool,
    pool_state: &PoolState,
    counts: &crate::pool::manager::StateCounts,
    now: chrono::DateTime<chrono::Utc>,
) -> BackoffState {
    let prev = profile.status.as_ref();
    let prev_failures = prev.map(|s| s.consecutive_failures).unwrap_or(0);
    let prev_next_attempt = prev.and_then(|s| s.next_attempt_at.clone());
    let prev_reason = prev.and_then(|s| s.last_failure_reason.clone());
    let prev_max_attempted = prev.map(|s| s.max_attempted_index).unwrap_or(0);
    let prev_last_ready_max = prev.map(|s| s.last_ready_max_index).unwrap_or(0);

    // #189: a Creating instance whose guest Pods are Unschedulable is the
    // explicit backpressure signal. The index-gap math below only engages
    // backoff once an attempted index outruns the highest Ready one, which
    // can lag (or never fire) for a single wedged member. Treat a live
    // scheduling block as "engage backoff now" so scale-up is suppressed and
    // `next_attempt_at` is extended — exactly the fail-closed backoff #166
    // wires up — instead of churning new (still-unschedulable) members.
    let scheduling_blocked_present = pool_state.clusters.values().any(|e| e.scheduling_blocked);

    // High-water mark of any cluster name we've ever seen, including the
    // current state and the sticky previous status value.
    let profile_name = profile.metadata.name.clone().unwrap_or_default();
    let live_max = max_index_in_state(pool_state, &profile_name);
    let new_max_attempted = live_max.max(prev_max_attempted);

    // Highest index of any instance that has ever reached `Ready` (or is
    // currently Ready / Leased) in this reconcile's snapshot.
    let max_ready_now = pool_state
        .clusters
        .iter()
        .filter(|(_, e)| {
            e.idle_since.is_some()
                || matches!(
                    e.state,
                    crate::pool::ClusterState::Ready | crate::pool::ClusterState::Leased
                )
        })
        .filter_map(|(name, _)| extract_cluster_index(name, &profile_name))
        .max()
        .unwrap_or(0);
    let new_last_ready_max = max_ready_now.max(prev_last_ready_max);

    // Anything currently Ready/leased OR an instance reached Ready in this
    // pool's lifetime → reset failures to 0. A live scheduling block holds
    // the pool in backpressure though, so we don't take the clean-clear path
    // even when other members are Ready (otherwise scale-up would resume and
    // spawn more Pods the scheduler still can't place).
    let any_ready = counts.ready > 0 || counts.leased > 0 || new_last_ready_max > 0;
    if any_ready && new_last_ready_max >= new_max_attempted && !scheduling_blocked_present {
        // Pool has caught up — every attempted index has reached Ready at
        // some point. Clear failures.
        return BackoffState {
            consecutive_failures: 0,
            next_attempt_at: None,
            last_failure_reason: None,
            failure_class: crate::metrics::PoolFailureClass::Other,
            max_attempted_index: new_max_attempted,
            last_ready_max_index: new_last_ready_max,
        };
    }

    // Index-gap failures, floored to at least 1 while a scheduling block is
    // live so the backoff window is always engaged for the wedged member.
    let new_failures = new_max_attempted
        .saturating_sub(new_last_ready_max)
        .max(u32::from(scheduling_blocked_present));

    // Refresh next_attempt_at only when failure count strictly increased,
    // so repeated reconciles inside one window don't push the wait further.
    // A scheduling block must always carry a (possibly preserved) future
    // attempt time so `backoff_active` keeps suppressing scale-up/recycle.
    let next_attempt = if new_failures > prev_failures && new_failures > 0 {
        crate::pool::manager::backoff_delay_for(profile, new_failures)
            .map(|d| (now + d).to_rfc3339())
    } else if scheduling_blocked_present {
        // Hold the window: refresh if we somehow lost it, else carry forward.
        prev_next_attempt.clone().or_else(|| {
            crate::pool::manager::backoff_delay_for(profile, new_failures.max(1))
                .map(|d| (now + d).to_rfc3339())
        })
    } else if new_failures == 0 {
        None
    } else {
        prev_next_attempt
    };

    // Bounded failure class for the metric label, decided from the signals we
    // actually have — NOT parsed back out of `last_failure_reason` below. That
    // string embeds dynamic data (the pool name, indexes, free-form guidance),
    // so substring classification is unsound. Today the only cause the pool loop
    // can attribute is the #191 capacity wedge; everything else is `Other`.
    let failure_class = if new_failures > 0 && scheduling_blocked_present {
        crate::metrics::PoolFailureClass::Capacity
    } else {
        crate::metrics::PoolFailureClass::Other
    };

    // Populate a triage-actionable reason from the signals we have (the
    // per-instance error isn't carried in PoolState, so we point operators at
    // the failing ClusterInstances rather than inventing detail). Previously
    // this field was only ever carried forward or cleared, so it was always
    // empty — defeating the status field's purpose. This text is human-facing
    // ONLY; the metric label comes from `failure_class` above.
    let last_failure_reason = if new_failures > 0 {
        let mut base = format!(
            "{new_failures} instance(s) not reaching Ready (attempted up to index \
             {new_max_attempted}, highest Ready {new_last_ready_max}); inspect the \
             Failed/not-Ready ClusterInstances (kubectl get ci -l \
             kobe.kunobi.ninja/pool={profile_name}) and their pod logs/events"
        );
        // #197 follow-up: when a member is crashlooping we HAVE the concrete
        // cause (the instance controller stamped it, incl. the distilled
        // "last log" fatal line) — cite one example so the reason (and the
        // lease-preflight 503 `detail` built from it) answers *why* instead
        // of only pointing at kubectl. Highest name wins for determinism
        // (that's the newest attempt under the pool's naming scheme).
        if let Some((name, msg)) = pool_state
            .clusters
            .iter()
            .filter_map(|(name, e)| e.crash_message.as_deref().map(|m| (name, m)))
            .max_by(|a, b| a.0.cmp(b.0))
        {
            base.push_str(&format!("; e.g. {name}: {msg}"));
        }
        // #189 (observability): when the #191 scheduling-blocked backpressure is
        // engaged, prefix the reason so it clearly reads as a capacity wedge
        // (`failure_class` above is already `Capacity`). This is a STRING-ONLY
        // enrichment: it does NOT change the phase, the failure count, or any
        // create/recycle/backoff decision — those already reacted to
        // `scheduling_blocked_present` above.
        if scheduling_blocked_present {
            let blocked = pool_state
                .clusters
                .values()
                .filter(|e| e.scheduling_blocked)
                .count();
            Some(format!(
                "{CAPACITY_BLOCKED_REASON_PREFIX} {blocked} instance(s) unschedulable; {base}"
            ))
        } else {
            Some(base)
        }
    } else {
        prev_reason
    };

    BackoffState {
        consecutive_failures: new_failures,
        next_attempt_at: next_attempt,
        last_failure_reason,
        failure_class,
        max_attempted_index: new_max_attempted,
        last_ready_max_index: new_last_ready_max,
    }
}

/// Compute the highest cluster index in the current pool state.
/// Names follow `pool-{profile}-{index}`.
fn max_index_in_state(state: &PoolState, profile_name: &str) -> u32 {
    let prefix = format!("pool-{profile_name}-");
    state
        .clusters
        .keys()
        .filter_map(|name| extract_index_with_prefix(name, &prefix))
        .max()
        .unwrap_or(0)
}

fn extract_cluster_index(name: &str, profile_name: &str) -> Option<u32> {
    let prefix = format!("pool-{profile_name}-");
    extract_index_with_prefix(name, &prefix)
}

fn extract_index_with_prefix(name: &str, prefix: &str) -> Option<u32> {
    name.strip_prefix(prefix)
        .and_then(|suffix| suffix.parse::<u32>().ok())
}

fn cluster_state_from_phase(phase: &ClusterInstancePhase) -> ClusterState {
    match phase {
        ClusterInstancePhase::Creating => ClusterState::Creating,
        ClusterInstancePhase::Ready => ClusterState::Ready,
        ClusterInstancePhase::Leased => ClusterState::Leased,
        ClusterInstancePhase::Recycling => ClusterState::Recycling,
        ClusterInstancePhase::Unhealthy => ClusterState::Unhealthy,
        ClusterInstancePhase::Failed => ClusterState::Unhealthy,
        // Quarantined maps to its own state, never to Unhealthy: Unhealthy is
        // deleted unconditionally by the pool manager, which would destroy the
        // cleanup handle and let the ordinary recycle path resume.
        ClusterInstancePhase::Quarantined => ClusterState::Quarantined,
    }
}

fn parse_optional_time(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod unsupported_config_tests {
    use super::*;
    use crate::metrics::RecycleReason;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn t(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn unsupported_config_holds_creates_and_drift_recycles_only() {
        let actions = vec![
            PoolAction::Create("p-3".into()),
            PoolAction::Delete("p-0".into(), RecycleReason::SpecDrift),
            PoolAction::Delete("p-1".into(), RecycleReason::Unhealthy),
            PoolAction::Delete("p-2".into(), RecycleReason::ScaleDown),
        ];
        let held = hold_unsupported_config(actions.clone(), &["cluster.servers"]);
        assert_eq!(
            held,
            vec![
                PoolAction::Delete("p-1".into(), RecycleReason::Unhealthy),
                PoolAction::Delete("p-2".into(), RecycleReason::ScaleDown),
            ]
        );
        assert_eq!(hold_unsupported_config(actions.clone(), &[]), actions);
    }

    #[test]
    fn config_supported_condition_names_backend_and_fields() {
        let c = config_supported_condition(
            &crate::crd::BackendType::Vcluster,
            &["cluster.servers", "cluster.agents"],
        );
        assert_eq!(c.condition_type, "ConfigSupported");
        assert_eq!(c.status, "False");
        assert_eq!(c.reason, "UnsupportedFields");
        assert!(
            c.message
                .contains("backend vcluster ignores cluster.servers, cluster.agents"),
            "{}",
            c.message
        );

        let ok = config_supported_condition(&crate::crd::BackendType::K3s, &[]);
        assert_eq!(ok.status, "True");
    }

    #[test]
    fn pool_conditions_keep_transition_time_until_status_flips() {
        let first = pool_conditions(
            &[],
            config_supported_condition(&crate::crd::BackendType::Vcluster, &["cluster.servers"]),
            t("2026-09-01T10:00:00Z"),
        );
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].last_transition_time.as_deref(),
            Some("2026-09-01T10:00:00Z")
        );

        let same = pool_conditions(
            &first,
            config_supported_condition(&crate::crd::BackendType::Vcluster, &["cluster.agents"]),
            t("2026-09-01T11:00:00Z"),
        );
        assert_eq!(
            same[0].last_transition_time.as_deref(),
            Some("2026-09-01T10:00:00Z")
        );
        assert!(same[0].message.contains("cluster.agents"));

        let flipped = pool_conditions(
            &same,
            config_supported_condition(&crate::crd::BackendType::Vcluster, &[]),
            t("2026-09-01T12:00:00Z"),
        );
        assert_eq!(flipped.len(), 1);
        assert_eq!(flipped[0].status, "True");
        assert_eq!(
            flipped[0].last_transition_time.as_deref(),
            Some("2026-09-01T12:00:00Z")
        );
    }

    /// End to end through `reconcile_profile`: a vcluster pool asking for
    /// three servers must not create a member, and must say why in status.
    #[tokio::test]
    async fn reconcile_blocks_a_pool_whose_backend_ignores_its_fields() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let ctx = Arc::new(ProfileContext {
            client,
            namespace: "test-ns".to_string(),
            pools: Arc::new(RwLock::new(HashMap::new())),
            velero: None,
            factory: None,
            render_ctx: crate::pool::RenderContext::with_kobe_sync_image("zondax/kobe-sync:test"),
            golden_in_progress: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        });

        let empty_list = |kind: &str| {
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": kind,
                "metadata": { "resourceVersion": "1" },
                "items": []
            })
        };
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(empty_list("ClusterInstanceList")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_list("ClusterLeaseList")))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances",
            ))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let pool: ClusterPool = serde_json::from_value(serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": { "name": "vc", "namespace": "test-ns", "uid": "pool-uid", "generation": 1 },
            "spec": {
                "size": 1,
                "backend": { "type": "vcluster" },
                "cluster": { "version": "v1.33.1", "servers": 3 },
                "scaling": { "minReady": 1, "maxClusters": 2 }
            }
        }))
        .unwrap();

        let patched = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let sink = patched.clone();
        let echo = serde_json::to_value(&pool).unwrap();
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/vc/status",
            ))
            .respond_with(move |req: &wiremock::Request| {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                    sink.lock().unwrap().push(v);
                }
                ResponseTemplate::new(200).set_body_json(echo.clone())
            })
            .mount(&server)
            .await;

        reconcile_profile(Arc::new(pool), ctx)
            .await
            .expect("reconcile succeeds");

        let writes = patched.lock().unwrap().clone();
        let status = &writes.last().expect("status was patched")["status"];
        assert_eq!(status["phase"], "Failing", "{status}");
        let condition = status["conditions"]
            .as_array()
            .and_then(|cs| cs.iter().find(|c| c["type"] == "ConfigSupported"))
            .unwrap_or_else(|| panic!("no ConfigSupported condition: {status}"));
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedFields");
        assert!(
            condition["message"]
                .as_str()
                .unwrap()
                .contains("cluster.servers"),
            "{condition}"
        );
    }
}
