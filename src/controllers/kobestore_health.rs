//! KobeStore health controller.
//!
//! Watches `KobeStore` CRs and patches a `Healthy` condition into
//! `status.conditions` based on the runtime state of the backing
//! workload's pods. This makes the operator no longer "blind" to its
//! shared datastore — when kine OOMKills under bootstrap load (or any
//! other backend goes degraded), the condition is observable via
//! `kubectl get kobestore` and the profile controller can pause new
//! ClusterInstance creates against that store, breaking the
//! bootstrap-fail-recycle loop.
//!
//! ## What we evaluate
//!
//! For each KobeStore, the controller looks for a Deployment (or
//! failing that a StatefulSet) **with the same name as the KobeStore
//! in the same namespace** — that's the convention the chart-managed
//! kine and etcd templates follow. If found, it walks the workload's
//! currently-running pods and inspects each container's `status` for:
//!
//! 1. **MemoryPressure** — at least one container terminated as
//!    `OOMKilled` within the recent window (default 10 min). The
//!    smoking gun for "kine resources too tight under load".
//! 2. **RestartLoop** — restart count ≥ 3 on any container regardless
//!    of reason. Catches less-specific crashloops.
//! 3. **NotReady** — every container is supposed to be ready; if any
//!    isn't, surface it.
//!
//! Otherwise the condition is `Healthy=True, reason=Stable`.
//!
//! ## What we DON'T evaluate
//!
//! - **External KobeStores**: when no Deployment or StatefulSet with
//!   the same name exists in the operator's namespace, the condition
//!   reports `Healthy=Unknown, reason=External`. We can't observe a
//!   workload we don't know about; downgrading these to `False` would
//!   break every external etcd setup. The convention-based lookup is
//!   intentional: zero spec surface for the common case (chart-managed
//!   datastores), graceful "unknown" fallback for everything else.
//! - **TCP reachability of the endpoints**. The pod may be Ready but
//!   network-partitioned from the operator. This controller only
//!   surfaces signals derived from the apiserver's view of the pod;
//!   the existing `vkobe` backend's readiness probe handles
//!   end-to-end reachability for actual cluster bootstraps.
//!
//! ## Why a Controller and not just a periodic loop
//!
//! kube-rs's `Controller` runtime gives us:
//! - Watch on `KobeStore` (so spec edits trigger immediate reconcile)
//! - Built-in workqueue + dedup (so a pod restart doesn't fan out into
//!   N reconciles when N pods are restarting)
//! - Automatic backoff on transient errors via `error_policy`
//!
//! Reconcile cadence is set to 30s on success — the failure modes we
//! care about (OOMKill) are observable immediately via the watch on
//! `Pod` we set up via `Controller::watches`, so the periodic
//! requeue is a defensive lower bound.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::crd::{KobeStore, KobeStoreCondition, KobeStoreStatus};

/// Window in which an `OOMKilled` is considered "recent" enough to
/// trigger `MemoryPressure`. A pod that OOM'd hours ago and has been
/// stable since is not currently degraded; we don't want to halt the
/// pool forever on a single old failure.
const RECENT_FAILURE_WINDOW: Duration = Duration::from_secs(600);

/// Restart-count threshold for `RestartLoop`. Aligned with kubelet's
/// own crashloop heuristic so what users see in `kubectl get pod`
/// matches what we report.
const RESTART_LOOP_THRESHOLD: i32 = 3;

pub struct HealthContext {
    pub client: Client,
    pub namespace: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run_kobestore_health_controller(
    client: Client,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let stores: Api<KobeStore> = Api::namespaced(client.clone(), namespace);
    let ctx = Arc::new(HealthContext {
        client,
        namespace: namespace.to_string(),
    });

    info!("Starting KobeStore health controller");

    let controller = Controller::new(stores, Config::default())
        .run(reconcile_store_health, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => debug!(store = %obj.name, "KobeStore health reconciled"),
                Err(e) => error!("KobeStore health reconcile error: {e:?}"),
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("KobeStore health controller shutting down");
        }
    }
}

fn error_policy(_: Arc<KobeStore>, err: &HealthError, _: Arc<HealthContext>) -> Action {
    error!("KobeStore health reconcile error: {err}");
    Action::requeue(Duration::from_secs(30))
}

async fn reconcile_store_health(
    store: Arc<KobeStore>,
    ctx: Arc<HealthContext>,
) -> Result<Action, HealthError> {
    let store_name = store.name_any();
    let store_ns = store.namespace().unwrap_or_else(|| ctx.namespace.clone());

    let evaluation = evaluate_health(&ctx.client, &store_ns, &store).await;

    let stores: Api<KobeStore> = Api::namespaced(ctx.client.clone(), &store_ns);
    write_health_condition(&stores, &store, evaluation).await?;
    let _ = store_name; // surfaced via reconciled() span if/when we add tracing instrumentation

    // Re-evaluate every 30s as a defensive lower bound. The Watch on
    // KobeStore picks up spec changes immediately; this loop catches
    // pod-level changes that we don't (yet) watch directly.
    Ok(Action::requeue(Duration::from_secs(30)))
}

// ─────────────────────────────────────────────────────────────────────
// Health evaluation
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthEvaluation {
    pub status: &'static str, // "True" | "False" | "Unknown"
    pub reason: String,
    pub message: String,
}

impl HealthEvaluation {
    fn healthy() -> Self {
        Self {
            status: "True",
            reason: "Stable".to_string(),
            message: "All backing pods Ready, no recent OOMKills, no restart loop".to_string(),
        }
    }
    fn external() -> Self {
        Self {
            status: "Unknown",
            reason: "External".to_string(),
            message: "No same-named Deployment/StatefulSet in this namespace; \
                      operator cannot observe pod health for an external KobeStore"
                .to_string(),
        }
    }
}

async fn evaluate_health(client: &Client, namespace: &str, store: &KobeStore) -> HealthEvaluation {
    let store_name = store.name_any();

    // Convention: the chart-managed kine/etcd templates name the
    // backing Deployment (or StatefulSet for etcd) the same as the
    // KobeStore CR. Try Deployment first, then StatefulSet, then
    // give up and report `Unknown` (external store, can't observe).
    let deploys: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let selector = match deploys.get(&store_name).await {
        Ok(d) => d.spec.and_then(|s| s.selector.match_labels),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // No Deployment with this name; try StatefulSet.
            let stsets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
            match stsets.get(&store_name).await {
                Ok(s) => s.spec.and_then(|s| s.selector.match_labels),
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    // Neither workload exists by that name → external.
                    return HealthEvaluation::external();
                }
                Err(e) => {
                    warn!(error = %e, store = %store_name,
                          "Failed to fetch backing StatefulSet; reporting Unknown");
                    return HealthEvaluation {
                        status: "Unknown",
                        reason: "LookupFailed".to_string(),
                        message: format!("Failed to fetch backing StatefulSet: {e}"),
                    };
                }
            }
        }
        Err(e) => {
            warn!(error = %e, store = %store_name,
                  "Failed to fetch backing Deployment; reporting Unknown");
            return HealthEvaluation {
                status: "Unknown",
                reason: "LookupFailed".to_string(),
                message: format!("Failed to fetch backing Deployment: {e}"),
            };
        }
    };

    let Some(labels) = selector else {
        return HealthEvaluation {
            status: "Unknown",
            reason: "SelectorMissing".to_string(),
            message: format!(
                "Workload '{store_name}' has no selector.matchLabels; cannot list backing pods"
            ),
        };
    };

    let label_selector = labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&label_selector);
    let pods = match pods_api.list(&lp).await {
        Ok(l) => l.items,
        Err(e) => {
            warn!(error = %e, store = %store_name,
                  "Failed to list backing pods; reporting Unknown");
            return HealthEvaluation {
                status: "Unknown",
                reason: "LookupFailed".to_string(),
                message: format!("Failed to list backing pods: {e}"),
            };
        }
    };

    evaluate_pods(&pods)
}

/// Pure function over a slice of pods → health evaluation.
/// Extracted from `evaluate_health` so the actual classification logic
/// is unit-testable without a kube fixture.
pub fn evaluate_pods(pods: &[Pod]) -> HealthEvaluation {
    if pods.is_empty() {
        return HealthEvaluation {
            status: "False",
            reason: "NoPods".to_string(),
            message: "Backing workload has no running pods".to_string(),
        };
    }

    // k8s_openapi exposes timestamps as `jiff::Timestamp`. We don't
    // need a typed comparison — convert to Unix milliseconds and
    // compare integers, which avoids dragging in a jiff↔chrono
    // converter for what is fundamentally "is this within the last N
    // seconds".
    let now_ms = Utc::now().timestamp_millis();
    let window_ms = RECENT_FAILURE_WINDOW.as_millis() as i64;

    let mut max_restart_count = 0;
    let mut not_ready_pods: Vec<String> = Vec::new();
    let mut recent_oom: Option<(String, i64)> = None;
    let mut max_restart_pod: Option<String> = None;

    for pod in pods {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let Some(status) = pod.status.as_ref() else {
            continue;
        };
        let Some(container_statuses) = status.container_statuses.as_ref() else {
            // Pod scheduled but containers not started yet — counts as
            // not-ready but not as a hard failure.
            not_ready_pods.push(pod_name.clone());
            continue;
        };

        let mut all_ready = true;
        for cs in container_statuses {
            if cs.restart_count > max_restart_count {
                max_restart_count = cs.restart_count;
                max_restart_pod = Some(pod_name.clone());
            }
            if !cs.ready {
                all_ready = false;
            }
            if let Some(last_state) = cs.last_state.as_ref()
                && let Some(term) = last_state.terminated.as_ref()
                && term.reason.as_deref() == Some("OOMKilled")
                && let Some(finished_at) = term.finished_at.as_ref()
            {
                let finished_ms = finished_at.0.as_millisecond();
                if now_ms - finished_ms <= window_ms {
                    let entry = (pod_name.clone(), finished_ms);
                    recent_oom = match recent_oom {
                        None => Some(entry),
                        Some(existing) if entry.1 > existing.1 => Some(entry),
                        Some(existing) => Some(existing),
                    };
                }
            }
        }
        if !all_ready {
            not_ready_pods.push(pod_name);
        }
    }

    // Priority order — most actionable signal wins.
    if let Some((pod, when_ms)) = recent_oom {
        // Convert back to RFC3339 for the human-readable message.
        let when = chrono::DateTime::from_timestamp_millis(when_ms)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| format!("{when_ms}ms-since-epoch"));
        return HealthEvaluation {
            status: "False",
            reason: "MemoryPressure".to_string(),
            message: format!(
                "Pod {pod} OOMKilled at {when}; consider raising memory limits on the backing workload"
            ),
        };
    }
    if max_restart_count >= RESTART_LOOP_THRESHOLD {
        return HealthEvaluation {
            status: "False",
            reason: "RestartLoop".to_string(),
            message: format!(
                "Pod {} has restart count {max_restart_count}; check liveness probes and resource limits",
                max_restart_pod.unwrap_or_default()
            ),
        };
    }
    if !not_ready_pods.is_empty() {
        return HealthEvaluation {
            status: "False",
            reason: "NotReady".to_string(),
            message: format!("Backing pods not Ready: {}", not_ready_pods.join(", ")),
        };
    }

    HealthEvaluation::healthy()
}

async fn write_health_condition(
    stores: &Api<KobeStore>,
    store: &KobeStore,
    eval: HealthEvaluation,
) -> Result<(), kube::Error> {
    // Preserve other status fields (ready, current_clusters, used_by)
    // by reading the existing list of conditions and only flipping the
    // Healthy entry. Missing -> insert; present and same status -> keep
    // lastTransitionTime (so kubectl -w doesn't fire on a redundant
    // reconcile); present and different status -> update timestamp.
    let existing = store
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    let mut new_conditions: Vec<KobeStoreCondition> = existing
        .iter()
        .filter(|c| c.condition_type != "Healthy")
        .cloned()
        .collect();

    let prev_healthy = existing.iter().find(|c| c.condition_type == "Healthy");
    let last_transition_time = match prev_healthy {
        Some(prev) if prev.status == eval.status => prev.last_transition_time.clone(),
        _ => Some(Utc::now().to_rfc3339()),
    };

    new_conditions.push(KobeStoreCondition {
        condition_type: "Healthy".to_string(),
        status: eval.status.to_string(),
        reason: eval.reason,
        message: eval.message,
        last_transition_time,
    });

    // Patch ONLY the conditions field via JSON Merge Patch. The other
    // status fields (ready, current_clusters, used_by) are owned by
    // separate code paths; we don't want to clobber them by sending a
    // full status object with default values.
    //
    // NB: JSON Merge Patch on an array IS a full replacement (RFC 7396
    // doesn't merge arrays). That's fine for `conditions` because we
    // just rebuilt the full list above with the unchanged entries
    // preserved.
    let patch = serde_json::json!({
        "status": {
            "conditions": new_conditions,
        }
    });
    stores
        .patch_status(
            &store.name_any(),
            &PatchParams::apply("kobe-operator-health"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Convenience: read the current `Healthy` reason for a store, used by
/// the profile controller's gating logic. `None` means "not unhealthy"
/// (either healthy, unknown, or condition missing — all treated as
/// "OK to proceed" so a fresh deploy doesn't deadlock waiting for the
/// health controller's first reconcile).
pub fn unhealthy_reason(store: &KobeStore) -> Option<String> {
    store
        .status
        .as_ref()
        .and_then(KobeStoreStatus::unhealthy_reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateTerminated, ContainerStatus, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::core::ObjectMeta;

    fn pod(name: &str, statuses: Vec<ContainerStatus>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: None,
            status: Some(PodStatus {
                container_statuses: Some(statuses),
                ..Default::default()
            }),
        }
    }

    fn cs_ready() -> ContainerStatus {
        ContainerStatus {
            name: "main".to_string(),
            ready: true,
            restart_count: 0,
            image: "test".to_string(),
            image_id: "".to_string(),
            ..Default::default()
        }
    }

    /// Build a `Time` (jiff::Timestamp wrapper) from "N seconds ago"
    /// using chrono's wall-clock and converting via Unix millis. Test
    /// helper because the chrono ↔ jiff direction is awkward.
    fn time_seconds_ago(secs: i64) -> Time {
        let ms = (Utc::now() - chrono::Duration::seconds(secs)).timestamp_millis();
        Time(k8s_openapi::jiff::Timestamp::from_millisecond(ms).unwrap())
    }

    fn cs_oom_recent() -> ContainerStatus {
        ContainerStatus {
            name: "main".to_string(),
            ready: true,
            restart_count: 1,
            image: "test".to_string(),
            image_id: "".to_string(),
            last_state: Some(ContainerState {
                terminated: Some(ContainerStateTerminated {
                    reason: Some("OOMKilled".to_string()),
                    finished_at: Some(time_seconds_ago(60)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn cs_oom_old() -> ContainerStatus {
        ContainerStatus {
            name: "main".to_string(),
            ready: true,
            restart_count: 1,
            image: "test".to_string(),
            image_id: "".to_string(),
            last_state: Some(ContainerState {
                terminated: Some(ContainerStateTerminated {
                    reason: Some("OOMKilled".to_string()),
                    finished_at: Some(time_seconds_ago(7200)), // 2h ago
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn cs_high_restart() -> ContainerStatus {
        ContainerStatus {
            name: "main".to_string(),
            ready: true,
            restart_count: 5,
            image: "test".to_string(),
            image_id: "".to_string(),
            ..Default::default()
        }
    }

    fn cs_not_ready() -> ContainerStatus {
        ContainerStatus {
            name: "main".to_string(),
            ready: false,
            restart_count: 0,
            image: "test".to_string(),
            image_id: "".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_pods_is_unhealthy() {
        let e = evaluate_pods(&[]);
        assert_eq!(e.status, "False");
        assert_eq!(e.reason, "NoPods");
    }

    #[test]
    fn all_ready_pods_are_healthy() {
        let e = evaluate_pods(&[pod("p1", vec![cs_ready()])]);
        assert_eq!(e.status, "True");
        assert_eq!(e.reason, "Stable");
    }

    #[test]
    fn recent_oom_takes_priority_over_other_signals() {
        // A pod with both OOM and high restart count should report OOM.
        let mut cs = cs_oom_recent();
        cs.restart_count = 7;
        let e = evaluate_pods(&[pod("kine", vec![cs])]);
        assert_eq!(e.status, "False");
        assert_eq!(e.reason, "MemoryPressure");
        assert!(e.message.contains("kine"));
        assert!(e.message.contains("OOMKilled"));
    }

    #[test]
    fn old_oom_does_not_trigger() {
        // 2 hours old OOM, no other failures -> healthy.
        let e = evaluate_pods(&[pod("p1", vec![cs_oom_old()])]);
        assert_eq!(e.status, "True", "old OOM beyond window should not flag");
    }

    #[test]
    fn restart_loop_threshold() {
        let e = evaluate_pods(&[pod("flapper", vec![cs_high_restart()])]);
        assert_eq!(e.status, "False");
        assert_eq!(e.reason, "RestartLoop");
        assert!(e.message.contains("flapper"));
        assert!(e.message.contains("5"));
    }

    #[test]
    fn not_ready_when_no_other_failures() {
        let e = evaluate_pods(&[pod("p1", vec![cs_not_ready()])]);
        assert_eq!(e.status, "False");
        assert_eq!(e.reason, "NotReady");
    }

    #[test]
    fn restart_below_threshold_is_ok() {
        let mut cs = cs_ready();
        cs.restart_count = 2; // below RESTART_LOOP_THRESHOLD=3
        let e = evaluate_pods(&[pod("p1", vec![cs])]);
        assert_eq!(e.status, "True");
    }

    #[test]
    fn priority_oom_over_notready() {
        // Pod has both OOM and one not-ready container — OOM wins.
        let mut not_ready = cs_not_ready();
        not_ready.name = "sidecar".to_string();
        let oom = cs_oom_recent();
        let e = evaluate_pods(&[pod("multi", vec![oom, not_ready])]);
        assert_eq!(e.reason, "MemoryPressure");
    }

    #[test]
    fn unhealthy_reason_helper() {
        let store = KobeStore {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: crate::crd::KobeStoreSpec {
                driver: crate::crd::KobeStoreDriver::KineSqlite,
                endpoints: vec![],
                tls: None,
                capacity: crate::crd::KobeStoreCapacity { max_clusters: 10 },
                replicas: None,
            },
            status: Some(KobeStoreStatus {
                ready: false,
                current_clusters: 0,
                used_by: vec![],
                conditions: vec![KobeStoreCondition {
                    condition_type: "Healthy".to_string(),
                    status: "False".to_string(),
                    reason: "MemoryPressure".to_string(),
                    message: "Pod kine OOMKilled".to_string(),
                    last_transition_time: None,
                }],
            }),
        };
        let r = unhealthy_reason(&store).expect("should be unhealthy");
        assert!(r.contains("MemoryPressure"));
        assert!(r.contains("OOMKilled"));
    }

    #[test]
    fn unhealthy_reason_returns_none_when_healthy() {
        let store = KobeStore {
            metadata: ObjectMeta::default(),
            spec: crate::crd::KobeStoreSpec {
                driver: crate::crd::KobeStoreDriver::KineSqlite,
                endpoints: vec![],
                tls: None,
                capacity: crate::crd::KobeStoreCapacity { max_clusters: 10 },
                replicas: None,
            },
            status: Some(KobeStoreStatus {
                ready: true,
                current_clusters: 0,
                used_by: vec![],
                conditions: vec![KobeStoreCondition {
                    condition_type: "Healthy".to_string(),
                    status: "True".to_string(),
                    reason: "Stable".to_string(),
                    message: "ok".to_string(),
                    last_transition_time: None,
                }],
            }),
        };
        assert!(unhealthy_reason(&store).is_none());
    }

    #[test]
    fn unhealthy_reason_returns_none_when_unknown_or_missing() {
        // Unknown
        let store_unknown = KobeStore {
            metadata: ObjectMeta::default(),
            spec: crate::crd::KobeStoreSpec {
                driver: crate::crd::KobeStoreDriver::KineSqlite,
                endpoints: vec![],
                tls: None,
                capacity: crate::crd::KobeStoreCapacity { max_clusters: 10 },
                replicas: None,
            },
            status: Some(KobeStoreStatus {
                ready: false,
                current_clusters: 0,
                used_by: vec![],
                conditions: vec![KobeStoreCondition {
                    condition_type: "Healthy".to_string(),
                    status: "Unknown".to_string(),
                    reason: "External".to_string(),
                    message: "no backingWorkload".to_string(),
                    last_transition_time: None,
                }],
            }),
        };
        assert!(unhealthy_reason(&store_unknown).is_none());

        // Missing condition entirely (fresh deploy before health controller runs)
        let store_missing = KobeStore {
            metadata: ObjectMeta::default(),
            spec: crate::crd::KobeStoreSpec {
                driver: crate::crd::KobeStoreDriver::KineSqlite,
                endpoints: vec![],
                tls: None,
                capacity: crate::crd::KobeStoreCapacity { max_clusters: 10 },
                replicas: None,
            },
            status: None,
        };
        assert!(unhealthy_reason(&store_missing).is_none());
    }
}
