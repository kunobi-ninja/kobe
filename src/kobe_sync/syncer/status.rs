//! Status syncer: host -> virtual direction.
//!
//! Watches host Pod status (IP, conditions, phase, container statuses) and
//! syncs back to the virtual Pod. This is how `kubectl get pods` in the
//! virtual cluster shows real status.

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Binding, ObjectReference, Pod, PodStatus};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::LABEL_MANAGED;

// ---------------------------------------------------------------------------
// Pure function: build a status patch from host Pod status
// ---------------------------------------------------------------------------

/// Build a JSON merge-patch value from a host Pod's status.
///
/// The returned value is suitable for patching the virtual Pod's `/status`
/// subresource. It copies:
/// - `phase`
/// - `podIP` / `podIPs`
/// - `conditions`
/// - `containerStatuses`
/// - `initContainerStatuses`
/// - `hostIP` / `hostIPs`
/// - `startTime`
/// - `message` / `reason`
pub fn build_status_patch(status: &PodStatus) -> serde_json::Value {
    let mut status_obj = serde_json::Map::new();

    if let Some(phase) = &status.phase {
        status_obj.insert(
            "phase".to_string(),
            serde_json::Value::String(phase.clone()),
        );
    }

    if let Some(pod_ip) = &status.pod_ip {
        status_obj.insert(
            "podIP".to_string(),
            serde_json::Value::String(pod_ip.clone()),
        );
    }

    if let Some(pod_ips) = &status.pod_ips {
        status_obj.insert(
            "podIPs".to_string(),
            serde_json::to_value(pod_ips).unwrap_or_default(),
        );
    }

    if let Some(host_ip) = &status.host_ip {
        status_obj.insert(
            "hostIP".to_string(),
            serde_json::Value::String(host_ip.clone()),
        );
    }

    if let Some(host_ips) = &status.host_ips {
        status_obj.insert(
            "hostIPs".to_string(),
            serde_json::to_value(host_ips).unwrap_or_default(),
        );
    }

    if let Some(conditions) = &status.conditions {
        status_obj.insert(
            "conditions".to_string(),
            serde_json::to_value(conditions).unwrap_or_default(),
        );
    }

    if let Some(container_statuses) = &status.container_statuses {
        status_obj.insert(
            "containerStatuses".to_string(),
            serde_json::to_value(container_statuses).unwrap_or_default(),
        );
    }

    if let Some(init_container_statuses) = &status.init_container_statuses {
        status_obj.insert(
            "initContainerStatuses".to_string(),
            serde_json::to_value(init_container_statuses).unwrap_or_default(),
        );
    }

    if let Some(start_time) = &status.start_time {
        status_obj.insert(
            "startTime".to_string(),
            serde_json::to_value(start_time).unwrap_or_default(),
        );
    }

    if let Some(message) = &status.message {
        status_obj.insert(
            "message".to_string(),
            serde_json::Value::String(message.clone()),
        );
    }

    if let Some(reason) = &status.reason {
        status_obj.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.clone()),
        );
    }

    serde_json::json!({
        "status": serde_json::Value::Object(status_obj)
    })
}

// ---------------------------------------------------------------------------
// Pod binding: schedule a virtual pod onto a (virtual) node
// ---------------------------------------------------------------------------

/// Create a `Binding` object to schedule a virtual pod onto a (virtual) node.
///
/// This mimics what kube-scheduler does: it POSTs a `Binding` to
/// `/api/v1/namespaces/{ns}/pods/{name}/binding`, which causes the API server
/// to set `spec.nodeName` on the pod.
///
/// Returns `Ok(())` on success **and** when the pod is already bound
/// (HTTP 409 Conflict). Other errors are propagated.
pub async fn bind_virtual_pod(
    virtual_client: &kube::Client,
    pod_name: &str,
    namespace: &str,
    node_name: &str,
) -> anyhow::Result<()> {
    let binding = Binding {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(pod_name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        target: ObjectReference {
            kind: Some("Node".to_string()),
            name: Some(node_name.to_string()),
            api_version: Some("v1".to_string()),
            ..Default::default()
        },
    };

    let url = format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/binding");
    let body = serde_json::to_vec(&binding)?;
    let req = http::Request::post(&url)
        .header("Content-Type", "application/json")
        .body(body)?;

    match virtual_client.request_text(req).await {
        Ok(_) => {
            info!(
                pod = pod_name,
                namespace = namespace,
                node = node_name,
                "StatusSyncer: bound virtual pod to node"
            );
            Ok(())
        }
        Err(kube::Error::Api(ref api_err)) if api_err.code == 409 => {
            // 409 Conflict means the pod is already bound -- that is fine.
            debug!(
                pod = pod_name,
                namespace = namespace,
                "StatusSyncer: virtual pod already bound, skipping"
            );
            Ok(())
        }
        Err(e) => {
            warn!(
                pod = pod_name,
                namespace = namespace,
                error = %e,
                "StatusSyncer: failed to bind virtual pod"
            );
            Err(e.into())
        }
    }
}

// ---------------------------------------------------------------------------
// StatusSyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// Status syncer: watches host Pods with `LABEL_MANAGED=true` and syncs
/// their status back to the corresponding virtual Pod.
///
/// Direction: host -> virtual.
pub struct StatusSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for StatusSyncer {
    fn name(&self) -> &str {
        "status"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        // Watch host Pods that are managed by kobe-sync.
        let host_pod_api: Api<Pod> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default().labels(&format!("{}=true", LABEL_MANAGED));
        let mut stream = std::pin::pin!(watcher::watcher(host_pod_api, watcher_config));

        info!("StatusSyncer: starting watch on host pods");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("StatusSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_status_event(&ev, &ctx).await {
                                warn!(error = %e, "StatusSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "StatusSyncer: watcher error");
                        }
                        None => {
                            info!("StatusSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the status syncer.
async fn handle_status_event(event: &Event<Pod>, ctx: &SyncerContext) -> anyhow::Result<()> {
    match event {
        Event::Apply(pod) | Event::InitApply(pod) => {
            let host_name = pod.name_any();

            // Reverse-translate host pod name to virtual (name, namespace).
            let (virtual_name, virtual_ns) = match ctx.translator.to_virtual(&host_name) {
                Some(pair) => pair,
                None => {
                    debug!(
                        host_name = %host_name,
                        "StatusSyncer: could not reverse-translate host pod name, skipping"
                    );
                    return Ok(());
                }
            };

            // Extract status from the host pod.
            let host_status = match &pod.status {
                Some(s) => s,
                None => {
                    debug!(
                        host_name = %host_name,
                        "StatusSyncer: host pod has no status, skipping"
                    );
                    return Ok(());
                }
            };

            debug!(
                host = %host_name,
                virtual_name = %virtual_name,
                virtual_ns = %virtual_ns,
                phase = ?host_status.phase,
                "StatusSyncer: syncing status to virtual pod"
            );

            let patch_value = build_status_patch(host_status);

            // Patch the virtual Pod's /status subresource.
            //
            // Important: `PatchParams::default()` + `Patch::Merge`, NOT
            // `apply().force() + Merge`. kube-rs validates that
            // `force=true` is only legal with `Patch::Apply`
            // (server-side apply) and rejects with `PatchParams::force
            // only works with Patch::Apply` otherwise. The previous
            // shape silently broke every status sync after our 0.22.x
            // refactor — fake nodes existed, host pods ran, but the
            // virtual probe pod never bound to a node because the
            // status patch failed at the kube-rs validation layer
            // before ever reaching the apiserver. End result: every
            // SchedulingProbe gate stayed Pending forever.
            //
            // We don't need SSA semantics here — there's no conflict
            // resolution on status fields, kobe-sync owns the status
            // mirror exclusively. Merge is the right choice and the
            // simpler path.
            let virtual_pod_api: Api<Pod> =
                Api::namespaced(ctx.virtual_client.clone(), &virtual_ns);

            virtual_pod_api
                .patch_status(
                    &virtual_name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch_value),
                )
                .await?;

            debug!(
                virtual_name = %virtual_name,
                virtual_ns = %virtual_ns,
                "StatusSyncer: patched virtual pod status"
            );

            // If the host pod has been scheduled (spec.nodeName set), bind the
            // virtual pod to the same node so it transitions from Pending to
            // Running -- there is no kube-scheduler inside the virtual cluster.
            if let Some(host_node) = pod.spec.as_ref().and_then(|s| s.node_name.as_deref()) {
                // Check if the virtual pod is already bound.
                let virtual_pod = virtual_pod_api.get_opt(&virtual_name).await?;
                let already_bound = virtual_pod
                    .as_ref()
                    .and_then(|vp| vp.spec.as_ref())
                    .and_then(|s| s.node_name.as_deref())
                    .is_some();

                if !already_bound
                    && let Err(e) =
                        bind_virtual_pod(&ctx.virtual_client, &virtual_name, &virtual_ns, host_node)
                            .await
                {
                    warn!(
                        error = %e,
                        virtual_name = %virtual_name,
                        virtual_ns = %virtual_ns,
                        "StatusSyncer: failed to bind virtual pod"
                    );
                }
            }
        }
        Event::Delete(pod) => {
            // When a host pod is deleted, the virtual pod's status will become
            // stale. The pod syncer (virtual -> host) handles pod lifecycle;
            // we just log here.
            debug!(
                pod = %pod.name_any(),
                "StatusSyncer: host pod deleted, no status action needed"
            );
        }
        Event::Init => {
            debug!("StatusSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("StatusSyncer: initial list complete");
        }
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        Binding, ContainerStatus, ObjectReference, PodCondition, PodStatus,
    };

    #[test]
    fn test_build_status_patch() {
        let host_pod_status = PodStatus {
            phase: Some("Running".into()),
            pod_ip: Some("10.244.1.5".into()),
            conditions: Some(vec![PodCondition {
                type_: "Ready".into(),
                status: "True".into(),
                ..Default::default()
            }]),
            container_statuses: Some(vec![ContainerStatus {
                name: "main".into(),
                ready: true,
                restart_count: 0,
                ..Default::default()
            }]),
            ..Default::default()
        };

        let patch = build_status_patch(&host_pod_status);
        assert_eq!(patch["status"]["phase"], "Running");
        assert_eq!(patch["status"]["podIP"], "10.244.1.5");

        // Verify conditions are present.
        let conditions = &patch["status"]["conditions"];
        assert!(conditions.is_array());
        assert_eq!(conditions[0]["type"], "Ready");
        assert_eq!(conditions[0]["status"], "True");

        // Verify container statuses are present.
        let cs = &patch["status"]["containerStatuses"];
        assert!(cs.is_array());
        assert_eq!(cs[0]["name"], "main");
        assert_eq!(cs[0]["ready"], true);
    }

    #[test]
    fn test_build_status_patch_pending() {
        let status = PodStatus {
            phase: Some("Pending".into()),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        assert_eq!(patch["status"]["phase"], "Pending");
        // No podIP when pending.
        assert!(patch["status"]["podIP"].is_null());
    }

    #[test]
    fn test_build_status_patch_with_host_ip() {
        let status = PodStatus {
            phase: Some("Running".into()),
            host_ip: Some("10.0.0.1".into()),
            pod_ip: Some("10.244.0.5".into()),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        assert_eq!(patch["status"]["hostIP"], "10.0.0.1");
        assert_eq!(patch["status"]["podIP"], "10.244.0.5");
    }

    #[test]
    fn test_build_status_patch_failed_pod() {
        let status = PodStatus {
            phase: Some("Failed".into()),
            message: Some("OOMKilled".into()),
            reason: Some("OutOfMemory".into()),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        assert_eq!(patch["status"]["phase"], "Failed");
        assert_eq!(patch["status"]["message"], "OOMKilled");
        assert_eq!(patch["status"]["reason"], "OutOfMemory");
    }

    #[test]
    fn test_build_status_patch_empty_status() {
        let status = PodStatus::default();

        let patch = build_status_patch(&status);
        // The "status" key should exist but be mostly empty.
        assert!(patch["status"].is_object());
        assert!(patch["status"]["phase"].is_null());
        assert!(patch["status"]["podIP"].is_null());
    }

    #[test]
    fn test_build_status_patch_multiple_conditions() {
        let status = PodStatus {
            phase: Some("Running".into()),
            conditions: Some(vec![
                PodCondition {
                    type_: "Initialized".into(),
                    status: "True".into(),
                    ..Default::default()
                },
                PodCondition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    ..Default::default()
                },
                PodCondition {
                    type_: "ContainersReady".into(),
                    status: "True".into(),
                    ..Default::default()
                },
                PodCondition {
                    type_: "PodScheduled".into(),
                    status: "True".into(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        let conds = patch["status"]["conditions"].as_array().unwrap();
        assert_eq!(conds.len(), 4);
    }

    #[test]
    fn test_build_status_patch_multiple_containers() {
        let status = PodStatus {
            phase: Some("Running".into()),
            container_statuses: Some(vec![
                ContainerStatus {
                    name: "app".into(),
                    ready: true,
                    restart_count: 0,
                    ..Default::default()
                },
                ContainerStatus {
                    name: "sidecar".into(),
                    ready: true,
                    restart_count: 2,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        let cs = patch["status"]["containerStatuses"].as_array().unwrap();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0]["name"], "app");
        assert_eq!(cs[1]["name"], "sidecar");
        assert_eq!(cs[1]["restartCount"], 2);
    }

    #[test]
    fn test_build_status_patch_init_containers() {
        let status = PodStatus {
            phase: Some("Running".into()),
            init_container_statuses: Some(vec![ContainerStatus {
                name: "init-db".into(),
                ready: false,
                restart_count: 0,
                ..Default::default()
            }]),
            ..Default::default()
        };

        let patch = build_status_patch(&status);
        let ics = patch["status"]["initContainerStatuses"].as_array().unwrap();
        assert_eq!(ics.len(), 1);
        assert_eq!(ics[0]["name"], "init-db");
    }

    // -- Pod binding serialization tests --

    #[test]
    fn test_binding_serializes_correctly() {
        let binding = Binding {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("my-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            target: ObjectReference {
                kind: Some("Node".to_string()),
                name: Some("worker-1".to_string()),
                api_version: Some("v1".to_string()),
                ..Default::default()
            },
        };

        let json = serde_json::to_value(&binding).expect("Binding should serialize");
        assert_eq!(json["metadata"]["name"], "my-pod");
        assert_eq!(json["metadata"]["namespace"], "default");
        assert_eq!(json["target"]["kind"], "Node");
        assert_eq!(json["target"]["name"], "worker-1");
        assert_eq!(json["target"]["apiVersion"], "v1");
    }

    #[test]
    fn test_binding_url_is_well_formed() {
        let namespace = "kube-system";
        let pod_name = "coredns-abc123";
        let url = format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/binding");
        assert_eq!(
            url,
            "/api/v1/namespaces/kube-system/pods/coredns-abc123/binding"
        );
    }

    #[test]
    fn test_binding_body_is_valid_json() {
        let binding = Binding {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("test-pod".to_string()),
                namespace: Some("test-ns".to_string()),
                ..Default::default()
            },
            target: ObjectReference {
                kind: Some("Node".to_string()),
                name: Some("node-1".to_string()),
                api_version: Some("v1".to_string()),
                ..Default::default()
            },
        };

        let body = serde_json::to_vec(&binding).expect("should serialize to bytes");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["target"]["name"], "node-1");
    }
}
