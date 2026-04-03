//! Fake node syncer: host -> virtual direction.
//!
//! When a synced Pod lands on a host node, this syncer synthesizes a
//! corresponding `Node` object in the virtual kube-apiserver. It copies
//! labels, capacity, allocatable, and conditions from the host node. When no
//! managed Pods reference a fake node any longer, the node is cleaned up.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Node, NodeCondition, NodeSpec, NodeStatus, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContextV2};
use super::translator::LABEL_MANAGED;

// ---------------------------------------------------------------------------
// Pure function: synthesize a fake Node from a host Node
// ---------------------------------------------------------------------------

/// Synthesize a fake `Node` object suitable for the virtual kube-apiserver
/// from a host cluster Node.
///
/// Copies:
/// - name
/// - labels (plus the `LABEL_MANAGED=true` marker)
/// - capacity, allocatable
/// - conditions
///
/// The resulting Node is suitable for creating in the virtual cluster so that
/// `kubectl get nodes` in the virtual cluster shows the underlying host node.
pub fn synthesize_fake_node(host_node: &Node) -> Node {
    let name = host_node.metadata.name.clone();

    // Copy labels and add our managed marker.
    let mut labels = host_node.metadata.labels.clone().unwrap_or_default();
    labels.insert(LABEL_MANAGED.to_string(), "true".to_string());

    // Build status: copy capacity, allocatable, conditions.
    let host_status = host_node.status.as_ref();

    let capacity = host_status.and_then(|s| s.capacity.clone());
    let allocatable = host_status.and_then(|s| s.allocatable.clone());
    let conditions: Option<Vec<NodeCondition>> = host_status.and_then(|s| s.conditions.clone());
    let addresses = host_status.and_then(|s| s.addresses.clone());

    let status = Some(NodeStatus {
        capacity,
        allocatable,
        conditions,
        addresses,
        ..Default::default()
    });

    Node {
        metadata: ObjectMeta {
            name,
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(NodeSpec {
            ..Default::default()
        }),
        status,
    }
}

// ---------------------------------------------------------------------------
// FakeNodeSyncerV2 -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// v2 Fake Node syncer: watches host Pods with `LABEL_MANAGED=true` and
/// synthesizes corresponding Node objects in the virtual kube-apiserver.
///
/// Uses reference counting so that a virtual node is deleted only when the
/// last pod referencing it is removed.
///
/// Direction: host -> virtual.
pub struct FakeNodeSyncerV2 {
    /// Track how many managed pods reference each host node name.
    node_refs: Arc<Mutex<HashMap<String, usize>>>,
}

impl FakeNodeSyncerV2 {
    pub fn new() -> Self {
        Self {
            node_refs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the current reference count for a node (for testing/diagnostics).
    pub async fn ref_count(&self, node_name: &str) -> usize {
        self.node_refs
            .lock()
            .await
            .get(node_name)
            .copied()
            .unwrap_or(0)
    }
}

impl Default for FakeNodeSyncerV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ResourceSyncer for FakeNodeSyncerV2 {
    fn name(&self) -> &str {
        "fake_nodes"
    }

    async fn run(&self, ctx: Arc<SyncerContextV2>, shutdown: CancellationToken) {
        // Watch host Pods that are managed by kobe-sync.
        let host_pod_api: Api<Pod> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);
        let host_node_api: Api<Node> = Api::all(ctx.host_client.clone());
        let virtual_node_api: Api<Node> = Api::all(ctx.virtual_client.clone());

        let watcher_config = watcher::Config::default().labels(&format!("{}=true", LABEL_MANAGED));
        let mut stream = std::pin::pin!(watcher::watcher(host_pod_api, watcher_config));

        info!("FakeNodeSyncerV2: starting watch on host pods");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("FakeNodeSyncerV2: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = self.handle_event(
                                &ev, &ctx, &host_node_api, &virtual_node_api,
                            ).await {
                                warn!(error = %e, "FakeNodeSyncerV2: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "FakeNodeSyncerV2: watcher error");
                        }
                        None => {
                            info!("FakeNodeSyncerV2: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl FakeNodeSyncerV2 {
    /// Handle a single watcher event for host pods.
    ///
    /// * **Apply** -- increment the ref-count for the pod's `nodeName` and
    ///   ensure a virtual node exists.
    /// * **Delete** -- decrement the ref-count; if it reaches zero, delete the
    ///   virtual node.
    async fn handle_event(
        &self,
        event: &Event<Pod>,
        _ctx: &SyncerContextV2,
        host_node_api: &Api<Node>,
        virtual_node_api: &Api<Node>,
    ) -> anyhow::Result<()> {
        match event {
            Event::Apply(pod) | Event::InitApply(pod) => {
                // Extract spec.nodeName from the host pod.
                let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());

                if let Some(node_name) = node_name {
                    // Increment reference count.
                    let first_ref = {
                        let mut refs = self.node_refs.lock().await;
                        let count = refs.entry(node_name.clone()).or_insert(0);
                        *count += 1;
                        debug!(
                            node = %node_name,
                            ref_count = *count,
                            pod = %pod.name_any(),
                            "FakeNodeSyncerV2: incremented node ref count"
                        );
                        *count == 1
                    };

                    // Only synthesize the virtual node if this is the first reference
                    // or the node doesn't exist yet.
                    if first_ref {
                        // Fetch the host node.
                        match host_node_api.get(&node_name).await {
                            Ok(host_node) => {
                                let fake_node = synthesize_fake_node(&host_node);

                                // Create or update in virtual cluster.
                                match virtual_node_api.get_opt(&node_name).await? {
                                    Some(_existing) => {
                                        let patch = kube::api::Patch::Apply(&fake_node);
                                        virtual_node_api
                                            .patch(
                                                &node_name,
                                                &kube::api::PatchParams::apply("kobe-sync").force(),
                                                &patch,
                                            )
                                            .await?;
                                        debug!(node = %node_name, "FakeNodeSyncerV2: updated virtual node");
                                    }
                                    None => {
                                        virtual_node_api
                                            .create(&PostParams::default(), &fake_node)
                                            .await?;
                                        debug!(node = %node_name, "FakeNodeSyncerV2: created virtual node");
                                    }
                                }
                            }
                            Err(kube::Error::Api(err)) if err.code == 404 => {
                                warn!(
                                    node = %node_name,
                                    "FakeNodeSyncerV2: host node not found, skipping"
                                );
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
            Event::Delete(pod) => {
                let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());

                if let Some(node_name) = node_name {
                    let should_delete = {
                        let mut refs = self.node_refs.lock().await;
                        if let Some(count) = refs.get_mut(&node_name) {
                            *count = count.saturating_sub(1);
                            debug!(
                                node = %node_name,
                                ref_count = *count,
                                pod = %pod.name_any(),
                                "FakeNodeSyncerV2: decremented node ref count"
                            );
                            *count == 0
                        } else {
                            false
                        }
                    };

                    if should_delete {
                        // Delete the virtual node.
                        match virtual_node_api
                            .delete(&node_name, &DeleteParams::default())
                            .await
                        {
                            Ok(_) => {
                                info!(
                                    node = %node_name,
                                    "FakeNodeSyncerV2: deleted virtual node (no more pods)"
                                );
                            }
                            Err(kube::Error::Api(err)) if err.code == 404 => {
                                debug!(
                                    node = %node_name,
                                    "FakeNodeSyncerV2: virtual node already gone"
                                );
                            }
                            Err(e) => return Err(e.into()),
                        }
                        // Remove the entry entirely so it's clean.
                        self.node_refs.lock().await.remove(&node_name);
                    }
                } else {
                    debug!(
                        pod = %pod.name_any(),
                        "FakeNodeSyncerV2: pod deleted without node assignment"
                    );
                }
            }
            Event::Init => {
                debug!("FakeNodeSyncerV2: watcher init bookmark");
            }
            Event::InitDone => {
                info!("FakeNodeSyncerV2: initial list complete");
            }
        }

        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Node, NodeCondition, NodeStatus};
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    #[test]
    fn test_synthesize_fake_node() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("worker-1".into()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("kubernetes.io/os".into(), "linux".into());
                    m.insert(
                        "node.kubernetes.io/instance-type".into(),
                        "m5.xlarge".into(),
                    );
                    m
                }),
                ..Default::default()
            },
            status: Some(NodeStatus {
                capacity: Some({
                    let mut m = BTreeMap::new();
                    m.insert("cpu".into(), Quantity("4".into()));
                    m.insert("memory".into(), Quantity("16Gi".into()));
                    m
                }),
                allocatable: Some({
                    let mut m = BTreeMap::new();
                    m.insert("cpu".into(), Quantity("3800m".into()));
                    m.insert("memory".into(), Quantity("15Gi".into()));
                    m
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        assert_eq!(fake.metadata.name, Some("worker-1".into()));

        let labels = fake.metadata.labels.as_ref().unwrap();
        assert_eq!(labels.get("kubernetes.io/os"), Some(&"linux".into()));
        assert_eq!(
            labels.get("node.kubernetes.io/instance-type"),
            Some(&"m5.xlarge".into()),
        );
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".into()));

        // Verify capacity is copied.
        let status = fake.status.as_ref().unwrap();
        let capacity = status.capacity.as_ref().unwrap();
        assert_eq!(capacity.get("cpu"), Some(&Quantity("4".into())));
        assert_eq!(capacity.get("memory"), Some(&Quantity("16Gi".into())));

        // Verify allocatable is copied.
        let allocatable = status.allocatable.as_ref().unwrap();
        assert_eq!(allocatable.get("cpu"), Some(&Quantity("3800m".into())));
        assert_eq!(allocatable.get("memory"), Some(&Quantity("15Gi".into())));
    }

    #[test]
    fn test_fake_node_conditions_show_ready() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("w-1".into()),
                ..Default::default()
            },
            status: Some(NodeStatus {
                conditions: Some(vec![NodeCondition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        let conds = fake.status.as_ref().unwrap().conditions.as_ref().unwrap();
        assert!(
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        );
    }

    #[test]
    fn test_synthesize_fake_node_no_status() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("bare-node".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        assert_eq!(fake.metadata.name, Some("bare-node".into()));
        // Status exists but fields are None.
        let status = fake.status.as_ref().unwrap();
        assert!(status.capacity.is_none());
        assert!(status.allocatable.is_none());
        assert!(status.conditions.is_none());
    }

    #[test]
    fn test_synthesize_fake_node_no_labels() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("no-labels".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        let labels = fake.metadata.labels.as_ref().unwrap();
        // Should only have the managed label.
        assert_eq!(labels.len(), 1);
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".into()));
    }

    #[test]
    fn test_synthesize_fake_node_preserves_addresses() {
        use k8s_openapi::api::core::v1::NodeAddress;

        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("addr-node".into()),
                ..Default::default()
            },
            status: Some(NodeStatus {
                addresses: Some(vec![NodeAddress {
                    type_: "InternalIP".into(),
                    address: "10.0.1.5".into(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        let addrs = fake.status.as_ref().unwrap().addresses.as_ref().unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].type_, "InternalIP");
        assert_eq!(addrs[0].address, "10.0.1.5");
    }

    #[test]
    fn test_fake_node_managed_label_overrides_existing() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("override-test".into()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    // Host node happens to have this label set to "false".
                    m.insert(LABEL_MANAGED.to_string(), "false".into());
                    m
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        let labels = fake.metadata.labels.as_ref().unwrap();
        // Our synthesizer should always set it to "true".
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".into()));
    }

    #[tokio::test]
    async fn test_ref_count_starts_at_zero() {
        let syncer = FakeNodeSyncerV2::new();
        assert_eq!(syncer.ref_count("node-1").await, 0);
    }

    #[tokio::test]
    async fn test_ref_count_default_trait() {
        let syncer = FakeNodeSyncerV2::default();
        assert_eq!(syncer.ref_count("node-1").await, 0);
    }

    #[test]
    fn test_fake_node_multiple_conditions() {
        let host_node = Node {
            metadata: ObjectMeta {
                name: Some("multi-cond".into()),
                ..Default::default()
            },
            status: Some(NodeStatus {
                conditions: Some(vec![
                    NodeCondition {
                        type_: "Ready".into(),
                        status: "True".into(),
                        ..Default::default()
                    },
                    NodeCondition {
                        type_: "MemoryPressure".into(),
                        status: "False".into(),
                        ..Default::default()
                    },
                    NodeCondition {
                        type_: "DiskPressure".into(),
                        status: "False".into(),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let fake = synthesize_fake_node(&host_node);
        let conds = fake.status.as_ref().unwrap().conditions.as_ref().unwrap();
        assert_eq!(conds.len(), 3);
        assert!(
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        );
        assert!(
            conds
                .iter()
                .any(|c| c.type_ == "MemoryPressure" && c.status == "False")
        );
        assert!(
            conds
                .iter()
                .any(|c| c.type_ == "DiskPressure" && c.status == "False")
        );
    }
}
