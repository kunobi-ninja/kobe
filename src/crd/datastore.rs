use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Which storage driver the KobeStore uses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub enum KobeStoreDriver {
    /// Standard etcd cluster.
    #[serde(rename = "etcd")]
    Etcd,
    /// Kine-backed SQLite (single-node, lightweight).
    #[serde(rename = "kine-sqlite")]
    KineSqlite,
}

/// TLS configuration for connecting to the KobeStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreTls {
    /// Name of the Kubernetes Secret containing TLS credentials
    /// (ca.crt, tls.crt, tls.key).
    pub secret_ref: String,
}

/// Capacity limits for a KobeStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreCapacity {
    /// Maximum number of virtual clusters this KobeStore can serve.
    pub max_clusters: u32,
}

/// Identifies a virtual cluster using this KobeStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreUser {
    /// Namespace of the virtual cluster.
    pub namespace: String,
    /// Name of the virtual cluster.
    pub name: String,
}

/// KobeStore represents an external storage backend (etcd or kine-sqlite)
/// that virtual cluster kube-apiservers connect to via `--etcd-servers`
/// and `--etcd-prefix`.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "KobeStore",
    plural = "kobestores",
    shortname = "ks",
    status = "KobeStoreStatus",
    namespaced,
    printcolumn = r#"{"name":"Driver","type":"string","jsonPath":".spec.driver"}"#,
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Clusters","type":"integer","jsonPath":".status.currentClusters"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreSpec {
    /// Storage driver type.
    pub driver: KobeStoreDriver,

    /// Endpoints to connect to (e.g. ["https://etcd-0:2379"]).
    pub endpoints: Vec<String>,

    /// Optional TLS configuration for the connection.
    #[serde(default)]
    pub tls: Option<KobeStoreTls>,

    /// Capacity limits.
    pub capacity: KobeStoreCapacity,

    /// Number of replicas for the storage backend (relevant for etcd).
    #[serde(default)]
    pub replicas: Option<u32>,
}

/// Runtime status of a KobeStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreStatus {
    /// Whether the KobeStore is reachable and healthy.
    /// Kept for backward compatibility; new code should consult
    /// `conditions[type=Healthy]` for richer reasons + messages.
    #[serde(default)]
    pub ready: bool,

    /// Number of virtual clusters currently using this KobeStore.
    #[serde(default)]
    pub current_clusters: u32,

    /// List of virtual clusters using this KobeStore.
    #[serde(default)]
    pub used_by: Vec<KobeStoreUser>,

    /// Health conditions surfaced by the operator. Currently emitted:
    /// `Healthy` — based on the backing workload's pod
    /// `containerStatuses` (OOMKilled, restart pressure, NotReady).
    ///
    /// Pattern follows core/v1 condition shape so `kubectl` and ops
    /// tooling can read it consistently. The profile controller treats
    /// `Healthy=False` as a signal to halt new ClusterInstance creates
    /// against this store, breaking the bootstrap-fail-recycle loop
    /// that compounds load on a degraded backend.
    ///
    /// `skip_serializing_if = "Vec::is_empty"` avoids a JSON Merge
    /// Patch dropping the field to `null` when other status writers
    /// (e.g. the `ready` / `current_clusters` updater) re-emit status
    /// without conditions of their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<KobeStoreCondition>,
}

/// One status condition on a KobeStore. Mirrors the core/v1 condition
/// shape (type/status/reason/message/lastTransitionTime) so kubectl
/// and operators see a familiar surface.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KobeStoreCondition {
    /// Condition name. Currently the only emitted value is `Healthy`.
    #[serde(rename = "type")]
    pub condition_type: String,

    /// One of: `True`, `False`, `Unknown`.
    pub status: String,

    /// Machine-readable reason. Examples for `Healthy=False`:
    /// `MemoryPressure` (recent OOMKill), `RestartLoop` (≥3 restarts in window),
    /// `NotReady` (containers not all ready), `WorkloadMissing` (referenced
    /// Deployment/StatefulSet not found).
    pub reason: String,

    /// Human-readable detail. Includes the last failure timestamp and
    /// any field operators need to triage without re-walking the
    /// kubectl describe chain.
    pub message: String,

    /// RFC3339 of the last status change. Updated only when `status`
    /// flips (True ↔ False ↔ Unknown), not on every reconcile, so
    /// tools tailing `kubectl get -w` see meaningful events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

impl KobeStoreStatus {
    /// Returns the most recent `Healthy` condition, if any.
    pub fn healthy_condition(&self) -> Option<&KobeStoreCondition> {
        self.conditions
            .iter()
            .find(|c| c.condition_type == "Healthy")
    }

    /// `Some(message)` when the KobeStore should be treated as degraded
    /// for the purposes of gating new ClusterInstance creates.
    /// Returns `None` when:
    /// - No `Healthy` condition has been written yet (fresh deployment;
    ///   fail-safe: don't block creates before the health controller
    ///   has had a chance to evaluate)
    /// - `Healthy=True` (obviously healthy)
    /// - `Healthy=Unknown` (external store, can't observe; assume OK)
    pub fn unhealthy_reason(&self) -> Option<String> {
        let cond = self.healthy_condition()?;
        if cond.status == "False" {
            Some(format!("{}: {}", cond.reason, cond.message))
        } else {
            None
        }
    }
}
