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

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver's wire values are kebab-case and explicitly renamed, which
    /// `rename_all = "camelCase"` would NOT produce for `KineSqlite`.
    ///
    /// These strings are what every existing KobeStore has stored. Losing the
    /// rename would make `kine-sqlite` fail to deserialize, and a KobeStore
    /// that cannot be read is a datastore the operator stops reconciling —
    /// while the guests depending on it keep running.
    #[test]
    fn driver_wire_values_are_the_kebab_case_names() {
        for (driver, wire) in [
            (KobeStoreDriver::Etcd, "etcd"),
            (KobeStoreDriver::KineSqlite, "kine-sqlite"),
        ] {
            assert_eq!(
                serde_json::to_value(&driver).unwrap(),
                serde_json::Value::String(wire.to_string()),
                "{driver:?} must serialize as {wire:?}"
            );
            let back: KobeStoreDriver = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(
                serde_json::to_value(back).unwrap(),
                serde_json::Value::String(wire.to_string()),
                "{wire:?} must round-trip"
            );
        }

        // The camelCase spelling is NOT accepted — asserted so that adding a
        // rename_all here can't silently change the stored vocabulary.
        assert!(
            serde_json::from_str::<KobeStoreDriver>("\"kineSqlite\"").is_err(),
            "camelCase must not be an accepted driver spelling"
        );
    }

    /// The supported driver set, pinned. Adding one is a deliberate act with
    /// backend work behind it (#18 tracks Postgres/MySQL/NATS), so it should
    /// not be possible to widen this by accident.
    #[test]
    fn only_the_two_implemented_drivers_are_accepted() {
        for unsupported in ["postgres", "postgresql", "mysql", "nats", "sqlite", ""] {
            assert!(
                serde_json::from_str::<KobeStoreDriver>(&format!("\"{unsupported}\"")).is_err(),
                "{unsupported:?} must not deserialize as a driver — it has no backend"
            );
        }
    }

    /// The CRD's public identity.
    #[test]
    fn crd_identity_is_stable() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(KobeStore::crd()).unwrap();

        assert_eq!(crd["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(crd["spec"]["names"]["kind"], "KobeStore");
        assert_eq!(crd["spec"]["names"]["plural"], "kobestores");
        assert_eq!(crd["spec"]["names"]["shortNames"][0], "ks");
        assert_eq!(crd["metadata"]["name"], "kobestores.kobe.kunobi.ninja");

        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }
}
