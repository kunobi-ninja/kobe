use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Which storage driver the DataStore uses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub enum DataStoreDriver {
    /// Standard etcd cluster.
    #[serde(rename = "etcd")]
    Etcd,
    /// Kine-backed SQLite (single-node, lightweight).
    #[serde(rename = "kine-sqlite")]
    KineSqlite,
}

/// TLS configuration for connecting to the DataStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataStoreTls {
    /// Name of the Kubernetes Secret containing TLS credentials
    /// (ca.crt, tls.crt, tls.key).
    pub secret_ref: String,
}

/// Capacity limits for a DataStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataStoreCapacity {
    /// Maximum number of virtual clusters this DataStore can serve.
    pub max_clusters: u32,
}

/// Identifies a virtual cluster using this DataStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataStoreUser {
    /// Namespace of the virtual cluster.
    pub namespace: String,
    /// Name of the virtual cluster.
    pub name: String,
}

/// DataStore represents an external storage backend (etcd or kine-sqlite)
/// that virtual cluster kube-apiservers connect to via `--etcd-servers`
/// and `--etcd-prefix`.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kunobi.ninja",
    version = "v1alpha1",
    kind = "DataStore",
    plural = "datastores",
    shortname = "ds",
    status = "DataStoreStatus",
    namespaced,
    printcolumn = r#"{"name":"Driver","type":"string","jsonPath":".spec.driver"}"#,
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Clusters","type":"integer","jsonPath":".status.currentClusters"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct DataStoreSpec {
    /// Storage driver type.
    pub driver: DataStoreDriver,

    /// Endpoints to connect to (e.g. ["https://etcd-0:2379"]).
    pub endpoints: Vec<String>,

    /// Optional TLS configuration for the connection.
    #[serde(default)]
    pub tls: Option<DataStoreTls>,

    /// Capacity limits.
    pub capacity: DataStoreCapacity,

    /// Number of replicas for the storage backend (relevant for etcd).
    #[serde(default)]
    pub replicas: Option<u32>,
}

/// Runtime status of a DataStore.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct DataStoreStatus {
    /// Whether the DataStore is reachable and healthy.
    #[serde(default)]
    pub ready: bool,

    /// Number of virtual clusters currently using this DataStore.
    #[serde(default)]
    pub current_clusters: u32,

    /// List of virtual clusters using this DataStore.
    #[serde(default)]
    pub used_by: Vec<DataStoreUser>,
}
