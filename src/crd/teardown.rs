//! Verified-teardown vocabulary: cleanup modes, per-subject evidence, receipts,
//! and the pure eligibility rules that decide whether a footprint can be proven
//! absent at all.
//!
//! This module deliberately contains **no** teardown behaviour. It defines what
//! evidence looks like and which configurations can produce it; the k3s provider
//! and the controllers that consume it land separately.
//!
//! # Why receipts exist
//!
//! Today `ClusterBackend::delete` returns `Result<()>`, the instance controller
//! deletes the `ClusterInstance` once it returns, and the lease controller reads
//! the resulting 404 as "recycling complete". So an *accepted DELETE request* is
//! treated as proof of destruction. For capacity that held another tenant's code
//! and credentials that is not good enough: PVC, PDB, Pod and PostgreSQL
//! failures currently warn and continue, and nothing waits for the objects or
//! their backing volumes to actually disappear.
//!
//! A receipt replaces inference with evidence. The rule throughout is that
//! **uncertainty is not success**: anything we cannot observe becomes
//! [`CheckResult::Unknown`], which quarantines the capacity rather than
//! returning it to the pool.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ResourceRef;
use super::profile::{BackendType, ClusterConfig, DiagnosticsConfig};

/// How thoroughly a lease's capacity must be torn down before it can be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub enum CleanupMode {
    /// Today's behaviour: issue the deletes and trust an accepted request.
    ///
    /// Remains the default so existing `ClusterLease` objects are untouched.
    #[default]
    Standard,
    /// Removal of the final cleanup handle requires a verified receipt proving
    /// the exact lease-owned footprint is absent. Missing or uncertain evidence
    /// quarantines the unit instead of returning it to the pool.
    ///
    /// Only `backend.type=k3s` implements this; every other backend must reject
    /// it at bind time rather than silently degrading to [`Self::Standard`].
    VerifiedDestroy,
}

impl CleanupMode {
    /// Whether this mode requires evidence before capacity may be reused.
    pub fn requires_receipt(self) -> bool {
        matches!(self, Self::VerifiedDestroy)
    }
}

/// One thing whose absence must be proven.
///
/// Enumerated rather than free-text so a receipt cannot be satisfied by an
/// unrecognised or invented subject, and so adding a resource to the teardown
/// path is a deliberate, reviewable change to this list.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum TeardownSubject {
    AgentDeployment,
    ServerStatefulSet,
    ServerPods,
    Service,
    PodDisruptionBudget,
    PublisherConfigMap,
    RegistriesConfigMap,
    TokenSecret,
    KubeconfigSecret,
    /// The lease's connect-token Secret. Revoked first, verified like the rest.
    ConnectTokenSecret,
    /// The per-instance Secret carrying the PostgreSQL role password.
    DatastoreCredentialSecret,
    CidrClaim,
    /// Every `data-{instance}-server-{ordinal}` PVC.
    ServerDataPvcs,
    /// The PVs those PVCs were bound to, captured before deletion.
    ServerDataVolumes,
    /// The exact `k3s_<instance>` database.
    Database,
    /// The per-cluster PostgreSQL role that owns that database.
    ///
    /// Added after `fix(datastore): give each cluster its own PostgreSQL role`
    /// landed on main: k3s teardown now reclaims ownership, drops the database,
    /// *and* drops a role. Without this subject a leaked role would sit inside
    /// a receipt that claims the footprint is gone — the database would be
    /// proven absent while a credential-bearing role survived.
    DatabaseRole,
}

/// Current schema version for [`TeardownCreationManifest`].
pub const TEARDOWN_CREATION_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Exact identity of one Kubernetes object in a creation manifest.
///
/// Names are not identities: Kubernetes permits delete-and-recreate under the
/// same name. A UID is therefore mandatory for every recorded object, and a
/// receipt must account for the canonical identity rather than only its kind or
/// display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesResourceIdentity {
    pub api_version: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
}

impl KubernetesResourceIdentity {
    /// Stable, non-secret receipt identity including the Kubernetes UID fence.
    pub fn canonical_id(&self) -> String {
        format!(
            "k8s:{}:{}:{}:{}:{}",
            self.api_version,
            self.kind,
            self.namespace.as_deref().unwrap_or("_cluster"),
            self.name,
            self.uid
        )
    }

    /// Kubernetes object address without the UID fence. A manifest may not
    /// list two incarnations of the same address as if they were two replicas.
    fn object_key(&self) -> String {
        format!(
            "k8s:{}:{}:{}:{}",
            self.api_version,
            self.kind,
            self.namespace.as_deref().unwrap_or("_cluster"),
            self.name
        )
    }

    fn is_complete(&self) -> bool {
        !self.api_version.trim().is_empty()
            && !self.kind.trim().is_empty()
            && !self.name.trim().is_empty()
            && !self.uid.trim().is_empty()
            && self
                .namespace
                .as_deref()
                .is_none_or(|namespace| !namespace.trim().is_empty())
    }
}

/// One concrete Kubernetes resource created for the instance.
///
/// Repeating the same subject is intentional: it records multiplicity (for
/// example every server Pod and every PVC/PV) without weakening identity into a
/// selector or wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreationManifestResource {
    pub subject: TeardownSubject,
    pub resource: KubernetesResourceIdentity,
    /// Exact identity that controlled creation of this object.
    pub controller: KubernetesResourceIdentity,
    /// How the live object proves the controller relationship.
    pub control_relation: CreationControlRelation,
}

/// Kubernetes control edge authenticated while the object is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CreationControlRelation {
    /// `metadata.ownerReferences` contains this exact controller UID.
    ControllerOwner,
    /// A StatefulSet PVC carries the immutable ClusterInstance UID label.
    InstanceUidLabel,
    /// A PV's live `spec.claimRef.uid` is this exact PVC UID.
    ClaimRef,
}

/// Live dynamic-storage facts captured while the PVC and PV are both bound.
///
/// The StorageClass is referenced by exact UID and its reclaim policy is copied
/// from the live object. A configured class name, a later lookup, or a boolean
/// assertion is not enough to prove that deleting the claim destroys its data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageVolumeProvenance {
    pub pvc: KubernetesResourceIdentity,
    pub pv: KubernetesResourceIdentity,
    pub storage_class: KubernetesResourceIdentity,
    /// `StorageClass.reclaimPolicy` observed from the live class.
    pub reclaim_policy: String,
    /// `PersistentVolume.spec.persistentVolumeReclaimPolicy` observed from the
    /// bound PV. The PV is the final authority for what happens to its data.
    pub pv_reclaim_policy: String,
}

/// Actual datastore selected by the k3s backend at creation time.
///
/// The endpoint digest is computed after removing credentials and the database
/// path, so it identifies the PostgreSQL server without copying a secret into
/// CR status. PostgreSQL OIDs distinguish same-named recreated databases and
/// roles on that server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum DatastoreProvenance {
    EmbeddedSqlite,
    ExternalPostgres {
        /// Location selected by the workload, kept separately from the live
        /// cluster identity because DNS or an in-place reinitialization can
        /// preserve host and port while replacing all data.
        endpoint_digest: String,
        /// `pg_control_system().system_identifier` captured from the live
        /// PostgreSQL cluster at creation time.
        system_identifier: String,
        database: String,
        database_oid: String,
        role: String,
        role_oid: String,
    },
}

/// Structural OpenAPI projection of [`DatastoreProvenance`]. Kubernetes CRDs
/// cannot express the tagged enum's two different `mode` constants in a single
/// structural property, so the schema keeps the fields optional and the
/// controller's [`TeardownCreationManifest::validate`] enforces the exact
/// mode-specific contract before the manifest is trusted.
#[derive(JsonSchema)]
#[schemars(rename_all = "camelCase")]
#[allow(dead_code)]
enum DatastoreProvenanceModeSchema {
    EmbeddedSqlite,
    ExternalPostgres,
}

#[derive(JsonSchema)]
#[schemars(rename_all = "camelCase")]
#[allow(dead_code)]
struct DatastoreProvenanceSchema {
    mode: DatastoreProvenanceModeSchema,
    /// SHA-256 of the non-secret connection location (scheme, host and port).
    endpoint_digest: Option<String>,
    /// Live `pg_control_system().system_identifier` of the PostgreSQL cluster.
    system_identifier: Option<String>,
    database: Option<String>,
    database_oid: Option<String>,
    role: Option<String>,
    role_oid: Option<String>,
}

/// Immutable controller-authenticated inventory of what one instance created.
///
/// The instance controller writes this once to the status subresource after the
/// backend reports ready and every dynamic identity can be observed. The CRD
/// rejects changing or removing it afterwards. An absent manifest therefore
/// means "not yet provable" rather than permission to reconstruct a narrower
/// footprint at teardown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeardownCreationManifest {
    pub schema_version: u32,
    pub instance: ResourceRef,
    pub namespace: String,
    pub backend_type: BackendType,
    pub config_digest: String,
    pub service_cidr: String,
    pub cluster_cidr: String,
    pub server_replicas: u32,
    pub agent_replicas: u32,
    pub resources: Vec<CreationManifestResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<StorageVolumeProvenance>,
    #[schemars(with = "DatastoreProvenanceSchema")]
    pub datastore: DatastoreProvenance,
    pub sealed_at: String,
}

/// Why a creation manifest cannot authorize verified teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CreationManifestInvalid {
    #[error("unsupported creation manifest schema")]
    UnsupportedSchema,
    #[error("creation manifest identity or timestamp is incomplete")]
    IncompleteIdentity,
    #[error("creation manifest contains a duplicate concrete resource")]
    DuplicateResource,
    #[error("creation manifest does not match its declared multiplicity")]
    MultiplicityMismatch,
    #[error("dynamic storage provenance is incomplete or not reclaimable")]
    StorageUnverifiable,
    #[error("external datastore provenance is incomplete")]
    DatastoreUnverifiable,
}

impl TeardownCreationManifest {
    fn ordinal_name(name: &str, prefix: &str, replicas: u32) -> bool {
        name.strip_prefix(prefix)
            .and_then(|ordinal| ordinal.parse::<u32>().ok())
            .is_some_and(|ordinal| ordinal < replicas)
    }

    /// Subjects are not free-form labels: bind each one to the API, kind,
    /// namespace, and deterministic name shape the k3s backend actually owns.
    fn resource_shape_matches(&self, entry: &CreationManifestResource) -> bool {
        let identity = &entry.resource;
        let instance = &self.instance.name;
        let namespaced = identity.namespace.as_deref() == Some(self.namespace.as_str());
        let exact = |api_version: &str, kind: &str, name: String| {
            namespaced
                && identity.api_version == api_version
                && identity.kind == kind
                && identity.name == name
        };
        match entry.subject {
            TeardownSubject::AgentDeployment => {
                exact("apps/v1", "Deployment", format!("{instance}-agent"))
            }
            TeardownSubject::ServerStatefulSet => {
                exact("apps/v1", "StatefulSet", format!("{instance}-server"))
            }
            TeardownSubject::Service => exact("v1", "Service", format!("{instance}-server")),
            TeardownSubject::PodDisruptionBudget => exact(
                "policy/v1",
                "PodDisruptionBudget",
                format!("{instance}-server"),
            ),
            TeardownSubject::PublisherConfigMap => exact(
                "v1",
                "ConfigMap",
                format!("{instance}-kubeconfig-publisher"),
            ),
            TeardownSubject::RegistriesConfigMap => {
                exact("v1", "ConfigMap", format!("{instance}-registries"))
            }
            TeardownSubject::TokenSecret => exact("v1", "Secret", format!("{instance}-token")),
            TeardownSubject::KubeconfigSecret => {
                exact("v1", "Secret", format!("{instance}-kubeconfig"))
            }
            // Connect tokens are lease-scoped and named from the ClusterLease,
            // not the ClusterInstance. They must live in a separate immutable
            // binding footprint; accepting one here would authenticate the
            // wrong deterministic name and make the instance manifest mutable
            // after a lazy first connect.
            TeardownSubject::ConnectTokenSecret => false,
            TeardownSubject::DatastoreCredentialSecret => {
                exact("v1", "Secret", format!("{instance}-datastore"))
            }
            TeardownSubject::CidrClaim => {
                exact("kobe.kunobi.ninja/v1alpha1", "CIDRClaim", instance.clone())
            }
            TeardownSubject::ServerDataPvcs => {
                namespaced
                    && identity.api_version == "v1"
                    && identity.kind == "PersistentVolumeClaim"
                    && Self::ordinal_name(
                        &identity.name,
                        &format!("data-{instance}-server-"),
                        self.server_replicas,
                    )
            }
            TeardownSubject::ServerDataVolumes => {
                identity.namespace.is_none()
                    && identity.api_version == "v1"
                    && identity.kind == "PersistentVolume"
            }
            TeardownSubject::ServerPods => {
                namespaced
                    && identity.api_version == "v1"
                    && identity.kind == "Pod"
                    && Self::ordinal_name(
                        &identity.name,
                        &format!("{instance}-server-"),
                        self.server_replicas,
                    )
            }
            TeardownSubject::Database | TeardownSubject::DatabaseRole => false,
        }
    }

    fn instance_identity(&self) -> KubernetesResourceIdentity {
        KubernetesResourceIdentity {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "ClusterInstance".into(),
            namespace: Some(self.namespace.clone()),
            name: self.instance.name.clone(),
            uid: self.instance.uid.clone().unwrap_or_default(),
        }
    }

    fn control_shape_matches(&self, entry: &CreationManifestResource) -> bool {
        let instance = self.instance_identity();
        match entry.subject {
            TeardownSubject::ServerPods => {
                let statefulset = self
                    .resources
                    .iter()
                    .find(|candidate| candidate.subject == TeardownSubject::ServerStatefulSet);
                entry.control_relation == CreationControlRelation::ControllerOwner
                    && statefulset
                        .is_some_and(|statefulset| entry.controller == statefulset.resource)
            }
            TeardownSubject::ServerDataPvcs => {
                entry.control_relation == CreationControlRelation::InstanceUidLabel
                    && entry.controller == instance
            }
            TeardownSubject::ServerDataVolumes => {
                entry.control_relation == CreationControlRelation::ClaimRef
                    && self
                        .storage
                        .iter()
                        .any(|volume| volume.pv == entry.resource && volume.pvc == entry.controller)
            }
            TeardownSubject::Database | TeardownSubject::DatabaseRole => false,
            _ => {
                entry.control_relation == CreationControlRelation::ControllerOwner
                    && entry.controller == instance
            }
        }
    }

    /// Validate the sealed manifest before it becomes an authorization input.
    pub fn validate(&self) -> Result<(), CreationManifestInvalid> {
        let instance_fenced = self
            .instance
            .uid
            .as_deref()
            .is_some_and(|uid| !uid.trim().is_empty());
        if self.schema_version != TEARDOWN_CREATION_MANIFEST_SCHEMA_VERSION {
            return Err(CreationManifestInvalid::UnsupportedSchema);
        }
        if self.backend_type != BackendType::K3s
            || !instance_fenced
            || self.instance.name.trim().is_empty()
            || self.namespace.trim().is_empty()
            || self.config_digest.len() != 64
            || !self.config_digest.chars().all(|ch| ch.is_ascii_hexdigit())
            || self.service_cidr.trim().is_empty()
            || self.cluster_cidr.trim().is_empty()
            || self.server_replicas == 0
            || chrono::DateTime::parse_from_rfc3339(&self.sealed_at).is_err()
            || self.resources.iter().any(|entry| {
                !entry.resource.is_complete()
                    || !entry.controller.is_complete()
                    || !self.resource_shape_matches(entry)
                    || !self.control_shape_matches(entry)
            })
        {
            return Err(CreationManifestInvalid::IncompleteIdentity);
        }

        let mut identities = std::collections::BTreeSet::new();
        let mut object_keys = std::collections::BTreeSet::new();
        if self.resources.iter().any(|entry| {
            !identities.insert(entry.resource.canonical_id())
                || !object_keys.insert(entry.resource.object_key())
        }) {
            return Err(CreationManifestInvalid::DuplicateResource);
        }

        let count = |subject| {
            self.resources
                .iter()
                .filter(|entry| entry.subject == subject)
                .count()
        };
        let exactly_one = [
            TeardownSubject::ServerStatefulSet,
            TeardownSubject::Service,
            TeardownSubject::PublisherConfigMap,
            TeardownSubject::TokenSecret,
            TeardownSubject::KubeconfigSecret,
            TeardownSubject::CidrClaim,
        ]
        .into_iter()
        .all(|subject| count(subject) == 1);
        let optional_count_matches =
            |subject, expected| count(subject) == if expected { 1 } else { 0 };
        if !exactly_one
            || count(TeardownSubject::ServerPods) != self.server_replicas as usize
            || !optional_count_matches(TeardownSubject::AgentDeployment, self.agent_replicas > 0)
            || !optional_count_matches(
                TeardownSubject::PodDisruptionBudget,
                self.server_replicas > 1,
            )
            || count(TeardownSubject::RegistriesConfigMap) > 1
            || count(TeardownSubject::ConnectTokenSecret) != 0
        {
            return Err(CreationManifestInvalid::MultiplicityMismatch);
        }

        if self.storage.is_empty() {
            if count(TeardownSubject::ServerDataPvcs) != 0
                || count(TeardownSubject::ServerDataVolumes) != 0
            {
                return Err(CreationManifestInvalid::StorageUnverifiable);
            }
        } else {
            let manifest_pvcs: std::collections::BTreeSet<String> = self
                .resources
                .iter()
                .filter(|entry| entry.subject == TeardownSubject::ServerDataPvcs)
                .map(|entry| entry.resource.canonical_id())
                .collect();
            let manifest_pvs: std::collections::BTreeSet<String> = self
                .resources
                .iter()
                .filter(|entry| entry.subject == TeardownSubject::ServerDataVolumes)
                .map(|entry| entry.resource.canonical_id())
                .collect();
            let storage_pvcs: std::collections::BTreeSet<String> = self
                .storage
                .iter()
                .map(|volume| volume.pvc.canonical_id())
                .collect();
            let storage_pvs: std::collections::BTreeSet<String> = self
                .storage
                .iter()
                .map(|volume| volume.pv.canonical_id())
                .collect();
            if self.storage.len() != self.server_replicas as usize
                || count(TeardownSubject::ServerDataPvcs) != self.storage.len()
                || count(TeardownSubject::ServerDataVolumes) != self.storage.len()
                || storage_pvcs.len() != self.storage.len()
                || storage_pvs.len() != self.storage.len()
                || manifest_pvcs != storage_pvcs
                || manifest_pvs != storage_pvs
                || self.storage.iter().any(|volume| {
                    !volume.pvc.is_complete()
                        || !volume.pv.is_complete()
                        || !volume.storage_class.is_complete()
                        || volume.pvc.namespace.as_deref() != Some(self.namespace.as_str())
                        || volume.pvc.api_version != "v1"
                        || volume.pvc.kind != "PersistentVolumeClaim"
                        || volume.pv.namespace.is_some()
                        || volume.pv.api_version != "v1"
                        || volume.pv.kind != "PersistentVolume"
                        || volume.storage_class.namespace.is_some()
                        || volume.storage_class.api_version != "storage.k8s.io/v1"
                        || volume.storage_class.kind != "StorageClass"
                        || volume.reclaim_policy != "Delete"
                        || volume.pv_reclaim_policy != "Delete"
                })
            {
                return Err(CreationManifestInvalid::StorageUnverifiable);
            }
        }

        match &self.datastore {
            DatastoreProvenance::EmbeddedSqlite => {
                if count(TeardownSubject::DatastoreCredentialSecret) != 0 {
                    return Err(CreationManifestInvalid::DatastoreUnverifiable);
                }
            }
            DatastoreProvenance::ExternalPostgres {
                endpoint_digest,
                system_identifier,
                database,
                database_oid,
                role,
                role_oid,
            } => {
                if endpoint_digest.len() != 64
                    || !endpoint_digest.chars().all(|ch| ch.is_ascii_hexdigit())
                    || system_identifier
                        .parse::<u64>()
                        .map_or(true, |system_identifier| system_identifier == 0)
                    || database.trim().is_empty()
                    || database_oid
                        .parse::<u32>()
                        .map_or(true, |database_oid| database_oid == 0)
                    || role.trim().is_empty()
                    || role_oid
                        .parse::<u32>()
                        .map_or(true, |role_oid| role_oid == 0)
                    || count(TeardownSubject::DatastoreCredentialSecret) != 1
                {
                    return Err(CreationManifestInvalid::DatastoreUnverifiable);
                }
            }
        }
        Ok(())
    }

    /// Canonical SHA-256 used to bind a receipt to this immutable manifest.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        serde_json::to_vec(self).map(|encoded| hex::encode(Sha256::digest(encoded)))
    }

    /// Unique subjects that a receipt must cover. Optional footprints that were
    /// never created are absent because they have no manifest entry.
    pub fn required_subjects(&self) -> Vec<TeardownSubject> {
        let mut subjects = Vec::new();
        for entry in &self.resources {
            if !subjects.contains(&entry.subject) {
                subjects.push(entry.subject);
            }
        }
        if matches!(self.datastore, DatastoreProvenance::ExternalPostgres { .. }) {
            subjects.push(TeardownSubject::Database);
            subjects.push(TeardownSubject::DatabaseRole);
        }
        subjects
    }

    /// Every exact creation identity a successful receipt must account for.
    pub fn recorded_identities(&self) -> Vec<String> {
        let mut identities: Vec<String> = self
            .resources
            .iter()
            .map(|entry| entry.resource.canonical_id())
            .collect();
        if let DatastoreProvenance::ExternalPostgres {
            endpoint_digest,
            system_identifier,
            database,
            database_oid,
            role,
            role_oid,
        } = &self.datastore
        {
            identities.push(format!(
                "postgres:{system_identifier}:{endpoint_digest}:database:{database}:{database_oid}"
            ));
            identities.push(format!(
                "postgres:{system_identifier}:{endpoint_digest}:role:{role}:{role_oid}"
            ));
        }
        identities
    }

    /// Exact identities belonging to one teardown subject.
    pub fn identities_for_subject(&self, subject: TeardownSubject) -> Vec<String> {
        let mut identities: Vec<String> = self
            .resources
            .iter()
            .filter(|entry| entry.subject == subject)
            .map(|entry| entry.resource.canonical_id())
            .collect();
        if let DatastoreProvenance::ExternalPostgres {
            endpoint_digest,
            system_identifier,
            database,
            database_oid,
            role,
            role_oid,
        } = &self.datastore
        {
            match subject {
                TeardownSubject::Database => identities.push(format!(
                    "postgres:{system_identifier}:{endpoint_digest}:database:{database}:{database_oid}"
                )),
                TeardownSubject::DatabaseRole => {
                    identities.push(format!(
                        "postgres:{system_identifier}:{endpoint_digest}:role:{role}:{role_oid}"
                    ))
                }
                _ => {}
            }
        }
        identities
    }
}

/// Outcome of proving one subject absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CheckResult {
    /// Observed absent. The only result that contributes to a verified receipt.
    Verified,
    /// This footprint never existed, established from **recorded creation-time
    /// configuration** — not from a lookup that happened to return nothing.
    ///
    /// The distinction matters: "the pool never enabled registry mirrors" is
    /// `NotApplicable`; "listing ConfigMaps returned 403" is [`Self::Unknown`].
    NotApplicable,
    /// Could not be determined: an API or RBAC error, a timeout, an
    /// unreachable datastore, or a UID that no longer matches. Quarantines.
    Unknown,
}

/// Aggregate verdict for one teardown attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum TeardownOutcome {
    /// Attempt nonce and start time were persisted before deletion began.
    InProgress,
    /// Every required subject is `Verified` or `NotApplicable`.
    Verified,
    /// At least one subject is `Unknown`. Capacity is not reusable.
    Quarantined,
}

/// Evidence for one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeardownCheck {
    pub subject: TeardownSubject,
    pub result: CheckResult,
    /// Bounded, non-secret reason code (e.g. `pv_still_present`,
    /// `datastore_unreachable`). Never a raw provider response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// The concrete resources this check actually looked at.
    ///
    /// A [`TeardownSubject`] is a category. On its own,
    /// `Database = Verified` asserts that *a* database is gone without saying
    /// which — so a receipt could be satisfied by checking the wrong one, or by
    /// checking one of several when the footprint had more. Recording the exact
    /// identities makes the claim auditable after the fact, which is the whole
    /// point of keeping evidence that outlives the instance.
    ///
    /// Names only: object names, PV names, the database and role identifiers.
    /// Never connection strings, credentials, or anything that would turn a
    /// receipt into a secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified: Vec<String>,
}

/// Durable proof that one exact lease-owned footprint is gone.
///
/// Lives on `ClusterLeaseStatus` rather than on the `ClusterInstance`, because
/// it must remain queryable **after** the instance object disappears — that is
/// precisely the moment the evidence matters, and #74's owning `SandboxLease`
/// has to be able to consume it afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeardownReceipt {
    /// Schema version, so a consumer can refuse evidence it does not understand
    /// rather than misread an older shape as complete.
    pub schema_version: u32,
    /// Unique per attempt. Reconcile resumes an `InProgress` nonce unchanged;
    /// a later retry may replace a terminal receipt with a new attempt, but it
    /// never rewrites the identity of an active attempt.
    pub attempt_id: String,
    /// Exact subjects this receipt is about. A same-named replacement is a
    /// mismatch, not successful absence.
    pub lease: ResourceRef,
    pub instance: ResourceRef,
    pub pool: ResourceRef,
    /// Backend identity and immutable provenance digest observed at bind time.
    pub backend_type: String,
    pub config_digest: String,
    pub instance_spec_digest: String,
    /// SHA-256 of the immutable controller-authenticated creation manifest.
    #[serde(default)]
    pub creation_manifest_digest: String,
    /// Cleanup contract captured in the reciprocal binding. A receipt for a
    /// Standard teardown can never release VerifiedDestroy capacity.
    #[serde(default)]
    pub cleanup_mode: CleanupMode,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub checks: Vec<TeardownCheck>,
    #[serde(default)]
    pub retry_count: u32,
    pub outcome: TeardownOutcome,
}

/// Set by a consumer once it has read and acted on a lease's teardown receipt.
///
/// Until this is present, a receipt-carrying lease is retained after recycling
/// rather than deleted — the receipt is the only durable proof its capacity was
/// destroyed, and it is read precisely when the instance is already gone.
///
/// An annotation rather than a timeout: evidence that expires on a clock is
/// evidence you cannot rely on having when you need it.
pub const TEARDOWN_RECEIPT_ACKNOWLEDGED_ANNOTATION: &str =
    "kobe.kunobi.ninja/teardown-receipt-acknowledged";

/// Set by the composing Sandbox after it durably records that an internal
/// `ClusterLease` reached a terminal phase without ever binding an instance.
/// The value is `<teardownAttemptId>:<unboundReleaseVerifiedAt>`, so a stale
/// ACK cannot retire a later proof attempt on the same retained handle.
pub const UNBOUND_RELEASE_PROOF_ACKNOWLEDGED_ANNOTATION: &str =
    "kobe.kunobi.ninja/unbound-release-proof-acknowledged";

/// Retains a receipt-bearing lease until its exact receipt identity has been
/// acknowledged by the owning consumer.
pub const TEARDOWN_RECEIPT_RETENTION_FINALIZER: &str =
    "kobe.kunobi.ninja/teardown-receipt-retention";

/// Current schema version emitted by this build.
pub const TEARDOWN_RECEIPT_SCHEMA_VERSION: u32 = 1;

impl TeardownReceipt {
    /// Derive the aggregate outcome from the per-subject evidence.
    ///
    /// Deliberately not stored independently of `checks`: an outcome that could
    /// disagree with its own evidence is exactly the failure mode receipts exist
    /// to prevent.
    pub fn outcome_for(checks: &[TeardownCheck]) -> TeardownOutcome {
        if checks
            .iter()
            .any(|check| check.result == CheckResult::Unknown)
        {
            TeardownOutcome::Quarantined
        } else {
            TeardownOutcome::Verified
        }
    }

    /// Stable acknowledgement token for this exact terminal receipt.
    ///
    /// The value intentionally includes every capability fence a consumer must
    /// have observed: attempt nonce, all three Kubernetes UIDs, creation
    /// manifest digest, and cleanup mode. A boolean annotation (or an old
    /// attempt ID alone) could acknowledge a newer receipt after a retry.
    pub fn acknowledgement_token(&self) -> Option<String> {
        if self.schema_version != TEARDOWN_RECEIPT_SCHEMA_VERSION
            || self.outcome != TeardownOutcome::Verified
            || self.checks.is_empty()
            || Self::outcome_for(&self.checks) != TeardownOutcome::Verified
            || !self.completed_after_start()
            || self.attempt_id.trim().is_empty()
            || self.creation_manifest_digest.trim().is_empty()
            || self.cleanup_mode != CleanupMode::VerifiedDestroy
        {
            return None;
        }
        let lease_uid = self.lease.uid.as_deref()?.trim();
        let instance_uid = self.instance.uid.as_deref()?.trim();
        let pool_uid = self.pool.uid.as_deref()?.trim();
        if lease_uid.is_empty() || instance_uid.is_empty() || pool_uid.is_empty() {
            return None;
        }
        let _ = (lease_uid, instance_uid, pool_uid);
        // Hash the entire schema-versioned terminal record. This includes the
        // required attempt/UID/manifest/mode fences and also prevents a token
        // from acknowledging changed checks or timestamps under the same
        // nominal attempt identity.
        let encoded = serde_json::to_vec(self).ok()?;
        Some(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
    }

    /// Whether this receipt releases the exact footprint described by
    /// `expected`.
    ///
    /// A receipt is only proof of *what it actually covers*. An earlier version
    /// asked only "no `Unknown`, and not empty", which meant a receipt carrying
    /// one `serverStatefulSet=verified` check released capacity while saying
    /// nothing about the database, credentials, volumes, or Pods. Absence of
    /// evidence read as evidence of absence — the exact inversion receipts
    /// exist to prevent.
    ///
    /// `expected` must come from controller-owned bind-time state, never from
    /// the receipt being validated: a receipt that vouches for its own scope
    /// proves nothing.
    ///
    /// Requires all of:
    /// - a schema version this build understands;
    /// - a completion timestamp — an unfinished attempt is not proof;
    /// - the recorded verdict agreeing with the checks;
    /// - identity matching `expected` exactly, so a receipt from another
    ///   attempt or a same-named replacement cannot be replayed;
    /// - exactly one `Verified` check per expected subject — no missing
    ///   subjects, no duplicates, no extras, and no `NotApplicable` standing in
    ///   for a subject the scope says was created.
    pub fn permits_release_for(&self, expected: &TeardownScope<'_>) -> bool {
        if self.schema_version != TEARDOWN_RECEIPT_SCHEMA_VERSION
            || self.attempt_id.trim().is_empty()
            || self.attempt_id != expected.attempt_id
            || !self.completed_after_start()
            || self.outcome != TeardownOutcome::Verified
            || Self::outcome_for(&self.checks) != TeardownOutcome::Verified
        {
            return false;
        }
        // A reference without a UID cannot fence anything: two absent UIDs
        // compare equal, so a same-named replacement would satisfy the match
        // that is supposed to exclude it.
        //
        // EMPTY counts as absent. `Some("")` is not a UID, and checking only
        // for `None` left the exact hole this paragraph describes: two empty
        // strings compare equal just as happily as two `None`s.
        let fenced = |reference: &ResourceRef| {
            reference
                .uid
                .as_deref()
                .is_some_and(|uid| !uid.trim().is_empty())
        };
        if !fenced(&self.lease) || !fenced(&self.instance) || !fenced(&self.pool) {
            return false;
        }
        // Identity, not just shape: a valid receipt for a *different* subject
        // must not release this one.
        if self.lease != *expected.lease
            || self.instance != *expected.instance
            || self.pool != *expected.pool
            || self.backend_type != expected.backend_type
            || self.config_digest != expected.config_digest
            || self.instance_spec_digest != expected.instance_spec_digest
            || self.creation_manifest_digest != expected.creation_manifest_digest
            || self.cleanup_mode != expected.cleanup_mode
        {
            return false;
        }
        if expected.required_subjects.is_empty() {
            // Nothing to prove means nothing was proven. Fail closed rather
            // than treat an empty plan as a clean bill of health.
            return false;
        }
        if self.checks.len() != expected.required_subjects.len() {
            return false;
        }
        // Every recorded identity must appear in some verified check. A receipt
        // that proved three of four volumes gone would otherwise pass, leaving
        // the fourth — and the tenant data on it — behind.
        let proven: Vec<&String> = self
            .checks
            .iter()
            .filter(|check| check.result == CheckResult::Verified)
            .flat_map(|check| check.verified.iter())
            .collect();
        if !expected
            .recorded_identities
            .iter()
            .all(|identity| proven.contains(&identity))
        {
            return false;
        }

        expected.required_subjects.iter().all(|subject| {
            let mut matching = self.checks.iter().filter(|check| check.subject == *subject);
            let Some(check) = matching.next() else {
                return false;
            };
            // Exactly one: duplicates could otherwise pair a Verified with a
            // silently ignored second opinion.
            //
            // And it must be Verified, not merely "not Unknown". Accepting
            // NotApplicable here would let a receipt mark the database and
            // credentials as never-created and still release the lease. A
            // footprint that genuinely was never created belongs OUT of
            // `required_subjects` — that is what the scope is for.
            if matching.next().is_some() || check.result != CheckResult::Verified {
                return false;
            }
            // Where the name is derivable, the check must actually name it.
            // Otherwise `ServerStatefulSet = Verified` proves only that
            // *something* of that category was inspected.
            if let Some(manifest) = expected.creation_manifest {
                let identities = if *subject == TeardownSubject::ConnectTokenSecret {
                    expected
                        .connect_token_identity
                        .map(|identity| vec![identity.canonical_id()])
                        .unwrap_or_default()
                } else {
                    manifest.identities_for_subject(*subject)
                };
                check.verified.len() == identities.len()
                    && identities
                        .iter()
                        .all(|identity| check.verified.contains(identity))
            } else if expected.recorded_identities.is_empty() {
                match expected_identity_for(*subject, expected.instance_name) {
                    Some(expected_name) => check.verified.contains(&expected_name),
                    None => true,
                }
            } else {
                // Concrete manifest identities (including UIDs/OIDs) were
                // already checked for complete coverage above. Do not weaken
                // them back to the legacy name-only representation here.
                true
            }
        })
    }

    /// Both timestamps must be RFC3339 and completion must be strictly after
    /// the persisted attempt start. Arbitrary strings are not ordering proof.
    pub fn completed_after_start(&self) -> bool {
        let Ok(started) = chrono::DateTime::parse_from_rfc3339(&self.started_at) else {
            return false;
        };
        let Some(completed_at) = self.completed_at.as_deref() else {
            return false;
        };
        let Ok(completed) = chrono::DateTime::parse_from_rfc3339(completed_at) else {
            return false;
        };
        completed > started
    }
}

/// The exact footprint a receipt must account for, derived from
/// controller-owned bind-time state.
///
/// Separate from [`TeardownReceipt`] on purpose. The receipt is mutable status
/// written by the teardown path; the scope is the trusted record of what that
/// path was supposed to destroy. Validating a receipt against fields carried
/// inside itself would let a truncated or replayed receipt define its own
/// success criteria.
#[derive(Debug, Clone, Copy)]
pub struct TeardownScope<'a> {
    pub lease: &'a ResourceRef,
    pub instance: &'a ResourceRef,
    pub pool: &'a ResourceRef,
    pub backend_type: &'a str,
    pub config_digest: &'a str,
    pub instance_spec_digest: &'a str,
    pub creation_manifest_digest: &'a str,
    pub cleanup_mode: CleanupMode,
    /// Nonce persisted before the first destructive request.
    pub attempt_id: &'a str,
    /// Controller-authenticated creation record used to keep each concrete
    /// identity bound to the subject whose absence the check claims to prove.
    /// Without this association, a receipt could place a PV UID under the Pod
    /// check and still satisfy flattened identity coverage.
    pub creation_manifest: Option<&'a TeardownCreationManifest>,
    /// Lease-scoped footprint captured in the reciprocal binding. It cannot be
    /// part of the instance creation manifest because no lease existed then.
    pub connect_token_identity: Option<&'a KubernetesResourceIdentity>,
    /// Every subject this instance actually created. Optional footprints that
    /// were never created are simply absent — which is why the list must come
    /// from the creation record, not be inferred at teardown time.
    pub required_subjects: &'a [TeardownSubject],
    /// Used to derive the expected resource names. Comes from controller-owned
    /// bind-time state like the rest of this scope, never from the receipt.
    pub instance_name: &'a str,
    /// Provisioner-assigned identities recorded while the instance was healthy
    /// — the PersistentVolumes its claims were bound to.
    ///
    /// These cannot be derived from a name, so they are the one part of the
    /// footprint a teardown could otherwise quietly omit. Recorded long before
    /// teardown runs, they are something a receipt must account for rather than
    /// something it gets to choose.
    pub recorded_identities: &'a [String],
}

/// The name a subject's resource must have, where naming is deterministic.
///
/// This is the non-circular half of identity checking: it comes from the
/// recorded plan and the instance name, never from the receipt being validated.
/// A receipt claiming `ServerStatefulSet = Verified` while naming some other
/// object therefore fails, rather than being accepted because the category
/// matched.
///
/// `None` for subjects whose identity cannot be derived — the bound PV names
/// are assigned by the provisioner, and the Pod set is a label selector. Those
/// are still RECORDED in the receipt for audit; they simply cannot be
/// pre-computed here.
pub fn expected_identity_for(subject: TeardownSubject, instance: &str) -> Option<String> {
    let name = match subject {
        TeardownSubject::AgentDeployment => format!("{instance}-agent"),
        TeardownSubject::ServerStatefulSet => format!("{instance}-server"),
        TeardownSubject::Service => format!("{instance}-server"),
        TeardownSubject::PodDisruptionBudget => format!("{instance}-server"),
        TeardownSubject::PublisherConfigMap => format!("{instance}-kubeconfig-publisher"),
        TeardownSubject::RegistriesConfigMap => format!("{instance}-registries"),
        TeardownSubject::TokenSecret => format!("{instance}-token"),
        TeardownSubject::KubeconfigSecret => format!("{instance}-kubeconfig"),
        TeardownSubject::ConnectTokenSecret => format!("{instance}-connect-token"),
        TeardownSubject::DatastoreCredentialSecret => format!("{instance}-datastore"),
        TeardownSubject::CidrClaim => instance.to_string(),
        TeardownSubject::Database => format!("database:k3s_{instance}"),
        TeardownSubject::DatabaseRole => format!("role:k3s_{instance}"),
        // Provisioner-assigned or selector-based; recorded, not derivable.
        TeardownSubject::ServerPods
        | TeardownSubject::ServerDataPvcs
        | TeardownSubject::ServerDataVolumes => return None,
    };
    Some(name)
}

/// Derive the exact set of footprints a k3s instance creates, from the config
/// it is being created with.
///
/// Called at **creation** and stamped into immutable provenance — never
/// recomputed at teardown. Recomputing later would read whatever the config
/// says *then*, so a pool that stopped setting `registryMirrors` after an
/// instance was made would drop that ConfigMap from the plan and never verify
/// it. The plan has to describe what was built, not what would be built now.
///
/// Subjects that are always created are unconditional; the rest are included
/// only when the config that creates them is present. A footprint absent from
/// this list is not "excused" at teardown — it is simply not part of what this
/// instance made.
pub fn k3s_teardown_plan(
    cluster: &ClusterConfig,
    has_external_datastore: bool,
) -> Vec<TeardownSubject> {
    let mut plan = vec![
        // Always created by the k3s backend.
        TeardownSubject::ServerStatefulSet,
        TeardownSubject::ServerPods,
        TeardownSubject::Service,
        TeardownSubject::PublisherConfigMap,
        TeardownSubject::TokenSecret,
        TeardownSubject::KubeconfigSecret,
        TeardownSubject::CidrClaim,
        TeardownSubject::ConnectTokenSecret,
    ];

    // Agents are a separate Deployment only when the pool asks for them.
    if cluster.agents.is_some_and(|agents| agents > 0) {
        plan.push(TeardownSubject::AgentDeployment);
    }
    // The HA PodDisruptionBudget exists only for multi-server pools.
    if cluster.servers > 1 {
        plan.push(TeardownSubject::PodDisruptionBudget);
    }
    if cluster
        .registry_mirrors
        .as_ref()
        .is_some_and(|mirrors| !mirrors.is_empty())
    {
        plan.push(TeardownSubject::RegistriesConfigMap);
    }
    // Persistent storage means PVCs and the volumes behind them. Both, always
    // together: proving the claim gone while its volume survives is precisely
    // the gap that makes a receipt a lie.
    if cluster
        .persistence
        .as_ref()
        .is_some_and(|persistence| !storage_is_ephemeral(persistence))
    {
        plan.push(TeardownSubject::ServerDataPvcs);
        plan.push(TeardownSubject::ServerDataVolumes);
    }
    // A per-cluster database always comes with the role that owns it.
    if has_external_datastore {
        plan.push(TeardownSubject::DatastoreCredentialSecret);
        plan.push(TeardownSubject::Database);
        plan.push(TeardownSubject::DatabaseRole);
    }
    plan
}

/// Whether a persistence config allocates no durable volume.
fn storage_is_ephemeral(persistence: &super::profile::PersistenceConfig) -> bool {
    persistence
        .storage_type
        .as_deref()
        .unwrap_or("emptyDir")
        .eq_ignore_ascii_case("emptydir")
}

/// Why a pool's footprint cannot support [`CleanupMode::VerifiedDestroy`].
///
/// Rejected **before binding**. An ineligible pool must never accept a
/// receipt-required lease and then discover mid-teardown that it cannot produce
/// evidence — that would strand the lease in quarantine through no fault of the
/// caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedDestroyIneligible {
    #[error("backend does not implement verified teardown")]
    UnsupportedBackend,
    #[error("kubeletSharedMount leaves host state this receipt cannot account for")]
    KubeletSharedMount,
    #[error("diagnostics capture writes objects whose deletion is not receipt-verifiable")]
    DiagnosticsEnabled,
    #[error("storage is neither ephemeral nor dynamically provisioned with an observable volume")]
    UnverifiableStorage,
    #[error("external datastore identity was not recorded, so its absence cannot be proven")]
    DatastoreProvenanceMissing,
}

impl VerifiedDestroyIneligible {
    /// Bounded reason code for status, events, and metrics.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedBackend => "unsupported_backend",
            Self::KubeletSharedMount => "kubelet_shared_mount",
            Self::DiagnosticsEnabled => "diagnostics_enabled",
            Self::UnverifiableStorage => "unverifiable_storage",
            Self::DatastoreProvenanceMissing => "datastore_provenance_missing",
        }
    }
}

/// Whether a k3s cluster configuration can produce a verifiable receipt.
///
/// Pure and total: every rejection is derived from recorded configuration, never
/// from a live lookup, so the same inputs always yield the same verdict and the
/// decision can be made at bind time.
///
/// `external_datastore_identity_recorded` is threaded in rather than read here
/// because the datastore connection lives outside the CRD; the caller knows
/// whether the exact database identity needed to verify absence was captured.
pub fn verified_destroy_eligibility(
    backend: &BackendType,
    cluster: &ClusterConfig,
    diagnostics: Option<&DiagnosticsConfig>,
    external_datastore_identity_recorded: bool,
) -> Result<(), VerifiedDestroyIneligible> {
    // Only k3s can produce evidence. Every other backend must be refused here
    // rather than degrade to Standard cleanup while still claiming a verified
    // mode. Previously this variant existed but was unreachable, because the
    // function had no backend to judge — so a non-k3s pool received Ok(()).
    if *backend != BackendType::K3s {
        return Err(VerifiedDestroyIneligible::UnsupportedBackend);
    }

    // Host-side kubelet trees survive object deletion and are not part of any
    // subject we can observe from the API, so their presence makes "the
    // footprint is absent" unprovable. Re-admissible once the host reaper's
    // acknowledgement becomes part of the receipt.
    if cluster.kubelet_shared_mount.is_some() {
        return Err(VerifiedDestroyIneligible::KubeletSharedMount);
    }

    // Diagnostics capture writes bundles to S3 on release. Object deletion there
    // is not receipt-verifiable today, and a receipt that silently ignored them
    // would overstate what was destroyed.
    if diagnostics.is_some_and(|diagnostics| diagnostics.enabled) {
        return Err(VerifiedDestroyIneligible::DiagnosticsEnabled);
    }

    // Storage must be either non-persistent, or dynamically provisioned so the
    // PVC and its backing PV can be observed disappearing. A pool that pins a
    // storage class we cannot reason about is rejected rather than assumed
    // deletable — the reclaim policy itself is checked against the live
    // StorageClass by the provider, since it is not part of this config.
    if let Some(persistence) = cluster.persistence.as_ref() {
        let storage_type = persistence.storage_type.as_deref().unwrap_or("emptyDir");
        let ephemeral = storage_type.eq_ignore_ascii_case("emptydir");
        let dynamic = storage_type.eq_ignore_ascii_case("dynamic");
        if !ephemeral && !dynamic {
            return Err(VerifiedDestroyIneligible::UnverifiableStorage);
        }
    }

    if !external_datastore_identity_recorded {
        return Err(VerifiedDestroyIneligible::DatastoreProvenanceMissing);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::profile::{KubeletSharedMountConfig, PersistenceConfig};

    fn cluster() -> ClusterConfig {
        serde_json::from_value(serde_json::json!({ "version": "v1.32.0" }))
            .expect("minimal ClusterConfig must deserialize")
    }

    fn manifest_identity(
        api_version: &str,
        kind: &str,
        name: &str,
        uid: &str,
        namespaced: bool,
    ) -> KubernetesResourceIdentity {
        KubernetesResourceIdentity {
            api_version: api_version.into(),
            kind: kind.into(),
            namespace: namespaced.then(|| "test-ns".into()),
            name: name.into(),
            uid: uid.into(),
        }
    }

    fn manifest_entry(
        subject: TeardownSubject,
        api_version: &str,
        kind: &str,
        name: &str,
        uid: &str,
    ) -> CreationManifestResource {
        let (controller, control_relation) = match subject {
            TeardownSubject::ServerPods => (
                manifest_identity("apps/v1", "StatefulSet", "pool-p-0-server", "sts-uid", true),
                CreationControlRelation::ControllerOwner,
            ),
            _ => (
                manifest_identity(
                    "kobe.kunobi.ninja/v1alpha1",
                    "ClusterInstance",
                    "pool-p-0",
                    "instance-uid",
                    true,
                ),
                CreationControlRelation::ControllerOwner,
            ),
        };
        CreationManifestResource {
            subject,
            resource: manifest_identity(api_version, kind, name, uid, true),
            controller,
            control_relation,
        }
    }

    fn minimal_creation_manifest() -> TeardownCreationManifest {
        TeardownCreationManifest {
            schema_version: TEARDOWN_CREATION_MANIFEST_SCHEMA_VERSION,
            instance: ResourceRef {
                name: "pool-p-0".into(),
                uid: Some("instance-uid".into()),
            },
            namespace: "test-ns".into(),
            backend_type: BackendType::K3s,
            config_digest: "a".repeat(64),
            service_cidr: "10.240.0.0/20".into(),
            cluster_cidr: "10.248.0.0/20".into(),
            server_replicas: 1,
            agent_replicas: 0,
            resources: vec![
                manifest_entry(
                    TeardownSubject::ServerStatefulSet,
                    "apps/v1",
                    "StatefulSet",
                    "pool-p-0-server",
                    "sts-uid",
                ),
                manifest_entry(
                    TeardownSubject::Service,
                    "v1",
                    "Service",
                    "pool-p-0-server",
                    "service-uid",
                ),
                manifest_entry(
                    TeardownSubject::PublisherConfigMap,
                    "v1",
                    "ConfigMap",
                    "pool-p-0-kubeconfig-publisher",
                    "publisher-uid",
                ),
                manifest_entry(
                    TeardownSubject::TokenSecret,
                    "v1",
                    "Secret",
                    "pool-p-0-token",
                    "token-uid",
                ),
                manifest_entry(
                    TeardownSubject::KubeconfigSecret,
                    "v1",
                    "Secret",
                    "pool-p-0-kubeconfig",
                    "kubeconfig-uid",
                ),
                manifest_entry(
                    TeardownSubject::CidrClaim,
                    "kobe.kunobi.ninja/v1alpha1",
                    "CIDRClaim",
                    "pool-p-0",
                    "cidr-uid",
                ),
                manifest_entry(
                    TeardownSubject::ServerPods,
                    "v1",
                    "Pod",
                    "pool-p-0-server-0",
                    "pod-uid",
                ),
            ],
            storage: Vec::new(),
            datastore: DatastoreProvenance::EmbeddedSqlite,
            sealed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn creation_manifest_accepts_absent_optional_footprints() {
        let manifest = minimal_creation_manifest();
        assert!(manifest.validate().is_ok());
        let subjects = manifest.required_subjects();
        for absent in [
            TeardownSubject::AgentDeployment,
            TeardownSubject::PodDisruptionBudget,
            TeardownSubject::RegistriesConfigMap,
            TeardownSubject::ConnectTokenSecret,
            TeardownSubject::DatastoreCredentialSecret,
            TeardownSubject::ServerDataPvcs,
            TeardownSubject::ServerDataVolumes,
            TeardownSubject::Database,
            TeardownSubject::DatabaseRole,
        ] {
            assert!(!subjects.contains(&absent), "{absent:?} was not created");
        }
    }

    #[test]
    fn instance_manifest_rejects_a_lease_scoped_connect_token() {
        let mut manifest = minimal_creation_manifest();
        manifest.resources.push(manifest_entry(
            TeardownSubject::ConnectTokenSecret,
            "v1",
            "Secret",
            "lease-a-connect-token",
            "connect-token-uid",
        ));
        assert_eq!(
            manifest.validate(),
            Err(CreationManifestInvalid::IncompleteIdentity),
            "the lease controller must seal the lazy token under its lease name"
        );
    }

    #[test]
    fn creation_manifest_rejects_omission_duplicate_and_wrong_multiplicity() {
        let mut omitted = minimal_creation_manifest();
        omitted
            .resources
            .retain(|entry| entry.subject != TeardownSubject::TokenSecret);
        assert_eq!(
            omitted.validate(),
            Err(CreationManifestInvalid::MultiplicityMismatch)
        );

        let mut duplicate = minimal_creation_manifest();
        duplicate.resources.push(duplicate.resources[0].clone());
        assert_eq!(
            duplicate.validate(),
            Err(CreationManifestInvalid::DuplicateResource)
        );

        let mut recreated_duplicate = minimal_creation_manifest();
        let mut second_incarnation = recreated_duplicate.resources[0].clone();
        second_incarnation.resource.uid = "replacement-sts-uid".into();
        recreated_duplicate.resources.push(second_incarnation);
        recreated_duplicate.server_replicas = 2;
        assert_eq!(
            recreated_duplicate.validate(),
            Err(CreationManifestInvalid::DuplicateResource),
            "two UIDs for one Kubernetes address are not two replicas"
        );

        let mut wrong_replicas = minimal_creation_manifest();
        wrong_replicas.server_replicas = 2;
        assert_eq!(
            wrong_replicas.validate(),
            Err(CreationManifestInvalid::MultiplicityMismatch)
        );
    }

    #[test]
    fn creation_manifest_requires_complete_dynamic_storage_provenance() {
        let mut manifest = minimal_creation_manifest();
        let pvc = manifest_identity(
            "v1",
            "PersistentVolumeClaim",
            "data-pool-p-0-server-0",
            "pvc-uid",
            true,
        );
        let pv = manifest_identity("v1", "PersistentVolume", "pv-a", "pv-uid", false);
        let storage_class = manifest_identity(
            "storage.k8s.io/v1",
            "StorageClass",
            "fast-delete",
            "sc-uid",
            false,
        );
        manifest.resources.push(CreationManifestResource {
            subject: TeardownSubject::ServerDataPvcs,
            resource: pvc.clone(),
            controller: manifest_identity(
                "kobe.kunobi.ninja/v1alpha1",
                "ClusterInstance",
                "pool-p-0",
                "instance-uid",
                true,
            ),
            control_relation: CreationControlRelation::InstanceUidLabel,
        });
        manifest.resources.push(CreationManifestResource {
            subject: TeardownSubject::ServerDataVolumes,
            resource: pv.clone(),
            controller: pvc.clone(),
            control_relation: CreationControlRelation::ClaimRef,
        });
        manifest.storage.push(StorageVolumeProvenance {
            pvc,
            pv,
            storage_class,
            reclaim_policy: "Delete".into(),
            pv_reclaim_policy: "Delete".into(),
        });
        assert!(manifest.validate().is_ok());

        let mut retained = manifest.clone();
        retained.storage[0].pv_reclaim_policy = "Retain".into();
        assert_eq!(
            retained.validate(),
            Err(CreationManifestInvalid::StorageUnverifiable)
        );

        let mut unrecorded = manifest;
        unrecorded.storage[0].pv.uid = "unrecorded-pv-uid".into();
        assert_eq!(
            unrecorded.validate(),
            Err(CreationManifestInvalid::IncompleteIdentity),
            "the PV claimRef control edge must match the exact recorded PV/PVC pair"
        );
    }

    #[test]
    fn external_datastore_requires_exact_database_role_and_secret() {
        let mut manifest = minimal_creation_manifest();
        manifest.datastore = DatastoreProvenance::ExternalPostgres {
            endpoint_digest: "b".repeat(64),
            system_identifier: "72623859790382856".into(),
            database: "k3s_pool_p_0".into(),
            database_oid: "16384".into(),
            role: "k3s_pool_p_0".into(),
            role_oid: "16385".into(),
        };
        assert_eq!(
            manifest.validate(),
            Err(CreationManifestInvalid::DatastoreUnverifiable)
        );

        manifest.resources.push(manifest_entry(
            TeardownSubject::DatastoreCredentialSecret,
            "v1",
            "Secret",
            "pool-p-0-datastore",
            "datastore-secret-uid",
        ));
        assert!(manifest.validate().is_ok());
        let exact_database_identity = manifest
            .identities_for_subject(TeardownSubject::Database)
            .pop()
            .unwrap();
        assert!(exact_database_identity.starts_with(
            "postgres:72623859790382856:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:database:"
        ));
        assert!(
            manifest
                .required_subjects()
                .contains(&TeardownSubject::Database)
        );
        assert!(
            manifest
                .required_subjects()
                .contains(&TeardownSubject::DatabaseRole)
        );

        let mut missing_cluster_identity = manifest.clone();
        let DatastoreProvenance::ExternalPostgres {
            system_identifier, ..
        } = &mut missing_cluster_identity.datastore
        else {
            unreachable!();
        };
        *system_identifier = "0".into();
        assert_eq!(
            missing_cluster_identity.validate(),
            Err(CreationManifestInvalid::DatastoreUnverifiable)
        );

        let mut replacement_cluster = manifest.clone();
        let DatastoreProvenance::ExternalPostgres {
            system_identifier, ..
        } = &mut replacement_cluster.datastore
        else {
            unreachable!();
        };
        *system_identifier = "72623859790382857".into();
        assert_ne!(
            manifest.digest().unwrap(),
            replacement_cluster.digest().unwrap()
        );
        assert_ne!(
            manifest.identities_for_subject(TeardownSubject::Database),
            replacement_cluster.identities_for_subject(TeardownSubject::Database)
        );
    }

    #[test]
    fn manifest_digest_changes_when_a_same_named_resource_is_recreated() {
        let original = minimal_creation_manifest();
        let mut recreated = original.clone();
        recreated.resources[0].resource.uid = "replacement-sts-uid".into();
        assert_ne!(original.digest().unwrap(), recreated.digest().unwrap());
    }

    #[test]
    fn ephemeral_k3s_with_recorded_datastore_is_eligible() {
        assert!(verified_destroy_eligibility(&BackendType::K3s, &cluster(), None, true).is_ok());
    }

    /// Each rejection must be derived from configuration alone, so an ineligible
    /// pool is refused at bind time rather than stranding a lease in quarantine.
    #[test]
    fn unverifiable_footprints_are_rejected_before_binding() {
        let mut shared_mount = cluster();
        shared_mount.kubelet_shared_mount = Some(KubeletSharedMountConfig {
            server: true,
            agents: true,
            ..serde_json::from_value(serde_json::json!({})).unwrap()
        });
        assert_eq!(
            verified_destroy_eligibility(&BackendType::K3s, &shared_mount, None, true).unwrap_err(),
            VerifiedDestroyIneligible::KubeletSharedMount
        );

        let capture: DiagnosticsConfig = serde_json::from_value(
            serde_json::json!({ "enabled": true, "storage": "s3://bucket/" }),
        )
        .unwrap();
        assert_eq!(
            verified_destroy_eligibility(&BackendType::K3s, &cluster(), Some(&capture), true)
                .unwrap_err(),
            VerifiedDestroyIneligible::DiagnosticsEnabled
        );

        let mut retained = cluster();
        retained.persistence = Some(PersistenceConfig {
            storage_type: Some("hostPath".into()),
            storage_class_name: None,
            storage_request_size: None,
        });
        assert_eq!(
            verified_destroy_eligibility(&BackendType::K3s, &retained, None, true).unwrap_err(),
            VerifiedDestroyIneligible::UnverifiableStorage
        );

        assert_eq!(
            verified_destroy_eligibility(&BackendType::K3s, &cluster(), None, false).unwrap_err(),
            VerifiedDestroyIneligible::DatastoreProvenanceMissing
        );
    }

    /// The plan must describe what was BUILT, not what the config says later.
    ///
    /// Optional footprints appear only when the config that creates them is
    /// present — and because the plan is stamped at creation, a pool that later
    /// stops setting `registryMirrors` cannot retroactively drop that ConfigMap
    /// from an existing instance's plan and leave it unverified.
    #[test]
    fn the_plan_covers_exactly_what_this_config_creates() {
        // Minimal ephemeral cluster, no datastore.
        let minimal: ClusterConfig =
            serde_json::from_value(serde_json::json!({ "version": "v1.32.0" })).unwrap();
        let plan = k3s_teardown_plan(&minimal, false);

        // Always built.
        for required in [
            TeardownSubject::ServerStatefulSet,
            TeardownSubject::ServerPods,
            TeardownSubject::Service,
            TeardownSubject::TokenSecret,
            TeardownSubject::KubeconfigSecret,
            TeardownSubject::CidrClaim,
            TeardownSubject::ConnectTokenSecret,
        ] {
            assert!(plan.contains(&required), "{required:?} is always created");
        }
        // Never built by this config — and therefore not something a receipt
        // has to excuse. Absent from the plan, not marked NotApplicable.
        for absent in [
            TeardownSubject::AgentDeployment,
            TeardownSubject::PodDisruptionBudget,
            TeardownSubject::RegistriesConfigMap,
            TeardownSubject::DatastoreCredentialSecret,
            TeardownSubject::ServerDataPvcs,
            TeardownSubject::ServerDataVolumes,
            TeardownSubject::Database,
            TeardownSubject::DatabaseRole,
        ] {
            assert!(!plan.contains(&absent), "{absent:?} was never created");
        }
    }

    /// Persistent storage must pull in BOTH the claim and its volume, and a
    /// datastore must pull in BOTH the database and its role. Proving one half
    /// while the other survives is exactly the leak a receipt would otherwise
    /// hide.
    #[test]
    fn paired_footprints_are_never_planned_alone() {
        let persistent: ClusterConfig = serde_json::from_value(serde_json::json!({
            "version": "v1.32.0",
            "servers": 3,
            "agents": 2,
            "persistence": { "storageType": "dynamic" },
            "registryMirrors": { "docker.io": ["https://mirror.example"] }
        }))
        .unwrap();
        let plan = k3s_teardown_plan(&persistent, true);

        assert!(plan.contains(&TeardownSubject::ServerDataPvcs));
        assert!(
            plan.contains(&TeardownSubject::ServerDataVolumes),
            "a claim without its volume proves only that the pointer is gone"
        );
        assert!(plan.contains(&TeardownSubject::Database));
        assert!(plan.contains(&TeardownSubject::DatastoreCredentialSecret));
        assert!(
            plan.contains(&TeardownSubject::DatabaseRole),
            "a database without its role leaves credentials behind"
        );
        // Config-gated extras now present.
        assert!(plan.contains(&TeardownSubject::AgentDeployment));
        assert!(plan.contains(&TeardownSubject::PodDisruptionBudget));
        assert!(plan.contains(&TeardownSubject::RegistriesConfigMap));
    }

    /// A single-server pool has no PodDisruptionBudget, and emptyDir storage
    /// has no volume to reclaim.
    #[test]
    fn single_server_ephemeral_pools_plan_no_pdb_or_volumes() {
        let single: ClusterConfig = serde_json::from_value(serde_json::json!({
            "version": "v1.32.0",
            "servers": 1,
            "persistence": { "storageType": "emptyDir" }
        }))
        .unwrap();
        let plan = k3s_teardown_plan(&single, false);
        assert!(!plan.contains(&TeardownSubject::PodDisruptionBudget));
        assert!(!plan.contains(&TeardownSubject::ServerDataPvcs));
        assert!(!plan.contains(&TeardownSubject::ServerDataVolumes));
    }

    /// A backend that cannot produce evidence must be refused at bind time.
    ///
    /// This variant existed before but was unreachable: the function took no
    /// backend, so a k0s or vcluster pool asking for verified teardown got
    /// `Ok(())` and would only discover mid-teardown that no evidence was
    /// possible — stranding the lease in quarantine through no fault of its
    /// caller.
    #[test]
    fn only_k3s_can_promise_verified_teardown() {
        for backend in [
            BackendType::K0s,
            BackendType::Capi,
            BackendType::Vkobe,
            BackendType::Vcluster,
        ] {
            assert_eq!(
                verified_destroy_eligibility(&backend, &cluster(), None, true).unwrap_err(),
                VerifiedDestroyIneligible::UnsupportedBackend,
                "{backend:?} cannot produce a receipt and must be refused"
            );
        }
        assert!(verified_destroy_eligibility(&BackendType::K3s, &cluster(), None, true).is_ok());
    }

    /// Disabled diagnostics must not disqualify a pool — only active capture
    /// creates objects we cannot account for.
    #[test]
    fn disabled_diagnostics_stays_eligible() {
        let disabled: DiagnosticsConfig = serde_json::from_value(
            serde_json::json!({ "enabled": false, "storage": "s3://bucket/" }),
        )
        .unwrap();
        assert!(
            verified_destroy_eligibility(&BackendType::K3s, &cluster(), Some(&disabled), true)
                .is_ok()
        );
    }

    /// A single `Unknown` must dominate, however many subjects verified: the
    /// whole point is that partial evidence is not evidence.
    #[test]
    fn one_unknown_quarantines_the_whole_attempt() {
        let verified = TeardownCheck {
            subject: TeardownSubject::ServerStatefulSet,
            result: CheckResult::Verified,
            reason: None,
            verified: Vec::new(),
        };
        let not_applicable = TeardownCheck {
            subject: TeardownSubject::RegistriesConfigMap,
            result: CheckResult::NotApplicable,
            reason: None,
            verified: Vec::new(),
        };
        let unknown = TeardownCheck {
            subject: TeardownSubject::Database,
            result: CheckResult::Unknown,
            reason: Some("datastore_unreachable".into()),
            verified: Vec::new(),
        };

        assert_eq!(
            TeardownReceipt::outcome_for(&[verified.clone(), not_applicable.clone()]),
            TeardownOutcome::Verified
        );
        assert_eq!(
            TeardownReceipt::outcome_for(&[verified, not_applicable, unknown]),
            TeardownOutcome::Quarantined
        );
    }

    fn receipt(checks: Vec<TeardownCheck>, outcome: TeardownOutcome) -> TeardownReceipt {
        TeardownReceipt {
            schema_version: TEARDOWN_RECEIPT_SCHEMA_VERSION,
            attempt_id: "attempt-1".into(),
            lease: ResourceRef {
                name: "lease-a".into(),
                uid: Some("lease-uid".into()),
            },
            instance: ResourceRef {
                name: "pool-p-0".into(),
                uid: Some("instance-uid".into()),
            },
            pool: ResourceRef {
                name: "p".into(),
                uid: Some("pool-uid".into()),
            },
            backend_type: "k3s".into(),
            config_digest: "digest".into(),
            instance_spec_digest: "spec-digest".into(),
            creation_manifest_digest: "manifest-digest".into(),
            cleanup_mode: CleanupMode::VerifiedDestroy,
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:01:00Z".into()),
            checks,
            retry_count: 0,
            outcome,
        }
    }

    fn check(subject: TeardownSubject, result: CheckResult) -> TeardownCheck {
        TeardownCheck {
            subject,
            result,
            reason: None,
            // Name what a real provider would have named, so these fixtures
            // satisfy the identity comparison the way production does.
            verified: expected_identity_for(subject, "pool-p-0")
                .into_iter()
                .collect(),
        }
    }

    type ReceiptMutation = Box<dyn Fn(&mut TeardownReceipt)>;

    #[test]
    fn acknowledgement_token_is_bound_to_the_entire_verified_receipt() {
        let base = receipt(
            vec![check(
                TeardownSubject::ServerStatefulSet,
                CheckResult::Verified,
            )],
            TeardownOutcome::Verified,
        );
        let token = base
            .acknowledgement_token()
            .expect("a complete verified receipt has an ACK token");

        let mutations: Vec<ReceiptMutation> = vec![
            Box::new(|receipt| receipt.attempt_id = "attempt-2".into()),
            Box::new(|receipt| receipt.creation_manifest_digest = "other-manifest".into()),
            Box::new(|receipt| receipt.lease.uid = Some("other-lease".into())),
            Box::new(|receipt| receipt.instance.uid = Some("other-instance".into())),
            Box::new(|receipt| receipt.pool.uid = Some("other-pool".into())),
            Box::new(|receipt| receipt.checks[0].verified.push("extra-object".into())),
            Box::new(|receipt| receipt.completed_at = Some("2026-01-01T00:02:00Z".into())),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(
                changed.acknowledgement_token().as_deref(),
                Some(token.as_str())
            );
        }

        let mut standard = base.clone();
        standard.cleanup_mode = CleanupMode::Standard;
        assert!(standard.acknowledgement_token().is_none());
        let mut quarantined = base;
        quarantined.outcome = TeardownOutcome::Quarantined;
        assert!(quarantined.acknowledgement_token().is_none());
    }

    #[test]
    fn manifest_control_identity_cannot_be_substituted() {
        let manifest = minimal_creation_manifest();
        assert!(manifest.validate().is_ok());

        let mut foreign_controller = manifest.clone();
        foreign_controller.resources[0].controller.uid = "foreign-instance-uid".into();
        assert_eq!(
            foreign_controller.validate(),
            Err(CreationManifestInvalid::IncompleteIdentity)
        );

        let mut wrong_relation = manifest;
        wrong_relation.resources[0].control_relation = CreationControlRelation::InstanceUidLabel;
        assert_eq!(
            wrong_relation.validate(),
            Err(CreationManifestInvalid::IncompleteIdentity)
        );
    }

    fn lease_ref() -> ResourceRef {
        ResourceRef {
            name: "lease-a".into(),
            uid: Some("lease-uid".into()),
        }
    }
    fn instance_ref() -> ResourceRef {
        ResourceRef {
            name: "pool-p-0".into(),
            uid: Some("instance-uid".into()),
        }
    }
    fn pool_ref() -> ResourceRef {
        ResourceRef {
            name: "p".into(),
            uid: Some("pool-uid".into()),
        }
    }

    fn scope<'a>(
        required: &'a [TeardownSubject],
        refs: &'a (ResourceRef, ResourceRef, ResourceRef),
    ) -> TeardownScope<'a> {
        TeardownScope {
            lease: &refs.0,
            instance: &refs.1,
            pool: &refs.2,
            backend_type: "k3s",
            config_digest: "digest",
            instance_spec_digest: "spec-digest",
            creation_manifest_digest: "manifest-digest",
            cleanup_mode: CleanupMode::VerifiedDestroy,
            attempt_id: "attempt-1",
            creation_manifest: None,
            connect_token_identity: None,
            required_subjects: required,
            instance_name: "pool-p-0",
            recorded_identities: &[],
        }
    }

    #[test]
    fn concrete_identities_must_be_proven_under_their_own_subject() {
        let manifest = minimal_creation_manifest();
        let required = manifest.required_subjects();
        let recorded = manifest.recorded_identities();
        let manifest_digest = manifest.digest().unwrap();
        let refs = (lease_ref(), manifest.instance.clone(), pool_ref());
        let expected = TeardownScope {
            lease: &refs.0,
            instance: &refs.1,
            pool: &refs.2,
            backend_type: "k3s",
            config_digest: &manifest.config_digest,
            instance_spec_digest: "spec-digest",
            creation_manifest_digest: &manifest_digest,
            cleanup_mode: CleanupMode::VerifiedDestroy,
            attempt_id: "attempt-1",
            creation_manifest: Some(&manifest),
            connect_token_identity: None,
            required_subjects: &required,
            instance_name: "pool-p-0",
            recorded_identities: &recorded,
        };
        let checks: Vec<TeardownCheck> = required
            .iter()
            .map(|subject| TeardownCheck {
                subject: *subject,
                result: CheckResult::Verified,
                reason: None,
                verified: manifest.identities_for_subject(*subject),
            })
            .collect();
        let mut proof = receipt(checks, TeardownOutcome::Verified);
        proof.instance = manifest.instance.clone();
        proof.config_digest = manifest.config_digest.clone();
        proof.creation_manifest_digest = manifest_digest.clone();
        assert!(proof.permits_release_for(&expected));

        let statefulset = proof
            .checks
            .iter()
            .position(|check| check.subject == TeardownSubject::ServerStatefulSet)
            .unwrap();
        let service = proof
            .checks
            .iter()
            .position(|check| check.subject == TeardownSubject::Service)
            .unwrap();
        let statefulset_ids = proof.checks[statefulset].verified.clone();
        proof.checks[statefulset].verified = proof.checks[service].verified.clone();
        proof.checks[service].verified = statefulset_ids;
        assert!(
            !proof.permits_release_for(&expected),
            "flattened coverage must not let identities move between subjects"
        );

        let mut extra = receipt(
            required
                .iter()
                .map(|subject| TeardownCheck {
                    subject: *subject,
                    result: CheckResult::Verified,
                    reason: None,
                    verified: manifest.identities_for_subject(*subject),
                })
                .collect(),
            TeardownOutcome::Verified,
        );
        extra.instance = manifest.instance.clone();
        extra.config_digest = manifest.config_digest.clone();
        extra.creation_manifest_digest = manifest_digest.clone();
        extra.checks[0]
            .verified
            .push("invented-extra-identity".into());
        assert!(
            !extra.permits_release_for(&expected),
            "a manifest-bound receipt must prove exactly that subject's identities"
        );
    }

    #[test]
    fn release_requires_the_exact_connect_token_and_cleanup_contract() {
        let manifest = minimal_creation_manifest();
        let manifest_digest = manifest.digest().unwrap();
        let token = manifest_identity(
            "v1",
            "Secret",
            "lease-a-connect-token",
            "connect-token-uid",
            true,
        );
        let mut required = manifest.required_subjects();
        required.push(TeardownSubject::ConnectTokenSecret);
        let mut recorded = manifest.recorded_identities();
        recorded.push(token.canonical_id());
        let refs = (lease_ref(), manifest.instance.clone(), pool_ref());
        let expected = TeardownScope {
            lease: &refs.0,
            instance: &refs.1,
            pool: &refs.2,
            backend_type: "k3s",
            config_digest: &manifest.config_digest,
            instance_spec_digest: "spec-digest",
            creation_manifest_digest: &manifest_digest,
            cleanup_mode: CleanupMode::VerifiedDestroy,
            attempt_id: "attempt-1",
            creation_manifest: Some(&manifest),
            connect_token_identity: Some(&token),
            required_subjects: &required,
            instance_name: "pool-p-0",
            recorded_identities: &recorded,
        };
        let mut checks: Vec<TeardownCheck> = manifest
            .required_subjects()
            .into_iter()
            .map(|subject| TeardownCheck {
                subject,
                result: CheckResult::Verified,
                reason: None,
                verified: manifest.identities_for_subject(subject),
            })
            .collect();
        checks.push(TeardownCheck {
            subject: TeardownSubject::ConnectTokenSecret,
            result: CheckResult::Verified,
            reason: None,
            verified: vec![token.canonical_id()],
        });
        let mut proof = receipt(checks, TeardownOutcome::Verified);
        proof.instance = manifest.instance.clone();
        proof.config_digest = manifest.config_digest.clone();
        proof.creation_manifest_digest = manifest_digest.clone();
        assert!(proof.permits_release_for(&expected));

        let token_check = proof
            .checks
            .iter_mut()
            .find(|check| check.subject == TeardownSubject::ConnectTokenSecret)
            .unwrap();
        token_check.verified = vec!["k8s:v1:Secret:test:lease-a-connect-token:replacement".into()];
        assert!(!proof.permits_release_for(&expected));

        let mut downgraded = expected;
        downgraded.cleanup_mode = CleanupMode::Standard;
        assert!(!proof.permits_release_for(&downgraded));
    }

    #[test]
    fn release_is_bound_to_exact_attempt_manifest_and_ordered_rfc3339_time() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [TeardownSubject::ServerStatefulSet];
        let valid = receipt(
            vec![check(
                TeardownSubject::ServerStatefulSet,
                CheckResult::Verified,
            )],
            TeardownOutcome::Verified,
        );
        assert!(valid.permits_release_for(&scope(&required, &refs)));

        let mut wrong_attempt = valid.clone();
        wrong_attempt.attempt_id = "attempt-2".into();
        assert!(!wrong_attempt.permits_release_for(&scope(&required, &refs)));

        let mut wrong_manifest = valid.clone();
        wrong_manifest.creation_manifest_digest = "other-manifest".into();
        assert!(!wrong_manifest.permits_release_for(&scope(&required, &refs)));

        let mut equal = valid.clone();
        equal.completed_at = Some(equal.started_at.clone());
        assert!(!equal.permits_release_for(&scope(&required, &refs)));

        let mut before = valid.clone();
        before.completed_at = Some("2025-12-31T23:59:59Z".into());
        assert!(!before.permits_release_for(&scope(&required, &refs)));

        let mut malformed = valid;
        malformed.completed_at = Some("later".into());
        assert!(!malformed.permits_release_for(&scope(&required, &refs)));
    }

    /// A receipt releases capacity only if it accounts for EVERY subject the
    /// instance actually created.
    ///
    /// The earlier rule was "no Unknown, and not empty", which let a receipt
    /// carrying a single `serverStatefulSet=verified` check release a lease
    /// while saying nothing about the database, credentials, volumes, or Pods —
    /// absence of evidence read as evidence of absence.
    #[test]
    fn partial_evidence_cannot_release_capacity() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [
            TeardownSubject::ServerStatefulSet,
            TeardownSubject::Database,
            TeardownSubject::KubeconfigSecret,
        ];

        // Every required subject positively verified.
        let complete = receipt(
            vec![
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::Database, CheckResult::Verified),
                check(TeardownSubject::KubeconfigSecret, CheckResult::Verified),
            ],
            TeardownOutcome::Verified,
        );
        assert!(complete.permits_release_for(&scope(&required, &refs)));

        // NotApplicable must NOT satisfy a subject the scope says was created:
        // otherwise a receipt marks the database "never existed" and releases
        // the lease anyway. A genuinely absent footprint belongs out of the
        // scope, not explained away inside the receipt.
        let excused = receipt(
            vec![
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::Database, CheckResult::NotApplicable),
                check(TeardownSubject::KubeconfigSecret, CheckResult::Verified),
            ],
            TeardownOutcome::Verified,
        );
        assert!(
            !excused.permits_release_for(&scope(&required, &refs)),
            "NotApplicable cannot stand in for a subject the scope says was created"
        );

        // One subject simply missing — the defect this test exists for.
        let partial = receipt(
            vec![
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::Database, CheckResult::Verified),
            ],
            TeardownOutcome::Verified,
        );
        assert!(
            !partial.permits_release_for(&scope(&required, &refs)),
            "a receipt that omits a required subject must not release capacity"
        );

        // Duplicates must not let a second opinion hide behind the first.
        let duplicated = receipt(
            vec![
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::Database, CheckResult::Verified),
            ],
            TeardownOutcome::Verified,
        );
        assert!(!duplicated.permits_release_for(&scope(&required, &refs)));

        // An empty plan is not a clean bill of health.
        assert!(!complete.permits_release_for(&scope(&[], &refs)));
    }

    /// A check must name the resource its subject actually designates.
    ///
    /// Without this, `ServerStatefulSet = Verified` proves only that *something*
    /// of that category was inspected — a receipt could verify a different
    /// instance's StatefulSet, or one of several resources when the footprint
    /// had more, and still release capacity. The expected name is derived from
    /// controller-owned state and the instance name, never from the receipt.
    #[test]
    fn a_check_naming_the_wrong_resource_does_not_release() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [TeardownSubject::ServerStatefulSet];

        let correct = receipt(
            vec![check(
                TeardownSubject::ServerStatefulSet,
                CheckResult::Verified,
            )],
            TeardownOutcome::Verified,
        );
        assert!(correct.permits_release_for(&scope(&required, &refs)));

        // Right category, wrong object — another instance's StatefulSet.
        let wrong = receipt(
            vec![TeardownCheck {
                subject: TeardownSubject::ServerStatefulSet,
                result: CheckResult::Verified,
                reason: None,
                verified: vec!["some-other-instance-server".into()],
            }],
            TeardownOutcome::Verified,
        );
        assert!(
            !wrong.permits_release_for(&scope(&required, &refs)),
            "a check must name the resource its subject designates"
        );

        // Claiming the category with no identity at all is equally unproven.
        let unnamed = receipt(
            vec![TeardownCheck {
                subject: TeardownSubject::ServerStatefulSet,
                result: CheckResult::Verified,
                reason: None,
                verified: Vec::new(),
            }],
            TeardownOutcome::Verified,
        );
        assert!(!unnamed.permits_release_for(&scope(&required, &refs)));
    }

    /// Every identity recorded while the instance was healthy must be proven
    /// absent.
    ///
    /// Bound PV names cannot be derived from the instance name, so they are the
    /// one part of the footprint a teardown could quietly omit — verify three of
    /// four volumes and the fourth, with the tenant's data on it, survives while
    /// the receipt reads clean. Recording them at Ready and requiring coverage
    /// here is what closes that.
    #[test]
    fn every_recorded_identity_must_be_proven_absent() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [TeardownSubject::ServerDataVolumes];
        let recorded = vec!["pvc-aaa".to_string(), "pvc-bbb".to_string()];

        let volumes_check = |names: Vec<&str>| TeardownCheck {
            subject: TeardownSubject::ServerDataVolumes,
            result: CheckResult::Verified,
            reason: None,
            verified: names.into_iter().map(String::from).collect(),
        };
        let with_recorded = |identities: &'static [String]| TeardownScope {
            lease: &refs.0,
            instance: &refs.1,
            pool: &refs.2,
            backend_type: "k3s",
            config_digest: "digest",
            instance_spec_digest: "spec-digest",
            creation_manifest_digest: "manifest-digest",
            cleanup_mode: CleanupMode::VerifiedDestroy,
            attempt_id: "attempt-1",
            creation_manifest: None,
            connect_token_identity: None,
            required_subjects: &required,
            instance_name: "pool-p-0",
            recorded_identities: identities,
        };
        // Leaked to satisfy the 'static bound in this helper; test-only.
        let recorded_static: &'static [String] = Box::leak(recorded.clone().into_boxed_slice());

        // Both volumes proven: releases.
        let complete = receipt(
            vec![volumes_check(vec!["pvc-aaa", "pvc-bbb"])],
            TeardownOutcome::Verified,
        );
        assert!(complete.permits_release_for(&with_recorded(recorded_static)));

        // One volume unaccounted for: must not release.
        let partial = receipt(
            vec![volumes_check(vec!["pvc-aaa"])],
            TeardownOutcome::Verified,
        );
        assert!(
            !partial.permits_release_for(&with_recorded(recorded_static)),
            "a volume recorded at Ready but never proven absent must block release"
        );
    }

    /// Subjects whose names are provisioner-assigned cannot be pre-derived, so
    /// they must not be blocked by the identity check — only recorded.
    #[test]
    fn provisioner_assigned_subjects_are_not_name_checked() {
        assert!(expected_identity_for(TeardownSubject::ServerDataVolumes, "pool-p-0").is_none());
        assert!(expected_identity_for(TeardownSubject::ServerPods, "pool-p-0").is_none());
        assert_eq!(
            expected_identity_for(TeardownSubject::Database, "pool-p-0").as_deref(),
            Some("database:k3s_pool-p-0")
        );
    }

    /// A receipt is proof about ONE subject. It must not be replayable against
    /// another lease, instance, pool, or a same-named replacement.
    #[test]
    fn a_receipt_cannot_be_replayed_against_another_subject() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [TeardownSubject::ServerStatefulSet];
        let valid = receipt(
            vec![check(
                TeardownSubject::ServerStatefulSet,
                CheckResult::Verified,
            )],
            TeardownOutcome::Verified,
        );
        assert!(valid.permits_release_for(&scope(&required, &refs)));

        // Same name, different UID — a replacement object.
        let replaced = (
            lease_ref(),
            ResourceRef {
                name: "pool-p-0".into(),
                uid: Some("replacement-instance-uid".into()),
            },
            pool_ref(),
        );
        assert!(
            !valid.permits_release_for(&scope(&required, &replaced)),
            "a same-named replacement is a different subject"
        );

        // Drifted provenance must also refuse.
        let mut drifted = scope(&required, &refs);
        drifted.config_digest = "other-digest";
        assert!(!valid.permits_release_for(&drifted));

        // A reference with no UID cannot fence anything: two `None`s compare
        // equal, so this would otherwise "match" any same-named object.
        let unfenced_refs = (
            lease_ref(),
            ResourceRef {
                name: "pool-p-0".into(),
                uid: None,
            },
            pool_ref(),
        );
        let mut unfenced = receipt(
            vec![check(
                TeardownSubject::ServerStatefulSet,
                CheckResult::Verified,
            )],
            TeardownOutcome::Verified,
        );
        unfenced.instance = ResourceRef {
            name: "pool-p-0".into(),
            uid: None,
        };
        assert!(
            !unfenced.permits_release_for(&scope(&required, &unfenced_refs)),
            "a receipt without UIDs must never release capacity"
        );
    }

    /// Verdict, evidence, schema, and completeness each fail closed on their own.
    #[test]
    fn release_requires_evidence_that_matches_the_verdict() {
        let refs = (lease_ref(), instance_ref(), pool_ref());
        let required = [
            TeardownSubject::ServerStatefulSet,
            TeardownSubject::Database,
        ];

        // Verdict claims success while the evidence says otherwise.
        let contradicted = receipt(
            vec![
                check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
                check(TeardownSubject::Database, CheckResult::Unknown),
            ],
            TeardownOutcome::Verified,
        );
        assert!(
            !contradicted.permits_release_for(&scope(&required, &refs)),
            "a Verified verdict must not override an Unknown check"
        );

        let good = vec![
            check(TeardownSubject::ServerStatefulSet, CheckResult::Verified),
            check(TeardownSubject::Database, CheckResult::Verified),
        ];

        // An unrecognised schema must not be read as complete.
        let mut future = receipt(good.clone(), TeardownOutcome::Verified);
        future.schema_version = TEARDOWN_RECEIPT_SCHEMA_VERSION + 1;
        assert!(!future.permits_release_for(&scope(&required, &refs)));

        // An attempt that never finished is not proof.
        let mut unfinished = receipt(good, TeardownOutcome::Verified);
        unfinished.completed_at = None;
        assert!(!unfinished.permits_release_for(&scope(&required, &refs)));
    }

    #[test]
    fn standard_cleanup_is_the_default_and_needs_no_receipt() {
        assert_eq!(CleanupMode::default(), CleanupMode::Standard);
        assert!(!CleanupMode::Standard.requires_receipt());
        assert!(CleanupMode::VerifiedDestroy.requires_receipt());
    }
}
