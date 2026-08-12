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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Unique per attempt; retries produce new attempts, never edit old ones.
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
            || self.completed_at.is_none()
            || self.outcome != TeardownOutcome::Verified
            || Self::outcome_for(&self.checks) != TeardownOutcome::Verified
        {
            return false;
        }
        // A reference without a UID cannot fence anything: two `None` UIDs
        // compare equal, so a same-named replacement would satisfy the match
        // that is supposed to exclude it.
        if self.lease.uid.is_none() || self.instance.uid.is_none() || self.pool.uid.is_none() {
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
            match expected_identity_for(*subject, expected.instance_name) {
                Some(expected_name) => check.verified.contains(&expected_name),
                None => true,
            }
        })
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
    /// Every subject this instance actually created. Optional footprints that
    /// were never created are simply absent — which is why the list must come
    /// from the creation record, not be inferred at teardown time.
    pub required_subjects: &'a [TeardownSubject],
    /// Used to derive the expected resource names. Comes from controller-owned
    /// bind-time state like the rest of this scope, never from the receipt.
    pub instance_name: &'a str,
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
            required_subjects: required,
            instance_name: "pool-p-0",
        }
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
