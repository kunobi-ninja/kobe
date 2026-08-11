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
use super::profile::{ClusterConfig, DiagnosticsConfig};

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

    /// Whether this receipt permits releasing the final cleanup handle.
    ///
    /// Requires an explicitly recorded verdict *and* agreement with the checks,
    /// so a hand-edited or truncated receipt cannot unlock capacity.
    pub fn permits_release(&self) -> bool {
        self.schema_version == TEARDOWN_RECEIPT_SCHEMA_VERSION
            && self.outcome == TeardownOutcome::Verified
            && Self::outcome_for(&self.checks) == TeardownOutcome::Verified
            && !self.checks.is_empty()
    }
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
    cluster: &ClusterConfig,
    diagnostics: Option<&DiagnosticsConfig>,
    external_datastore_identity_recorded: bool,
) -> Result<(), VerifiedDestroyIneligible> {
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
        assert!(verified_destroy_eligibility(&cluster(), None, true).is_ok());
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
            verified_destroy_eligibility(&shared_mount, None, true).unwrap_err(),
            VerifiedDestroyIneligible::KubeletSharedMount
        );

        let capture: DiagnosticsConfig = serde_json::from_value(
            serde_json::json!({ "enabled": true, "storage": "s3://bucket/" }),
        )
        .unwrap();
        assert_eq!(
            verified_destroy_eligibility(&cluster(), Some(&capture), true).unwrap_err(),
            VerifiedDestroyIneligible::DiagnosticsEnabled
        );

        let mut retained = cluster();
        retained.persistence = Some(PersistenceConfig {
            storage_type: Some("hostPath".into()),
            storage_class_name: None,
            storage_request_size: None,
        });
        assert_eq!(
            verified_destroy_eligibility(&retained, None, true).unwrap_err(),
            VerifiedDestroyIneligible::UnverifiableStorage
        );

        assert_eq!(
            verified_destroy_eligibility(&cluster(), None, false).unwrap_err(),
            VerifiedDestroyIneligible::DatastoreProvenanceMissing
        );
    }

    /// Disabled diagnostics must not disqualify a pool — only active capture
    /// creates objects we cannot account for.
    #[test]
    fn disabled_diagnostics_stays_eligible() {
        let disabled: DiagnosticsConfig = serde_json::from_value(
            serde_json::json!({ "enabled": false, "storage": "s3://bucket/" }),
        )
        .unwrap();
        assert!(verified_destroy_eligibility(&cluster(), Some(&disabled), true).is_ok());
    }

    /// A single `Unknown` must dominate, however many subjects verified: the
    /// whole point is that partial evidence is not evidence.
    #[test]
    fn one_unknown_quarantines_the_whole_attempt() {
        let verified = TeardownCheck {
            subject: TeardownSubject::ServerStatefulSet,
            result: CheckResult::Verified,
            reason: None,
        };
        let not_applicable = TeardownCheck {
            subject: TeardownSubject::RegistriesConfigMap,
            result: CheckResult::NotApplicable,
            reason: None,
        };
        let unknown = TeardownCheck {
            subject: TeardownSubject::Database,
            result: CheckResult::Unknown,
            reason: Some("datastore_unreachable".into()),
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

    /// A receipt may only unlock capacity when its recorded verdict and its own
    /// evidence agree, so a hand-edited or truncated receipt cannot release it.
    #[test]
    fn release_requires_evidence_that_matches_the_verdict() {
        let verified = TeardownCheck {
            subject: TeardownSubject::ServerStatefulSet,
            result: CheckResult::Verified,
            reason: None,
        };
        let unknown = TeardownCheck {
            subject: TeardownSubject::Database,
            result: CheckResult::Unknown,
            reason: Some("datastore_unreachable".into()),
        };

        assert!(receipt(vec![verified.clone()], TeardownOutcome::Verified).permits_release());

        // Verdict claims success while the evidence says otherwise.
        assert!(
            !receipt(vec![verified.clone(), unknown], TeardownOutcome::Verified).permits_release(),
            "a Verified verdict must not override an Unknown check"
        );
        // No evidence at all is not proof of absence.
        assert!(!receipt(Vec::new(), TeardownOutcome::Verified).permits_release());
        // An unrecognised schema must not be read as complete.
        let mut future = receipt(vec![verified], TeardownOutcome::Verified);
        future.schema_version = TEARDOWN_RECEIPT_SCHEMA_VERSION + 1;
        assert!(!future.permits_release());
    }

    #[test]
    fn standard_cleanup_is_the_default_and_needs_no_receipt() {
        assert_eq!(CleanupMode::default(), CleanupMode::Standard);
        assert!(!CleanupMode::Standard.requires_receipt());
        assert!(CleanupMode::VerifiedDestroy.requires_receipt());
    }
}
