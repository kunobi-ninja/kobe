use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::LeaseBinding;
use crate::crd::teardown::{CleanupMode, KubernetesResourceIdentity, TeardownReceipt};
use crate::crd::{TeardownAcknowledgement, TeardownEvidenceReference};

/// ClusterLease is the internal representation of a cluster lease.
///
/// Created when a user/CI leases a cluster via the HTTP API.
/// The lease controller binds it to a warm cluster, tracks TTL,
/// and handles release/expiry/recycling.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "ClusterLease",
    plural = "clusterleases",
    shortname = "cl",
    status = "ClusterLeaseStatus",
    namespaced,
    validation = Rule::new("has(self.spec.cleanupMode) == has(oldSelf.spec.cleanupMode) && (!has(self.spec.cleanupMode) || self.spec.cleanupMode == oldSelf.spec.cleanupMode)")
        .message("spec.cleanupMode is immutable, including implicit Standard"),
    validation = Rule::new("self.spec.requester == oldSelf.spec.requester")
        .message("spec.requester is immutable"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.teardownAttemptId) || (has(self.status) && self.status != null && has(self.status.teardownAttemptId) && (self.status.teardownAttemptId == oldSelf.status.teardownAttemptId || (has(oldSelf.status.teardownReceipt) && oldSelf.status.teardownReceipt.outcome != 'inProgress' && has(self.status.teardownReceipt) && self.status.teardownReceipt.outcome == 'inProgress' && self.status.teardownReceipt.attemptId == self.status.teardownAttemptId)))")
        .message("status.teardownAttemptId changes only when a new InProgress retry is durably begun"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.binding) || (has(self.spec.cleanupMode) ? self.status.binding.cleanupMode == self.spec.cleanupMode : self.status.binding.cleanupMode == 'Standard')")
        .message("status.binding cleanupMode must match the immutable lease cleanup contract"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.binding) || self.status.binding.cleanupMode != 'VerifiedDestroy' || (self.status.binding.bindingId.size() > 0 && has(self.status.binding.lease.uid) && self.status.binding.lease.uid.size() > 0 && self.status.binding.lease.name == self.metadata.name && self.status.binding.instance.name.size() > 0 && self.status.binding.instance.uid.size() > 0 && self.status.binding.instance.observedGeneration > 0 && has(self.status.binding.pool.uid) && self.status.binding.pool.uid.size() > 0 && self.status.binding.pool.name == self.spec.poolRef && self.status.binding.backend.configDigest.size() > 0 && self.status.binding.instanceSpecDigest.size() > 0 && has(self.status.binding.creationManifestDigest) && self.status.binding.creationManifestDigest.size() > 0 && has(self.status.binding.creationManifest))")
        .message("VerifiedDestroy binding must carry complete UID/generation-fenced lease, instance, pool, backend, and creation provenance"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.binding) || oldSelf.status.binding.cleanupMode != 'VerifiedDestroy' || (has(self.status) && self.status != null && has(self.status.binding) && self.status.binding.bindingId == oldSelf.status.binding.bindingId && self.status.binding.lease == oldSelf.status.binding.lease && self.status.binding.instance == oldSelf.status.binding.instance && self.status.binding.pool == oldSelf.status.binding.pool && self.status.binding.backend == oldSelf.status.binding.backend && self.status.binding.instanceSpecDigest == oldSelf.status.binding.instanceSpecDigest && self.status.binding.cleanupMode == oldSelf.status.binding.cleanupMode && has(self.status.binding.creationManifestDigest) == has(oldSelf.status.binding.creationManifestDigest) && (!has(oldSelf.status.binding.creationManifestDigest) || self.status.binding.creationManifestDigest == oldSelf.status.binding.creationManifestDigest) && has(self.status.binding.creationManifest) == has(oldSelf.status.binding.creationManifest) && (!has(oldSelf.status.binding.creationManifest) || self.status.binding.creationManifest == oldSelf.status.binding.creationManifest) && (!has(oldSelf.status.binding.connectToken) || (has(self.status.binding.connectToken) && self.status.binding.connectToken == oldSelf.status.binding.connectToken)))")
        .message("VerifiedDestroy binding provenance is write-once and its connect-token identity is monotonic"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.binding) || self.status.binding.cleanupMode != 'VerifiedDestroy' || !has(self.status.clusterName) || self.status.clusterName == self.status.binding.instance.name")
        .message("VerifiedDestroy clusterName must project the exact bound instance"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.binding) || oldSelf.status.binding.cleanupMode != 'VerifiedDestroy' || !has(oldSelf.status.clusterName) || (has(self.status) && self.status != null && has(self.status.clusterName) && self.status.clusterName == oldSelf.status.clusterName)")
        .message("VerifiedDestroy clusterName is immutable once published"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.teardownReceipt) || (has(self.status.binding) && has(self.status.teardownAttemptId) && self.status.teardownReceipt.attemptId == self.status.teardownAttemptId && self.status.teardownReceipt.cleanupMode == self.status.binding.cleanupMode)")
        .message("status.teardownReceipt must match the durable attempt and reciprocal binding cleanup contract"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.unboundReleaseVerifiedAt) || (self.status.phase in ['Released', 'Expired'] && has(self.status.teardownAttemptId) && (!has(self.status.binding) || (self.status.binding.cleanupMode == 'VerifiedDestroy' && !has(self.status.binding.connectToken) && has(self.status.connectTokenCreation) && self.status.connectTokenCreation.phase == 'closed' && !has(self.status.connectTokenCreation.identity) && has(self.status.connectTokenCreation.verifiedAbsentAt) && self.status.connectTokenCreation.verifiedAbsentAt == self.status.unboundReleaseVerifiedAt)) && !has(self.status.clusterName) && !has(self.status.teardownReceipt) && has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'AllocationAbsent' && c.status == 'True' && c.reason == 'NeverBound'))")
        .message("unbound release proof requires an attempt-bound NeverBound condition and either no intent or a retained pre-create intent"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.teardownAcknowledgement) || (has(self.status) && self.status != null && has(self.status.teardownAcknowledgement) && self.status.teardownAcknowledgement == oldSelf.status.teardownAcknowledgement)")
        .message("status.teardownAcknowledgement is immutable once authority records it"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.teardownAcknowledgement) || ((self.status.teardownAcknowledgement.proof.kind == 'receipt' && has(self.status.teardownAcknowledgement.proof.receiptToken) && has(self.status.teardownAcknowledgement.proof.evidence) && !has(self.status.teardownAcknowledgement.proof.unboundReleaseVerifiedAt)) || (self.status.teardownAcknowledgement.proof.kind == 'neverBound' && !has(self.status.teardownAcknowledgement.proof.receiptToken) && !has(self.status.teardownAcknowledgement.proof.evidence) && has(self.status.teardownAcknowledgement.proof.unboundReleaseVerifiedAt)))")
        .message("status.teardownAcknowledgement proof payload must match its kind"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.connectTokenCreation) || (has(self.status) && self.status != null && has(self.status.connectTokenCreation) && (self.status.connectTokenCreation.attemptId == oldSelf.status.connectTokenCreation.attemptId || (oldSelf.status.phase == 'Pending' && !has(oldSelf.status.unboundReleaseVerifiedAt) && oldSelf.status.connectTokenCreation.phase == 'closed' && self.status.connectTokenCreation.phase == 'prepared')))")
        .message("status.connectTokenCreation attempt changes only after the prior attempt is Closed"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.connectTokenCreation) || (has(self.status) && self.status != null && has(self.status.connectTokenCreation) && (self.status.connectTokenCreation.phase == oldSelf.status.connectTokenCreation.phase || (oldSelf.status.connectTokenCreation.phase == 'prepared' && self.status.connectTokenCreation.phase in ['creating', 'closed']) || (oldSelf.status.connectTokenCreation.phase == 'creating' && self.status.connectTokenCreation.phase in ['reserved', 'closing']) || (oldSelf.status.connectTokenCreation.phase == 'reserved' && self.status.connectTokenCreation.phase in ['ready', 'closing']) || (oldSelf.status.connectTokenCreation.phase == 'ready' && self.status.connectTokenCreation.phase == 'closing') || (oldSelf.status.connectTokenCreation.phase == 'closing' && self.status.connectTokenCreation.phase == 'closed') || (oldSelf.status.phase == 'Pending' && !has(oldSelf.status.unboundReleaseVerifiedAt) && oldSelf.status.connectTokenCreation.phase == 'closed' && self.status.connectTokenCreation.phase == 'prepared')))")
        .message("status.connectTokenCreation phase transitions are monotonic"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.connectTokenCreation) || ((self.status.connectTokenCreation.phase in ['prepared', 'creating'] && !has(self.status.connectTokenCreation.identity) && !has(self.status.connectTokenCreation.verifiedAbsentAt)) || (self.status.connectTokenCreation.phase in ['reserved', 'ready', 'closing'] && has(self.status.connectTokenCreation.identity) && !has(self.status.connectTokenCreation.verifiedAbsentAt)) || (self.status.connectTokenCreation.phase == 'closed' && has(self.status.connectTokenCreation.verifiedAbsentAt)))")
        .message("status.connectTokenCreation payload must match its phase"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.connectTokenCreation) || self.status.connectTokenCreation.phase == 'closed' || (has(self.status.binding) && (has(self.status.connectTokenCreation.identity) == has(self.status.binding.connectToken)) && (!has(self.status.connectTokenCreation.identity) || self.status.connectTokenCreation.identity.uid == self.status.binding.connectToken.uid && self.status.connectTokenCreation.identity.kind == self.status.binding.connectToken.kind && self.status.connectTokenCreation.identity.apiVersion == self.status.binding.connectToken.apiVersion && self.status.connectTokenCreation.identity.name == self.status.binding.connectToken.name))")
        .message("an open connect-token creator must match the durable binding intent"),
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Cleanup","type":"string","jsonPath":".spec.cleanupMode"}"#,
    printcolumn = r#"{"name":"Receipt","type":"string","jsonPath":".status.teardownReceipt.outcome"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseSpec {
    /// Which profile's pool to lease from.
    pub pool_ref: String,

    /// Requested TTL (e.g. "1h", "30m").
    pub ttl: String,

    /// Identity of the requester.
    pub requester: Requester,

    /// Caller-supplied descriptive context for this lease.
    ///
    /// Kobe stores this JSON object as opaque, untrusted data. It never affects
    /// authorization, quota, priority, scheduling, or lifecycle decisions. The
    /// HTTP API bounds its encoded size and nesting depth before creation, and
    /// no lease API mutates it afterwards. Do not place credentials or other
    /// secrets here: lease owners and cluster administrators can read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::crd::json_object_schema")]
    // Keep recursive caller data behind a pointer so controller async frames
    // do not grow with serde_json::Value's enum representation.
    pub metadata: Option<Box<serde_json::Value>>,

    /// Lease priority for queue ordering.
    /// Higher values are served first.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// How thoroughly this lease's capacity must be torn down before reuse.
    ///
    /// Absent means [`CleanupMode::Standard`], so every existing `ClusterLease`
    /// keeps its current behaviour. #74's internal leases request
    /// [`CleanupMode::VerifiedDestroy`]; pools that cannot produce evidence
    /// reject it at bind time rather than degrading silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_mode: Option<CleanupMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Requester {
    /// Type of requester: "{provider}:{role}" (e.g. "github-actions:ci", "clerk:admin").
    #[serde(rename = "type")]
    pub requester_type: String,

    /// Identity string (e.g. "repo:org/repo:ref:refs/heads/main" for GitHub,
    /// or user ID for Clerk).
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseStatus {
    /// Current phase of the lease lifecycle.
    #[serde(default)]
    pub phase: LeasePhase,

    /// Name of the bound cluster (set when phase=Bound).
    // skip_serializing_if: never serialize None, so a controller doing
    // pass-through preservation that momentarily reads it as None cannot erase it
    // via a JSON-Merge-Patch null (RFC 7396). Only ever set, never cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,

    /// Authoritative UID-fenced reciprocal binding. It may be present while the
    /// lease is still `Pending` as a crash-safe reservation intent; access is
    /// authorized only after the lease reaches `Bound` and the exact same value
    /// exists on the referenced `ClusterInstance`.
    ///
    /// A `VerifiedDestroy` intent is write-once. If release closes it before
    /// token creation, the exact value remains alongside `NeverBound` proof so
    /// consumers can distinguish "intent retained, instance absent" from "no
    /// intent was ever recorded".
    ///
    /// `clusterName` remains for compatibility and display, but must never be
    /// used alone for access, mutation, rollback, release, or teardown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<LeaseBinding>,

    /// When the lease was bound to a vcluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<String>,

    /// When the lease expires (TTL deadline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Durable proof that this lease's exact capacity was destroyed.
    ///
    /// Recorded here rather than on the `ClusterInstance` because it must stay
    /// queryable *after* the instance object is gone — which is exactly when
    /// the evidence matters, and when #74's owning `SandboxLease` consumes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_receipt: Option<TeardownReceipt>,

    /// Exact immutable authority record corresponding to
    /// [`Self::teardown_receipt`]. Consumers never trust the status mirror
    /// without fetching this UID/generation/resourceVersion-fenced object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_evidence: Option<TeardownEvidenceReference>,

    /// Durable nonce written before the first destructive request. Kept
    /// separate from the mutable InProgress-to-terminal receipt so consumers
    /// can verify that the terminal record belongs to the exact attempt the
    /// controller began, rather than trusting a nonce supplied by that record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub teardown_attempt_id: Option<String>,

    /// Crash-safe state machine for creation of the lease-scoped connect
    /// token. `Prepared` is persisted before the create-capable reconcile;
    /// `Creating` is then persisted immediately before the one permitted
    /// Secret `POST`.
    /// `Reserved` records the exact Secret UID and closes the create name;
    /// every later operation is an exact-UID `PATCH` or `DELETE`, never a
    /// second create. Terminal release may certify `NeverBound` only after the
    /// same attempt reaches `Closed` with an observed-absence timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_token_creation: Option<ConnectTokenCreation>,

    /// API-server-observed proof that this exact terminal lease never acquired
    /// a reciprocal `ClusterInstance` binding. A pre-create binding intent may
    /// remain as immutable audit provenance; it must have no token identity and
    /// its creator must be `Closed`. The proof is meaningful only with the same
    /// status' immutable [`Self::teardown_attempt_id`] and is retained until the
    /// composing Sandbox explicitly acknowledges that attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub unbound_release_verified_at: Option<String>,

    /// Authority-owned proof that a distinct consumer durably checkpointed
    /// this exact receipt or `NeverBound` attempt. The lifecycle controller
    /// may remove the retention finalizer only when this value matches the
    /// currently retained proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_acknowledgement: Option<TeardownAcknowledgement>,

    /// Position in the priority queue (0 = not queued, 1 = next).
    #[serde(default)]
    pub queue_position: u32,

    /// URL to the diagnostic bundle captured on release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics_url: Option<String>,

    /// Number of TTL extensions granted for this lease.
    #[serde(default)]
    pub extensions_count: u32,

    /// Maximum number of extensions allowed (from policy).
    #[serde(default)]
    pub max_extensions: u32,

    /// Human-readable explanation of the lease's current state, set when the
    /// reason is non-obvious — primarily why a `Pending` lease has not bound
    /// (e.g. "no Ready cluster; pool p phase=Failing, consecutiveFailures=3,
    /// lastFailureReason=..."). Lets a client distinguish "warming up" from
    /// "this pool will never satisfy me" without scraping pool status itself.
    ///
    /// skip_serializing_if: omit when None so a JSON-Merge-Patch (RFC 7396)
    /// pass-through preservation can't erase a previously-set message via an
    /// explicit null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Standard Kubernetes-style status conditions, derived by the lease
    /// controller from `phase` / `cluster_name` / `message` (see
    /// `derive_lease_conditions`). Mirrors `ClusterInstanceStatus.conditions`.
    /// Currently emitted: `Bound` (True once a cluster is assigned) and
    /// `Satisfiable` (False on the no-Ready-cluster path, carrying the
    /// unsatisfiable reason). These give `kubectl` and ops tooling a familiar,
    /// machine-readable surface for *why* the lease is where it is, alongside
    /// the human-readable `message`.
    ///
    /// `skip_serializing_if = "Vec::is_empty"` protects the list from
    /// Merge-Patch erasure, same pattern as `message`: a writer that emits an
    /// empty `Vec` (e.g. a status patch that only touches another field) must
    /// omit the key entirely — otherwise a JSON Merge Patch carrying
    /// `"conditions": []` would replace the on-disk list with an empty one
    /// (RFC 7396 / array-replacement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ClusterLeaseCondition>,
}

/// Durable lifecycle of the only create-capable connect-token operation.
///
/// Persisting this separately from [`LeaseBinding::connect_token`] matters for
/// the crash window between a Secret `POST` and the status patch that records
/// its UID. A restart in `Creating` observes the original attempt but never
/// emits another `POST`; an ambiguous 404 therefore fails closed instead of
/// certifying `NeverBound` while a delayed create could still arrive.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectTokenCreation {
    #[schemars(length(min = 1))]
    pub attempt_id: String,
    pub phase: ConnectTokenCreationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<KubernetesResourceIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub verified_absent_at: Option<String>,
}

/// Monotonic states for [`ConnectTokenCreation`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConnectTokenCreationPhase {
    /// Durable binding intent exists, but no Secret create was dispatched.
    Prepared,
    /// The single empty-Secret create may be in flight or have an ambiguous
    /// result. Reconcilers may observe this attempt, but must never retry its
    /// `POST`.
    Creating,
    /// The exact empty Secret UID is durable, so no later `POST` is needed.
    Reserved,
    /// Token data was installed into the exact reserved Secret.
    Ready,
    /// Release has closed activation and is deleting the exact Secret.
    Closing,
    /// Exact Secret absence was observed for this attempt.
    Closed,
}

/// One status condition on a `ClusterLease`. Mirrors the core/v1 condition
/// shape (type/status/reason/message/lastTransitionTime) — and
/// `ClusterInstanceCondition` — so kubectl and operators see a familiar
/// surface across all Kobe resources.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLeaseCondition {
    /// Condition name. Emitted values: `Bound`, `Satisfiable`.
    #[serde(rename = "type")]
    pub condition_type: String,

    /// One of: `True`, `False`, `Unknown`.
    pub status: String,

    /// Machine-readable reason. For `Bound` this is the current phase
    /// (e.g. `Bound`, `Pending`, `Expired`). For `Satisfiable` it is the
    /// unsatisfiable classification (e.g. `Warming`, `PoolExhausted`) on the
    /// no-Ready-cluster path, or the phase otherwise.
    pub reason: String,

    /// Human-readable detail, generally a copy of `status.message` for the
    /// current state (or empty when there is none).
    pub message: String,

    /// RFC3339 of the last status change. Updated only when `status`
    /// flips (True ↔ False ↔ Unknown), not on every reconcile, so tools
    /// tailing `kubectl get -w` see meaningful transitions rather than churn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

/// Lease lifecycle phases.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
pub enum LeasePhase {
    /// Waiting for a warm cluster to become available.
    #[default]
    Pending,
    /// Bound to a cluster.
    Bound,
    /// Explicitly released by the user.
    Released,
    /// TTL expired, cluster being reclaimed.
    Expired,
    /// Cluster being deleted and recreated.
    Recycling,
    /// Teardown could not be proven complete for this lease's exact capacity.
    /// Terminal until the same subject produces a verified receipt.
    Quarantined,
}

impl std::fmt::Display for LeasePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeasePhase::Pending => write!(f, "Pending"),
            LeasePhase::Bound => write!(f, "Bound"),
            LeasePhase::Released => write!(f, "Released"),
            LeasePhase::Expired => write!(f, "Expired"),
            LeasePhase::Recycling => write!(f, "Recycling"),
            LeasePhase::Quarantined => write!(f, "Quarantined"),
        }
    }
}

/// Default priority: normal (50).
fn default_priority() -> u32 {
    50
}

#[cfg(test)]
mod json_safety_tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn status_omits_none_preserve_fields_so_merge_patch_cannot_erase_them() {
        // With skip_serializing_if, a None preserve-field is OMITTED from the
        // serialized status. A JSON Merge Patch (RFC 7396) then leaves the
        // on-disk value untouched, instead of deleting it via an explicit null —
        // so a controller doing pass-through preservation can't erase a field it
        // momentarily read as None.
        let none_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            ..Default::default()
        };
        let v = serde_json::to_value(&none_status).unwrap();
        assert!(
            v.get("clusterName").is_none(),
            "clusterName must be omitted when None"
        );
        assert!(
            v.get("boundAt").is_none(),
            "boundAt must be omitted when None"
        );
        assert!(
            v.get("expiresAt").is_none(),
            "expiresAt must be omitted when None"
        );
        assert!(
            v.get("diagnosticsUrl").is_none(),
            "diagnosticsUrl must be omitted when None"
        );
        assert!(
            v.get("binding").is_none(),
            "binding must be omitted when None"
        );
        assert!(
            v.get("teardownAttemptId").is_none(),
            "teardownAttemptId must be omitted when None"
        );

        // Set values are still serialized.
        let set_status = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            bound_at: Some("2026-06-04T00:00:00Z".into()),
            expires_at: Some("2026-06-04T01:00:00Z".into()),
            teardown_receipt: None,
            teardown_attempt_id: Some("attempt-1".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&set_status).unwrap();
        assert_eq!(
            v.get("clusterName").and_then(|x| x.as_str()),
            Some("pool-x-0")
        );
        assert_eq!(
            v.get("teardownAttemptId").and_then(|x| x.as_str()),
            Some("attempt-1")
        );
        assert_eq!(
            v.get("boundAt").and_then(|x| x.as_str()),
            Some("2026-06-04T00:00:00Z")
        );
    }

    #[test]
    fn empty_conditions_are_omitted_from_serialized_status() {
        // An empty `conditions` Vec must NOT serialize (skip_serializing_if =
        // Vec::is_empty), so a Merge-Patch from a writer that does not set
        // conditions never carries `"conditions": []` — which would erase a
        // previously-derived list per RFC 7396 array-replacement.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Pending,
            ..Default::default()
        };
        let v = serde_json::to_value(&st).unwrap();
        assert!(
            v.get("conditions").is_none(),
            "empty conditions must be omitted, got: {v}"
        );

        // A populated list serializes with camelCase keys.
        let st = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            conditions: vec![ClusterLeaseCondition {
                condition_type: "Bound".into(),
                status: "True".into(),
                reason: "Bound".into(),
                message: "running".into(),
                last_transition_time: Some("2026-06-04T00:00:00Z".into()),
            }],
            ..Default::default()
        };
        let v = serde_json::to_value(&st).unwrap();
        let conds = v.get("conditions").and_then(|c| c.as_array()).unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].get("type").and_then(|x| x.as_str()), Some("Bound"));
        assert_eq!(
            conds[0].get("lastTransitionTime").and_then(|x| x.as_str()),
            Some("2026-06-04T00:00:00Z")
        );
    }

    /// The serialized form of `LeasePhase` is a WIRE CONTRACT, not an
    /// implementation detail.
    ///
    /// `kobectl` reads the phase out of the API response as a *string*
    /// and compares it against literals — `is_terminal_failure_phase`
    /// matches "expired" / "released" / "recycling" case-insensitively to
    /// decide whether to stop waiting on a lease. A `#[serde(rename)]` or
    /// a renamed variant here would not fail to compile anywhere; the CLI
    /// would just silently stop recognising terminal leases and wait out
    /// its full timeout on a lease that was never going to bind.
    #[test]
    fn lease_phase_serializes_as_the_bare_variant_name() {
        for (phase, wire) in [
            (LeasePhase::Pending, "Pending"),
            (LeasePhase::Bound, "Bound"),
            (LeasePhase::Released, "Released"),
            (LeasePhase::Expired, "Expired"),
            (LeasePhase::Recycling, "Recycling"),
        ] {
            assert_eq!(
                serde_json::to_value(&phase).unwrap(),
                serde_json::Value::String(wire.to_string()),
                "{phase:?} must serialize as the bare name {wire:?} — kobectl \
                 string-matches this"
            );
            let back: LeasePhase = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, phase, "{wire:?} must round-trip back to {phase:?}");
        }
    }

    /// `Display` and the serde form must agree.
    ///
    /// Both reach users: the serde form goes over the API to the CLI's
    /// phase comparison, and `Display` is what the CLI prints back
    /// ("Lease {id} ended in phase {phase}"). If they diverged, an error
    /// message would name a phase that the code matching on it would not
    /// recognise — the most confusing possible failure.
    #[test]
    fn lease_phase_display_matches_the_serialized_form() {
        for phase in [
            LeasePhase::Pending,
            LeasePhase::Bound,
            LeasePhase::Released,
            LeasePhase::Expired,
            LeasePhase::Recycling,
        ] {
            let serialized = serde_json::to_value(&phase).unwrap();
            assert_eq!(
                serialized.as_str().unwrap(),
                phase.to_string(),
                "Display and serde disagree for {phase:?}"
            );
        }
    }

    /// Phase defaults to `Pending`: a status written without one describes
    /// a lease that has not bound, which is the safe reading. Defaulting
    /// to `Bound` would make an unbound lease look served.
    #[test]
    fn phase_defaults_to_pending() {
        let st: ClusterLeaseStatus = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(st.phase, LeasePhase::Pending);
        assert_eq!(LeasePhase::default(), LeasePhase::Pending);
    }

    /// The spec binds camelCase only. The API server writes these CRs, and
    /// the CRD schema declares `poolRef` — a snake_case key would be
    /// dropped as an unknown field rather than rejected, leaving a lease
    /// with no pool.
    #[test]
    fn spec_binds_camel_case_keys_only() {
        let ok: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "ci-small",
            "ttl": "1h",
            "requester": { "type": "github-actions:ci", "identity": "repo:org/repo" }
        }))
        .expect("camelCase spec must bind");
        assert_eq!(ok.pool_ref, "ci-small");

        let snake = serde_json::from_value::<ClusterLeaseSpec>(serde_json::json!({
            "pool_ref": "ci-small",
            "ttl": "1h",
            "requester": { "type": "github-actions:ci", "identity": "repo:org/repo" }
        }));
        assert!(
            snake.is_err(),
            "snake_case `pool_ref` must not bind — it would silently leave poolRef unset"
        );
    }

    /// `priority` is optional and defaults to normal. The queue sorts on
    /// it descending, so a wrong default would silently re-order every
    /// lease that omits it.
    #[test]
    fn priority_defaults_to_normal_when_absent() {
        let spec: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "p", "ttl": "1h",
            "requester": { "type": "t", "identity": "i" }
        }))
        .unwrap();
        assert_eq!(spec.priority, 50);

        let explicit: ClusterLeaseSpec = serde_json::from_value(serde_json::json!({
            "poolRef": "p", "ttl": "1h", "priority": 99,
            "requester": { "type": "t", "identity": "i" }
        }))
        .unwrap();
        assert_eq!(explicit.priority, 99);
    }

    /// `Requester.requester_type` is spelled `type` on the wire — the
    /// Rust field can't be, so this rename is the only thing keeping the
    /// stored CR readable by every writer of it.
    #[test]
    fn requester_type_is_named_type_on_the_wire() {
        let r = Requester {
            requester_type: "github-actions:ci".into(),
            identity: "repo:org/repo".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v.get("type").and_then(|x| x.as_str()),
            Some("github-actions:ci")
        );
        assert!(
            v.get("requesterType").is_none() && v.get("requester_type").is_none(),
            "the Rust field name must not leak onto the wire, got: {v}"
        );
    }

    #[test]
    fn crd_schema_exposes_typed_uid_fenced_binding() {
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();
        let binding = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"]
            ["properties"]["binding"];
        let properties = &binding["properties"];
        for key in [
            "bindingId",
            "lease",
            "instance",
            "pool",
            "backend",
            "instanceSpecDigest",
        ] {
            assert!(
                properties.get(key).is_some(),
                "missing binding.{key}: {binding}"
            );
        }
        assert_eq!(properties["lease"]["properties"]["uid"]["type"], "string");
        assert_eq!(
            properties["instance"]["properties"]["uid"]["type"],
            "string"
        );
        assert_eq!(
            properties["instance"]["properties"]["observedGeneration"]["format"],
            "int64"
        );
        assert_eq!(properties["pool"]["properties"]["uid"]["type"], "string");
        assert_eq!(
            properties["backend"]["properties"]["type"]["type"],
            "string"
        );
    }

    /// A condition with no recorded transition omits the key rather than
    /// writing an explicit null, so a reader round-tripping the condition
    /// does not turn "never transitioned" into a stored null.
    ///
    /// Note this is NOT the Merge-Patch protection that `message` and
    /// `conditions` get. JSON Merge Patch replaces arrays wholesale, so a
    /// patch carrying a `conditions` array at all replaces the stored list
    /// entirely — omitting a property *inside* an emitted element protects
    /// nothing. Omitting the whole `conditions` key is what protects the
    /// list; that is pinned separately by
    /// `empty_conditions_are_omitted_from_serialized_status`.
    #[test]
    fn condition_omits_last_transition_time_when_unset() {
        let c = ClusterLeaseCondition {
            condition_type: "Satisfiable".into(),
            status: "False".into(),
            reason: "Warming".into(),
            message: "no Ready cluster".into(),
            last_transition_time: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(
            v.get("lastTransitionTime").is_none(),
            "unset lastTransitionTime must be omitted, not null: {v}"
        );
    }

    /// A status written by a NEWER operator must still deserialize, or a
    /// rolling upgrade wedges the older replica on every lease it reads.
    #[test]
    fn status_from_a_newer_operator_still_deserializes() {
        let st: ClusterLeaseStatus = serde_json::from_value(serde_json::json!({
            "phase": "Bound",
            "clusterName": "pool-x-0",
            "someFieldFromTheFuture": { "nested": true }
        }))
        .expect("unknown fields must be ignored, not rejected");
        assert_eq!(st.phase, LeasePhase::Bound);
        assert_eq!(st.cluster_name.as_deref(), Some("pool-x-0"));
    }

    /// A fully-populated status survives serialize → deserialize →
    /// serialize unchanged.
    ///
    /// Scoped deliberately to the populated case, which is what a bound
    /// lease looks like. It is NOT a general fixed-point claim: an input
    /// with `"conditions": []` comes back without the key, an explicit
    /// null on a skipped field is likewise dropped, and unknown fields
    /// from a newer operator are discarded on deserialize (by design —
    /// see `status_from_a_newer_operator_still_deserializes`). Those are
    /// intended asymmetries, not regressions this test would catch.
    #[test]
    fn a_populated_status_survives_a_serde_round_trip() {
        let original = ClusterLeaseStatus {
            phase: LeasePhase::Bound,
            cluster_name: Some("pool-x-0".into()),
            binding: None,
            bound_at: Some("2026-06-04T00:00:00Z".into()),
            expires_at: Some("2026-06-04T01:00:00Z".into()),
            queue_position: 0,
            diagnostics_url: None,
            extensions_count: 1,
            max_extensions: 3,
            message: Some("bound".into()),
            conditions: vec![ClusterLeaseCondition {
                condition_type: "Bound".into(),
                status: "True".into(),
                reason: "Bound".into(),
                message: "bound".into(),
                last_transition_time: Some("2026-06-04T00:00:00Z".into()),
            }],
            // Populated, not None: the receipt is the durable evidence a #74
            // SandboxLease reads back after its ClusterInstance is gone, so it
            // has to survive the wire intact.
            teardown_receipt: Some(crate::crd::TeardownReceipt {
                schema_version: crate::crd::TEARDOWN_RECEIPT_SCHEMA_VERSION,
                attempt_id: "attempt-1".into(),
                lease: crate::crd::ResourceRef {
                    name: "lease-x".into(),
                    uid: Some("lease-uid".into()),
                },
                instance: crate::crd::ResourceRef {
                    name: "pool-x-0".into(),
                    uid: Some("instance-uid".into()),
                },
                pool: crate::crd::ResourceRef {
                    name: "x".into(),
                    uid: Some("pool-uid".into()),
                },
                backend_type: "k3s".into(),
                config_digest: "cfg".into(),
                instance_spec_digest: "spec".into(),
                creation_manifest_digest: "manifest-digest".into(),
                cleanup_mode: crate::crd::CleanupMode::VerifiedDestroy,
                started_at: "2026-06-04T02:00:00Z".into(),
                completed_at: Some("2026-06-04T02:01:00Z".into()),
                checks: vec![crate::crd::TeardownCheck {
                    subject: crate::crd::TeardownSubject::ServerStatefulSet,
                    result: crate::crd::CheckResult::Verified,
                    reason: None,
                    verified: Vec::new(),
                }],
                retry_count: 0,
                outcome: crate::crd::TeardownOutcome::Verified,
            }),
            teardown_evidence: None,
            teardown_attempt_id: Some("attempt-1".into()),
            connect_token_creation: None,
            unbound_release_verified_at: None,
            teardown_acknowledgement: None,
        };
        let once = serde_json::to_value(&original).unwrap();
        let back: ClusterLeaseStatus = serde_json::from_value(once.clone()).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), once);
    }

    /// The CRD's public identity. Changing any of these is a breaking
    /// change for every `kubectl` invocation and manifest in the wild.
    #[test]
    fn crd_identity_is_stable() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();

        assert_eq!(crd["spec"]["group"], "kobe.kunobi.ninja");
        assert_eq!(crd["spec"]["scope"], "Namespaced");
        assert_eq!(crd["spec"]["names"]["kind"], "ClusterLease");
        assert_eq!(crd["spec"]["names"]["plural"], "clusterleases");
        assert_eq!(crd["spec"]["names"]["shortNames"][0], "cl");
        assert_eq!(crd["metadata"]["name"], "clusterleases.kobe.kunobi.ninja");

        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["name"], "v1alpha1");
        assert_eq!(versions[0]["served"], true);
        assert_eq!(versions[0]["storage"], true);
    }

    /// `status` must be a real subresource, or the apiserver silently
    /// discards every `patch_status` the lease controller issues and no
    /// lease ever leaves `Pending`.
    #[test]
    fn crd_declares_the_status_subresource() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();
        let versions = crd["spec"]["versions"].as_array().unwrap();
        assert!(
            versions[0]["subresources"].get("status").is_some(),
            "status subresource missing: {}",
            versions[0]["subresources"]
        );
    }

    #[test]
    fn crd_makes_cleanup_mode_presence_and_value_immutable_at_the_root() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(ClusterLease::crd()).unwrap();
        let rules =
            crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["x-kubernetes-validations"]
                .as_array()
                .expect("root transition rules");
        assert!(rules.iter().any(|rule| {
            rule["rule"]
                == "has(self.spec.cleanupMode) == has(oldSelf.spec.cleanupMode) && (!has(self.spec.cleanupMode) || self.spec.cleanupMode == oldSelf.spec.cleanupMode)"
        }));
        for expected in [
            "status.binding.cleanupMode == self.spec.cleanupMode",
            "status.teardownReceipt.attemptId == self.status.teardownAttemptId",
            "c.type == 'AllocationAbsent' && c.status == 'True' && c.reason == 'NeverBound'",
            "self.status.binding.bindingId == oldSelf.status.binding.bindingId",
            "self.status.binding.connectToken == oldSelf.status.binding.connectToken",
            "self.status.binding.lease.uid.size() > 0",
            "self.status.binding.lease.name == self.metadata.name",
            "self.status.binding.instance.uid.size() > 0",
            "self.status.binding.pool.uid.size() > 0",
            "self.status.binding.creationManifestDigest.size() > 0",
            "self.status.clusterName == oldSelf.status.clusterName",
            "self.status.clusterName == self.status.binding.instance.name",
            "self.status.connectTokenCreation.verifiedAbsentAt == self.status.unboundReleaseVerifiedAt",
            "self.status.phase in ['Released', 'Expired']",
        ] {
            assert!(rules.iter().any(|rule| {
                rule["rule"]
                    .as_str()
                    .is_some_and(|rule| rule.contains(expected))
            }));
        }
        assert!(rules.iter().any(|rule| {
            rule["rule"].as_str().is_some_and(|rule| {
                rule.contains("status.teardownAttemptId")
                    && rule.contains("teardownReceipt.outcome == 'inProgress'")
                    && rule.contains("teardownReceipt.attemptId == self.status.teardownAttemptId")
            })
        }));
        let status = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"]
            ["properties"];
        assert_eq!(status["teardownAttemptId"]["type"], "string");
    }

    #[test]
    fn legacy_status_without_conditions_deserializes() {
        // Back-compat: a ClusterLease persisted before the conditions field
        // existed (no `conditions` key) must still deserialize, defaulting to
        // an empty Vec.
        let legacy = serde_json::json!({
            "phase": "Bound",
            "clusterName": "pool-x-0",
            "expiresAt": "2026-06-04T01:00:00Z",
            "queuePosition": 0,
            "extensionsCount": 0,
            "maxExtensions": 2
        });
        let status: ClusterLeaseStatus = serde_json::from_value(legacy).unwrap();
        assert_eq!(status.phase, LeasePhase::Bound);
        assert!(
            status.conditions.is_empty(),
            "missing conditions must default to an empty Vec"
        );
    }
}
