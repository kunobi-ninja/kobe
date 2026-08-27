//! Distributed admission and teardown barrier for Sandbox operations.
//!
//! A process-local registry is required to cancel the sockets owned by one API
//! replica, but it cannot enforce a principal-wide limit or prove that every
//! replica has drained before workload cleanup. This module adds two
//! API-server CAS records in the protected Sandbox ledger namespace:
//!
//! - one gate per `SandboxLease` UID, containing at most eight operations;
//! - one ledger per authenticated principal, containing at most 32 operations.
//!
//! Admission creates the lease gate before reserving capacity or publishing an
//! admitted `SandboxLease`. Handlers enter that existing gate first and the
//! principal ledger second. The lifecycle controller closes the same gate
//! before teardown and waits until every entry is gone. A close racing an entry
//! is therefore serialized by one `resourceVersion`; there is no check-then-act
//! window in which a late handler can mint a credential after cleanup starts,
//! and teardown never needs to CREATE a gate while the ledger quota is full.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::crd::{SandboxConditionStatus, SandboxLease, SandboxLeasePhase};

const LEDGER_KIND_LABEL: &str = "kobe.kunobi.ninja/sandbox-access-kind";
const LEASE_NAME_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-name";
// Deliberately distinct from the admission-reservation UID label. Pending
// admission cleanup lists that label to discover quota/alias tokens; treating
// an access gate as a token would either delete the teardown barrier early or
// reject cleanup because its object shape is intentionally different.
const LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-access-lease-uid";
const GATE_KIND: &str = "lease-gate";
const PRINCIPAL_KIND: &str = "principal-ledger";
const STATE_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-access-state";
const ENTRIES_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-access-entries";
const EXECUTIONS_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-executions";
const PRINCIPAL_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-principal-hash";
/// Exact API-server identity of the pre-admission access gate.
pub const ACCESS_GATE_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-access-gate";
const OPEN: &str = "open";
const CLOSED: &str = "closed";
const MAX_CAS_ATTEMPTS: usize = 64;

/// Cluster identity of the API process serving one operation.
///
/// Pod UID distinguishes a replacement and `boot_id` distinguishes container
/// restarts inside the same Pod. A new process removes entries left by an older
/// boot only after proving the Pod identity is still its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServingReplica {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub boot_id: String,
}

impl ServingReplica {
    /// Reject incomplete downward-API identity before Sandbox routes serve.
    pub fn validate(&self) -> Result<(), AccessLedgerError> {
        if self.namespace.trim().is_empty()
            || self.pod_name.trim().is_empty()
            || self.pod_uid.trim().is_empty()
            || self.boot_id.trim().is_empty()
        {
            return Err(AccessLedgerError::Invalid("serving replica identity"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GateEntry {
    principal_hash: String,
    replica: ServingReplica,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalEntry {
    lease_uid: String,
    gate_name: String,
    replica: ServingReplica,
}

/// Durable lifetime reservation for one idempotency key.
///
/// Written before the `SandboxExecution` CREATE. `creation_state=creating` is a
/// durable tombstone: neither a clock nor a 404 may retire it because a CREATE
/// request whose response was lost can still land. Only an exact object UID or
/// a definitive API rejection moves that state forward. `active` is the
/// process-count slot and is retired only before Kobe crosses `startedAt`, or
/// after destruction proves the exact target absent. Runner verdicts are not
/// absence proof because the workload can forge their spool. Entries remain
/// until lease teardown, bounding retained history independently of how quickly
/// commands finish.
///
/// `writer` records the exact serving replica that opened the row, giving the
/// tombstone the same writer-liveness fence gate entries have: once that exact
/// process is provably gone ([`stale_for_current_replica`]) and a strong 404
/// observed the object absent, [`expire_orphaned_creating_execution`] can
/// resolve the row — a late CREATE could still land, but only the writer's own
/// resolve task could have bound it or started its runner, so the object it
/// might still produce is inert. Rows predating the field, or written without a
/// replica identity, keep the older fail-closed behavior and are never retired
/// by this path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionEntry {
    request_digest: String,
    pod_uid: String,
    reserved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_uid: Option<String>,
    #[serde(default)]
    creation_state: ExecutionCreationState,
    active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writer: Option<ServingReplica>,
}

impl ExecutionEntry {
    fn effective_creation_state(&self) -> ExecutionCreationState {
        if self.execution_uid.is_some() {
            ExecutionCreationState::Bound
        } else {
            self.creation_state
        }
    }
}

/// Monotonic resolution of the Kubernetes CREATE for one execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExecutionCreationState {
    /// The request may not have reached the API server, or may still land.
    #[default]
    Creating,
    /// An exact `SandboxExecution` UID was committed into this ledger row.
    Bound,
    /// The API server definitively rejected the CREATE without creating it.
    Rejected,
}

/// Result of reserving one execution's lifetime and active-process slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionCapacity {
    /// A new key consumed one lifetime and one active slot.
    Reserved,
    /// This exact key/digest already owns an active slot (lost response/retry).
    ExistingActive {
        execution_uid: Option<String>,
    },
    /// This exact key already settled; only its existing record may be read.
    ExistingTerminal {
        execution_uid: Option<String>,
    },
    LeaseClosed,
    LimitReached,
    Conflict,
}

fn reserve_execution_entry(
    entries: &mut BTreeMap<String, ExecutionEntry>,
    execution_name: &str,
    request_digest: &str,
    pod_uid: &str,
    reserved_at: &str,
    writer: Option<&ServingReplica>,
) -> ExecutionCapacity {
    if let Some(existing) = entries.get(execution_name) {
        if existing.request_digest != request_digest || existing.pod_uid != pod_uid {
            return ExecutionCapacity::Conflict;
        }
        return if existing.active {
            ExecutionCapacity::ExistingActive {
                execution_uid: existing.execution_uid.clone(),
            }
        } else {
            ExecutionCapacity::ExistingTerminal {
                execution_uid: existing.execution_uid.clone(),
            }
        };
    }
    let active = entries.values().filter(|entry| entry.active).count();
    if entries.len() >= crate::api::sandbox_executions::MAX_EXECUTIONS_PER_LEASE
        || active >= crate::api::sandbox_executions::MAX_ACTIVE_EXECUTIONS_PER_LEASE
    {
        return ExecutionCapacity::LimitReached;
    }
    entries.insert(
        execution_name.to_string(),
        ExecutionEntry {
            request_digest: request_digest.to_string(),
            pod_uid: pod_uid.to_string(),
            reserved_at: reserved_at.to_string(),
            execution_uid: None,
            creation_state: ExecutionCreationState::Creating,
            active: true,
            writer: writer.cloned(),
        },
    );
    ExecutionCapacity::Reserved
}

/// Read-only execution identity exposed to teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionManifestEntry {
    pub name: String,
    pub request_digest: String,
    pub pod_uid: String,
    pub reserved_at: String,
    pub execution_uid: Option<String>,
    pub creation_state: ExecutionCreationState,
    pub active: bool,
    /// Exact serving replica that opened the reservation, when known. Rows
    /// without one predate the writer fence and are never liveness-retired.
    pub writer: Option<ServingReplica>,
}

fn execution_can_release_active_capacity(
    state: crate::crd::ExecutionState,
    started: bool,
    process_absence_proven: bool,
) -> bool {
    state.is_terminal() && (!started || process_absence_proven)
}

/// Immutable, non-secret handle persisted atomically with Sandbox admission.
///
/// The deterministic name prevents duplicate gates; the UID prevents a
/// same-named replacement from becoming teardown or access authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessGateReference {
    pub name: String,
    pub uid: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AccessLedgerError {
    #[error("Sandbox access ledger has invalid {0}")]
    Invalid(&'static str),
    #[error("Sandbox access ledger CAS did not converge")]
    Contended,
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("Sandbox access ledger mutation task failed: {0}")]
    MutationTask(#[source] tokio::task::JoinError),
}

/// Result of globally reserving one operation.
pub enum AccessAcquire {
    Acquired(Box<AccessGuard>),
    LeaseClosed,
    LimitReached,
}

/// Result of closing a lease gate before destructive cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDrain {
    /// A close/create checkpoint was written; re-read it on the next pass.
    Checkpointed,
    /// Live replicas still own one or more operations.
    Waiting,
    /// The gate is closed and contains no operations.
    Drained,
}

#[derive(Clone)]
struct AccessClient {
    client: Client,
    namespace: String,
}

/// Durable distributed registration paired with the replica-local guard.
///
/// Drop removes the principal entry first and the lease-gate entry second. If
/// the process dies between them, the remaining gate entry keeps teardown
/// blocked until startup recovery or the controller proves the replica Pod is
/// absent; uncertainty never turns into cleanup permission.
pub struct AccessGuard {
    access: Arc<AccessClient>,
    registration: ReleaseRegistration,
    /// An acquisition PATCH remains owned after the request future is
    /// cancelled. Drop waits for its ambiguous outcome before cleanup, so a
    /// late commit cannot recreate the exact entry after cleanup observed it
    /// absent.
    pending_write: Option<tokio::task::JoinHandle<Result<Lease, kube::Error>>>,
}

#[derive(Clone)]
struct ReleaseRegistration {
    sandbox_name: String,
    sandbox_uid: String,
    gate_name: String,
    expected_gate_uid: String,
    gate_uid: Option<String>,
    principal_name: String,
    principal_uid: Option<String>,
    principal_hash: String,
    operation_id: String,
    replica: ServingReplica,
}

impl std::fmt::Debug for AccessGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessGuard")
            .field("gate_name", &self.registration.gate_name)
            .field("operation_id", &self.registration.operation_id)
            .finish_non_exhaustive()
    }
}

impl Drop for AccessGuard {
    fn drop(&mut self) {
        let access = self.access.clone();
        let registration = self.registration.clone();
        let pending_write = self.pending_write.take();
        if pending_write.is_none()
            && registration.gate_uid.is_none()
            && registration.principal_uid.is_none()
        {
            return;
        }
        tokio::spawn(async move {
            if let Some(pending_write) = pending_write {
                match pending_write.await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => warn!(
                        %error,
                        operation = %registration.operation_id,
                        "ambiguous Sandbox access acquisition PATCH completed with an error before cleanup"
                    ),
                    Err(error) => warn!(
                        %error,
                        operation = %registration.operation_id,
                        "ambiguous Sandbox access acquisition PATCH task failed before cleanup"
                    ),
                }
            }
            loop {
                match release_exact(&access, &registration).await {
                    Ok(()) => return,
                    Err(error) => {
                        // Keep owning the registration while this exact Pod is
                        // alive. If the process exits, startup recovery for the
                        // next boot removes it before routes serve. A transient
                        // API failure must not turn into a permanent same-boot
                        // entry that teardown can never distinguish from a
                        // live socket.
                        warn!(error = %error, operation = %registration.operation_id, "could not release Sandbox access registration; retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
        });
    }
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn gate_name(lease_uid: &str) -> String {
    format!("kobe-access-g-{}", &digest(lease_uid)[..40])
}

fn principal_name(principal_hash: &str) -> String {
    format!("kobe-access-p-{}", &digest(principal_hash)[..40])
}

fn annotation_path(key: &str) -> String {
    format!(
        "/metadata/annotations/{}",
        key.replace('~', "~0").replace('/', "~1")
    )
}

fn parse_entries<T>(lease: &Lease) -> Result<BTreeMap<String, T>, AccessLedgerError>
where
    T: for<'de> Deserialize<'de>,
{
    let encoded = lease
        .annotations()
        .get(ENTRIES_ANNOTATION)
        .ok_or(AccessLedgerError::Invalid("entries annotation"))?;
    Ok(serde_json::from_str(encoded)?)
}

fn parse_execution_entries(
    lease: &Lease,
) -> Result<BTreeMap<String, ExecutionEntry>, AccessLedgerError> {
    let encoded = lease
        .annotations()
        .get(EXECUTIONS_ANNOTATION)
        .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
    Ok(serde_json::from_str(encoded)?)
}

fn lease_uid(lease: &Lease) -> Result<&str, AccessLedgerError> {
    lease
        .metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("object UID"))
}

fn lease_rv(lease: &Lease) -> Result<&str, AccessLedgerError> {
    lease
        .metadata
        .resource_version
        .as_deref()
        .filter(|rv| !rv.is_empty())
        .ok_or(AccessLedgerError::Invalid("object resourceVersion"))
}

fn build_gate(namespace: &str, lease_name: &str, lease_uid: &str, state: &'static str) -> Lease {
    Lease {
        metadata: ObjectMeta {
            name: Some(gate_name(lease_uid)),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), lease_name.into()),
                (LEASE_UID_LABEL.into(), lease_uid.into()),
            ])),
            annotations: Some(BTreeMap::from([
                (STATE_ANNOTATION.into(), state.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
                (EXECUTIONS_ANNOTATION.into(), "{}".into()),
            ])),
            ..ObjectMeta::default()
        },
        spec: Some(LeaseSpec::default()),
    }
}

fn build_principal(namespace: &str, principal_hash: &str) -> Lease {
    Lease {
        metadata: ObjectMeta {
            name: Some(principal_name(principal_hash)),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([(
                LEDGER_KIND_LABEL.into(),
                PRINCIPAL_KIND.into(),
            )])),
            annotations: Some(BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), principal_hash.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ])),
            ..ObjectMeta::default()
        },
        spec: Some(LeaseSpec::default()),
    }
}

fn optimistic_conflict(error: &kube::Error) -> bool {
    let kube::Error::Api(response) = error else {
        return false;
    };
    match response.code {
        409 => true,
        422 => response
            .details
            .as_ref()
            .is_none_or(|details| details.causes.is_empty()),
        _ => false,
    }
}

async fn get_or_create_open_gate(
    api: &Api<Lease>,
    namespace: &str,
    lease_name: &str,
    expected_lease_uid: &str,
) -> Result<(Lease, bool), AccessLedgerError> {
    let name = gate_name(expected_lease_uid);
    match api.get(&name).await {
        Ok(gate) => Ok((gate, false)),
        Err(kube::Error::Api(response)) if response.code == 404 => {
            match api
                .create(
                    &PostParams::default(),
                    &build_gate(namespace, lease_name, expected_lease_uid, OPEN),
                )
                .await
            {
                Ok(created) => Ok((created, true)),
                Err(error) if optimistic_conflict(&error) => Ok((api.get(&name).await?, false)),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Create the empty, open access gate before a lease can be admitted.
///
/// This is an admission invariant rather than lazy handler setup. Every
/// admitted lease must already occupy its deterministic gate name, otherwise a
/// full ledger quota could prevent teardown from closing the gate and proving
/// access drained. Existing gates are accepted only when their exact
/// lease-name/UID provenance, open state, and empty entry set all match.
pub async fn prepare_open_gate(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
) -> Result<AccessGateReference, AccessLedgerError> {
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let (gate, _) =
        get_or_create_open_gate(&api, ledger_namespace, &sandbox_name, &sandbox_uid).await?;
    validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
        return Err(AccessLedgerError::Invalid("lease gate state"));
    }
    if !parse_entries::<GateEntry>(&gate)?.is_empty() {
        return Err(AccessLedgerError::Invalid(
            "pre-admission lease gate entries",
        ));
    }
    if !parse_execution_entries(&gate)?.is_empty() {
        return Err(AccessLedgerError::Invalid(
            "pre-admission execution entries",
        ));
    }
    Ok(AccessGateReference {
        name: gate.name_any(),
        uid: lease_uid(&gate)?.to_string(),
    })
}

/// Encode one exact gate handle for the atomic admission metadata patch.
pub fn encode_gate_reference(reference: &AccessGateReference) -> Result<String, AccessLedgerError> {
    if reference.name.trim().is_empty() || reference.uid.trim().is_empty() {
        return Err(AccessLedgerError::Invalid("access gate reference"));
    }
    Ok(serde_json::to_string(reference)?)
}

/// Read the exact gate handle committed with an admitted SandboxLease.
pub fn persisted_gate_reference(
    lease: &SandboxLease,
) -> Result<AccessGateReference, AccessLedgerError> {
    let encoded =
        lease
            .annotations()
            .get(ACCESS_GATE_ANNOTATION)
            .ok_or(AccessLedgerError::Invalid(
                "persisted access gate reference",
            ))?;
    let reference: AccessGateReference = serde_json::from_str(encoded)?;
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    if reference.name != gate_name(&sandbox_uid) || reference.uid.trim().is_empty() {
        return Err(AccessLedgerError::Invalid(
            "persisted access gate reference",
        ));
    }
    Ok(reference)
}

/// Prove an admitted lease still owns the exact open gate recorded at admission.
///
/// Placement calls this before creating any Sandbox footprint. The admission
/// marker alone is insufficient: a committed patch whose response was mutated
/// or whose gate annotation was stripped must retain its durable handle without
/// becoming workload authority. Exact name, object UID, full object shape, open
/// state, and typed entries are all required.
pub async fn verify_open_admitted_gate(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
) -> Result<(), AccessLedgerError> {
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let expected = persisted_gate_reference(lease)?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let gate = match api.get(&expected.name).await {
        Ok(gate) => gate,
        Err(kube::Error::Api(response)) if response.code == 404 => {
            return Err(AccessLedgerError::Invalid("missing admitted lease gate"));
        }
        Err(error) => return Err(error.into()),
    };
    validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
    if lease_uid(&gate)? != expected.uid {
        return Err(AccessLedgerError::Invalid("persisted access gate UID"));
    }
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
        return Err(AccessLedgerError::Invalid(
            "admitted lease gate is not open",
        ));
    }
    parse_entries::<GateEntry>(&gate)?;
    Ok(())
}

/// Remove an empty pre-admission gate after the exact parent is proven absent.
///
/// The caller owns the parent-404 fence. This helper never treats a DELETE
/// response as absence: it UID/resourceVersion-deletes the exact open gate and
/// then requires a 404, so failed admission cannot accumulate gates until the
/// namespace quota blocks unrelated cleanup.
pub async fn remove_pre_admission_gate(
    api: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<(), AccessLedgerError> {
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let name = gate_name(&sandbox_uid);
    let gate = match api.get(&name).await {
        Ok(gate) => gate,
        Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let ledger_namespace = api
        .namespace()
        .ok_or(AccessLedgerError::Invalid("ledger namespace"))?;
    validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN)
        || !parse_entries::<GateEntry>(&gate)?.is_empty()
        || !parse_execution_entries(&gate)?.is_empty()
    {
        return Err(AccessLedgerError::Invalid("pre-admission lease gate state"));
    }
    let expected_uid = lease_uid(&gate)?.to_string();
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(expected_uid.clone()),
            resource_version: Some(lease_rv(&gate)?.to_string()),
        }),
        ..DeleteParams::default()
    };
    let deletion = api.delete(&name, &params).await;
    match api.get(&name).await {
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Ok(replacement) if lease_uid(&replacement)? != expected_uid => Ok(()),
        Ok(_) => match deletion {
            Ok(_) => Err(AccessLedgerError::Invalid(
                "pre-admission gate deletion not confirmed",
            )),
            Err(error) => Err(error.into()),
        },
        Err(error) => Err(error.into()),
    }
}

fn validate_gate(
    gate: &Lease,
    expected_namespace: &str,
    expected_lease_name: &str,
    expected_lease_uid: &str,
) -> Result<(), AccessLedgerError> {
    let expected_labels = BTreeMap::from([
        (LEDGER_KIND_LABEL.to_string(), GATE_KIND.to_string()),
        (
            LEASE_NAME_LABEL.to_string(),
            expected_lease_name.to_string(),
        ),
        (LEASE_UID_LABEL.to_string(), expected_lease_uid.to_string()),
    ]);
    if gate.name_any() != gate_name(expected_lease_uid)
        || gate.namespace().as_deref() != Some(expected_namespace)
        || gate.labels() != &expected_labels
        || !gate
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || !gate
            .metadata
            .finalizers
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || gate.metadata.deletion_timestamp.is_some()
        || gate.spec.as_ref() != Some(&LeaseSpec::default())
    {
        return Err(AccessLedgerError::Invalid("lease gate provenance"));
    }
    let annotations = gate.annotations();
    if annotations.len() != 3
        || !annotations.contains_key(ENTRIES_ANNOTATION)
        || !annotations.contains_key(EXECUTIONS_ANNOTATION)
    {
        return Err(AccessLedgerError::Invalid("lease gate annotations"));
    }
    match annotations.get(STATE_ANNOTATION).map(String::as_str) {
        Some(OPEN | CLOSED) => {
            parse_execution_entries(gate)?;
            Ok(())
        }
        _ => Err(AccessLedgerError::Invalid("lease gate state")),
    }
}

fn validate_principal(
    ledger: &Lease,
    expected_namespace: &str,
    expected_principal_hash: &str,
) -> Result<(), AccessLedgerError> {
    let expected_labels =
        BTreeMap::from([(LEDGER_KIND_LABEL.to_string(), PRINCIPAL_KIND.to_string())]);
    if ledger.name_any() != principal_name(expected_principal_hash)
        || ledger.namespace().as_deref() != Some(expected_namespace)
        || ledger.labels() != &expected_labels
        || !ledger
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || !ledger
            .metadata
            .finalizers
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || ledger.metadata.deletion_timestamp.is_some()
        || ledger.spec.as_ref() != Some(&LeaseSpec::default())
    {
        return Err(AccessLedgerError::Invalid("principal ledger provenance"));
    }
    let annotations = ledger.annotations();
    if annotations.len() != 2
        || annotations.get(PRINCIPAL_ANNOTATION).map(String::as_str)
            != Some(expected_principal_hash)
        || !annotations.contains_key(ENTRIES_ANNOTATION)
    {
        return Err(AccessLedgerError::Invalid("principal ledger annotations"));
    }
    Ok(())
}

async fn patch_entries<T: Serialize>(
    api: &Api<Lease>,
    object: &Lease,
    previous: &str,
    entries: &BTreeMap<String, T>,
) -> Result<Lease, AccessLedgerError> {
    let next = serde_json::to_string(entries)?;
    let patch = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid(object)? },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(object)? },
        { "op": "test", "path": annotation_path(ENTRIES_ANNOTATION), "value": previous },
        { "op": "replace", "path": annotation_path(ENTRIES_ANNOTATION), "value": next }
    ]);
    Ok(api
        .patch(
            &object.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(serde_json::from_value(patch).expect("valid access-ledger patch")),
        )
        .await?)
}

/// Run an acquisition PATCH in a task whose handle is stored in the guard.
///
/// Dropping a Kubernetes request future does not prove the API server rejected
/// it. The owning request may be cancelled while the response is lost but the
/// write is still in flight. Keeping the handle in [`AccessGuard`] lets Drop
/// wait for that exact request to become terminal before it starts CAS cleanup.
async fn patch_entries_for_acquire<T: Serialize>(
    api: &Api<Lease>,
    object: &Lease,
    previous: &str,
    entries: &BTreeMap<String, T>,
    pending_write: &mut Option<tokio::task::JoinHandle<Result<Lease, kube::Error>>>,
) -> Result<Lease, AccessLedgerError> {
    if pending_write.is_some() {
        return Err(AccessLedgerError::Invalid(
            "overlapping access acquisition mutation",
        ));
    }
    let next = serde_json::to_string(entries)?;
    let patch = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid(object)? },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(object)? },
        { "op": "test", "path": annotation_path(ENTRIES_ANNOTATION), "value": previous },
        { "op": "replace", "path": annotation_path(ENTRIES_ANNOTATION), "value": next }
    ]);
    let api = api.clone();
    let name = object.name_any();
    *pending_write = Some(tokio::spawn(async move {
        api.patch(
            &name,
            &PatchParams::default(),
            &Patch::<()>::Json(
                serde_json::from_value(patch).expect("valid access-ledger acquisition patch"),
            ),
        )
        .await
    }));
    let result = pending_write
        .as_mut()
        .expect("acquisition PATCH handle was just installed")
        .await;
    pending_write.take();
    match result {
        Ok(result) => Ok(result?),
        Err(error) => Err(AccessLedgerError::MutationTask(error)),
    }
}

async fn patch_execution_entries(
    api: &Api<Lease>,
    gate: &Lease,
    previous: &str,
    entries: &BTreeMap<String, ExecutionEntry>,
) -> Result<Lease, AccessLedgerError> {
    let next = serde_json::to_string(entries)?;
    let patch = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid(gate)? },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(gate)? },
        { "op": "test", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": previous },
        { "op": "replace", "path": annotation_path(EXECUTIONS_ANNOTATION), "value": next }
    ]);
    Ok(api
        .patch(
            &gate.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(
                serde_json::from_value(patch).expect("valid execution-ledger patch"),
            ),
        )
        .await?)
}

async fn add_gate_entry(
    api: &Api<Lease>,
    registration: &mut ReleaseRegistration,
    pending_write: &mut Option<tokio::task::JoinHandle<Result<Lease, kube::Error>>>,
) -> Result<Option<Lease>, AccessLedgerError> {
    let ledger_namespace = api
        .namespace()
        .ok_or(AccessLedgerError::Invalid("ledger namespace"))?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = api.get(&registration.gate_name).await?;
        validate_gate(
            &gate,
            ledger_namespace,
            &registration.sandbox_name,
            &registration.sandbox_uid,
        )?;
        if lease_uid(&gate)? != registration.expected_gate_uid {
            return Err(AccessLedgerError::Invalid("persisted access gate UID"));
        }
        // Arm exact cleanup before the PATCH await. If the request task is
        // cancelled after the apiserver commits but before its response is
        // observed, Drop still has the only UID it may mutate.
        registration.gate_uid = Some(lease_uid(&gate)?.to_string());
        if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
            return Ok(None);
        }
        let previous = gate
            .annotations()
            .get(ENTRIES_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("entries annotation"))?;
        let mut entries: BTreeMap<String, GateEntry> = serde_json::from_str(&previous)?;
        if entries.len() >= crate::api::sandbox_streams::MAX_STREAMS_PER_LEASE {
            return Ok(None);
        }
        entries.insert(
            registration.operation_id.clone(),
            GateEntry {
                principal_hash: registration.principal_hash.clone(),
                replica: registration.replica.clone(),
            },
        );
        match patch_entries_for_acquire(api, &gate, &previous, &entries, pending_write).await {
            Ok(updated) => return Ok(Some(updated)),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

async fn add_principal_entry(
    api: &Api<Lease>,
    namespace: &str,
    gate: &Lease,
    registration: &mut ReleaseRegistration,
    pending_write: &mut Option<tokio::task::JoinHandle<Result<Lease, kube::Error>>>,
) -> Result<Option<Lease>, AccessLedgerError> {
    let name = registration.principal_name.clone();
    for _ in 0..MAX_CAS_ATTEMPTS {
        let ledger = match api.get(&name).await {
            Ok(ledger) => ledger,
            Err(kube::Error::Api(response)) if response.code == 404 => {
                match api
                    .create(
                        &PostParams::default(),
                        &build_principal(namespace, &registration.principal_hash),
                    )
                    .await
                {
                    Ok(created) => created,
                    Err(error) if optimistic_conflict(&error) => api.get(&name).await?,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        validate_principal(&ledger, namespace, &registration.principal_hash)?;
        registration.principal_uid = Some(lease_uid(&ledger)?.to_string());
        let previous = ledger
            .annotations()
            .get(ENTRIES_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("entries annotation"))?;
        let mut entries: BTreeMap<String, PrincipalEntry> = serde_json::from_str(&previous)?;
        if entries.len() >= crate::api::sandbox_streams::MAX_STREAMS_PER_PRINCIPAL {
            return Ok(None);
        }
        entries.insert(
            registration.operation_id.clone(),
            PrincipalEntry {
                lease_uid: registration.sandbox_uid.clone(),
                gate_name: gate.name_any(),
                replica: registration.replica.clone(),
            },
        );
        match patch_entries_for_acquire(api, &ledger, &previous, &entries, pending_write).await {
            Ok(updated) => return Ok(Some(updated)),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Atomically enter the per-lease and per-principal global limits.
pub async fn acquire(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    principal_hash: &str,
    replica: &ServingReplica,
) -> Result<AccessAcquire, AccessLedgerError> {
    replica.validate()?;
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let expected_gate = persisted_gate_reference(lease)?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let operation_id = uuid::Uuid::new_v4().to_string();
    // Construct the cleanup owner before the first API await. Request-task
    // cancellation can happen while any CREATE/PATCH response is in flight;
    // deterministic names plus the unguessable operation id let Drop discover
    // and retire a write even when its success response was lost.
    let mut guard = Box::new(AccessGuard {
        access: Arc::new(AccessClient {
            client: client.clone(),
            namespace: ledger_namespace.into(),
        }),
        registration: ReleaseRegistration {
            sandbox_name: sandbox_name.clone(),
            sandbox_uid: sandbox_uid.clone(),
            gate_name: expected_gate.name,
            expected_gate_uid: expected_gate.uid,
            gate_uid: None,
            principal_name: principal_name(principal_hash),
            principal_uid: None,
            principal_hash: principal_hash.into(),
            operation_id: operation_id.clone(),
            replica: replica.clone(),
        },
        pending_write: None,
    });
    let guard_mut = &mut *guard;
    let Some(gate) = add_gate_entry(
        &api,
        &mut guard_mut.registration,
        &mut guard_mut.pending_write,
    )
    .await?
    else {
        let name = gate_name(&sandbox_uid);
        return match api.get(&name).await {
            Ok(gate)
                if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) == Some(CLOSED) =>
            {
                Ok(AccessAcquire::LeaseClosed)
            }
            Ok(_) => Ok(AccessAcquire::LimitReached),
            Err(error) => Err(error.into()),
        };
    };
    let guard_mut = &mut *guard;
    let principal = add_principal_entry(
        &api,
        ledger_namespace,
        &gate,
        &mut guard_mut.registration,
        &mut guard_mut.pending_write,
    )
    .await?;
    let Some(_principal) = principal else {
        remove_gate_entry(
            &api,
            &gate.name_any(),
            lease_uid(&gate)?,
            &sandbox_name,
            &sandbox_uid,
            &operation_id,
            &GateEntry {
                principal_hash: principal_hash.into(),
                replica: replica.clone(),
            },
        )
        .await?;
        guard.registration.gate_uid = None;
        return Ok(AccessAcquire::LimitReached);
    };
    Ok(AccessAcquire::Acquired(guard))
}

async fn exact_gate_for_lease(
    api: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<Lease, AccessLedgerError> {
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let expected = persisted_gate_reference(lease)?;
    let gate = api.get(&expected.name).await?;
    let ledger_namespace = api
        .namespace()
        .ok_or(AccessLedgerError::Invalid("ledger namespace"))?;
    validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
    if lease_uid(&gate)? != expected.uid {
        return Err(AccessLedgerError::Invalid("persisted access gate UID"));
    }
    Ok(gate)
}

/// Reserve one lifetime-history entry and one active process slot.
///
/// This CAS precedes the `SandboxExecution` CREATE. Retrying after an ambiguous
/// CREATE is safe because the derived execution name and request digest are
/// already durable here; a different request under the same name conflicts and
/// no request can exceed either bound by racing another replica.
///
/// `writer` is recorded on the new row so startup recovery can later prove the
/// reserving process gone; see [`expire_orphaned_creating_execution`]. Passing
/// `None` keeps the legacy fail-closed row, which no liveness path may retire.
pub async fn reserve_execution_capacity(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    execution_name: &str,
    request_digest: &str,
    pod_uid: &str,
    writer: Option<&ServingReplica>,
) -> Result<ExecutionCapacity, AccessLedgerError> {
    if execution_name.is_empty() || request_digest.len() != 64 || pod_uid.is_empty() {
        return Err(AccessLedgerError::Invalid("execution reservation identity"));
    }
    if let Some(writer) = writer {
        writer.validate()?;
    }
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
            return Ok(ExecutionCapacity::LeaseClosed);
        }
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let outcome = reserve_execution_entry(
            &mut entries,
            execution_name,
            request_digest,
            pod_uid,
            &chrono::Utc::now().to_rfc3339(),
            writer,
        );
        if outcome != ExecutionCapacity::Reserved {
            return Ok(outcome);
        }
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(ExecutionCapacity::Reserved),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Bind a reserved slot to the exact API-server UID before marking it Running.
///
/// A close racing this checkpoint wins through the shared gate
/// resourceVersion. When close wins this returns `false`; the record remains
/// Queued and teardown removes it, but no runner may be started.
pub async fn bind_execution_capacity(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    execution: &crate::crd::SandboxExecution,
) -> Result<bool, AccessLedgerError> {
    let execution_uid = execution
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxExecution UID"))?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
            return Ok(false);
        }
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let entry = entries
            .get_mut(&execution.name_any())
            .ok_or(AccessLedgerError::Invalid("execution reservation"))?;
        if !entry.active
            || entry.request_digest != execution.spec.request_digest
            || entry.pod_uid != execution.spec.pod_uid
        {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        match entry.execution_uid.as_deref() {
            Some(uid) if uid == execution_uid => return Ok(true),
            Some(_) => return Err(AccessLedgerError::Invalid("execution reservation UID")),
            None if entry.creation_state == ExecutionCreationState::Creating => {
                entry.execution_uid = Some(execution_uid.clone());
                entry.creation_state = ExecutionCreationState::Bound;
            }
            None => {
                return Err(AccessLedgerError::Invalid(
                    "execution creation is already resolved",
                ));
            }
        }
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Retire one active slot only after its exact execution record is terminal.
///
/// The lifetime entry remains, so finishing quickly cannot bypass the
/// per-Sandbox history/disk bound with a stream of new idempotency keys.
/// `process_absence_proven` is reserved for teardown after an exact target
/// destruction receipt. The runner spool is writable by the workload UID, so
/// no runner report—including a plausible terminal one—may release capacity
/// for a command that crossed the Kubernetes `startedAt` checkpoint.
pub async fn complete_execution_capacity(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    execution: &crate::crd::SandboxExecution,
    process_absence_proven: bool,
) -> Result<(), AccessLedgerError> {
    let state = execution
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    let started = execution
        .status
        .as_ref()
        .and_then(|status| status.started_at.as_ref())
        .is_some();
    if !execution_can_release_active_capacity(state, started, process_absence_proven) {
        return Err(AccessLedgerError::Invalid(
            "execution process group is not proven terminal",
        ));
    }
    let execution_uid = execution
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxExecution UID"))?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let entry = entries
            .get_mut(&execution.name_any())
            .ok_or(AccessLedgerError::Invalid("execution reservation"))?;
        if entry.request_digest != execution.spec.request_digest
            || entry.pod_uid != execution.spec.pod_uid
            || entry.execution_uid.as_deref() != Some(execution_uid.as_str())
            || entry.effective_creation_state() != ExecutionCreationState::Bound
        {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        if !entry.active {
            return Ok(());
        }
        entry.active = false;
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(()),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Read the exact closed/open gate's durable execution manifest.
pub async fn execution_manifest(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
) -> Result<Vec<ExecutionManifestEntry>, AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let gate = exact_gate_for_lease(&api, lease).await?;
    Ok(parse_execution_entries(&gate)?
        .into_iter()
        .map(|(name, entry)| {
            let creation_state = entry.effective_creation_state();
            ExecutionManifestEntry {
                name,
                request_digest: entry.request_digest,
                pod_uid: entry.pod_uid,
                reserved_at: entry.reserved_at,
                execution_uid: entry.execution_uid,
                creation_state,
                active: entry.active,
                writer: entry.writer,
            }
        })
        .collect())
}

/// Adopt an exact execution whose CREATE/bind response was lost.
///
/// A missing object is deliberately a no-op: 404 does not prove that an
/// in-flight CREATE cannot still land. When an exact object is visible, its UID
/// is captured in the same CAS that closes the active slot. A concurrent bind
/// either wins first (and this returns `false`) or sees `active=false` and can
/// never start the runner afterward.
pub async fn expire_unbound_execution(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    execution_name: &str,
    expected_digest: &str,
    expected_pod_uid: &str,
    observed_execution_uid: Option<&str>,
) -> Result<bool, AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let entry = entries
            .get_mut(execution_name)
            .ok_or(AccessLedgerError::Invalid("execution reservation"))?;
        if entry.request_digest != expected_digest || entry.pod_uid != expected_pod_uid {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        if entry.execution_uid.is_some() {
            return Ok(false);
        }
        let Some(uid) = observed_execution_uid else {
            return Ok(false);
        };
        if uid.is_empty() {
            return Err(AccessLedgerError::Invalid("SandboxExecution UID"));
        }
        if entry.creation_state != ExecutionCreationState::Creating {
            return Ok(false);
        }
        entry.execution_uid = Some(uid.to_string());
        entry.creation_state = ExecutionCreationState::Bound;
        entry.active = false;
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Retire a `Creating` tombstone whose exact writer is provably gone.
///
/// The tombstone exists because an ambiguous CREATE might still land. Writer
/// death changes that calculus: only the reserving replica's own resolve task
/// could have bound the object or started its runner, and
/// [`stale_for_current_replica`] proves that exact process cannot own a live
/// connection anymore — same Pod name resolves to `current.pod_uid`, so an
/// older boot or older-UID Pod is gone by Kubernetes name uniqueness. Whatever
/// a late CREATE still produces is inert: never bound, never spawned, and
/// already handled as an orphan record by the object-side reaper.
///
/// The caller must have observed a strong 404 for the exact object first; the
/// row must match `expected` field-for-field so a same-named key replacement
/// cannot be retired as somebody else's evidence. The row flips to `Rejected`
/// with its active slot released — the same durable shape
/// [`reject_execution_creation`] leaves — so teardown's existing retirement
/// machinery takes it from there. Rows without a recorded writer, rows whose
/// writer is not provably dead relative to `current`, and rows already bound
/// are refused.
pub async fn expire_orphaned_creating_execution(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    expected: &ExecutionManifestEntry,
    current: &ServingReplica,
) -> Result<bool, AccessLedgerError> {
    current.validate()?;
    if expected.execution_uid.is_some() {
        return Err(AccessLedgerError::Invalid("bound execution reservation"));
    }
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let entry = entries
            .get_mut(&expected.name)
            .ok_or(AccessLedgerError::Invalid("execution reservation"))?;
        if entry.execution_uid.is_some()
            || entry.request_digest != expected.request_digest
            || entry.pod_uid != expected.pod_uid
            || entry.reserved_at != expected.reserved_at
            || entry.creation_state != ExecutionCreationState::Creating
        {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        let stale = entry
            .writer
            .as_ref()
            .is_some_and(|writer| stale_for_current_replica(writer, current));
        if !stale {
            return Ok(false);
        }
        entry.creation_state = ExecutionCreationState::Rejected;
        entry.active = false;
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Resolve a CREATE that the API server definitively rejected.
///
/// Transport failures, timeouts, 5xx responses, and 404 observations do not
/// qualify. The rejection and exact identity are committed by CAS so a racing
/// bind either wins first or can no longer start a runner afterward.
pub async fn reject_execution_creation(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    execution_name: &str,
    expected_digest: &str,
    expected_pod_uid: &str,
) -> Result<bool, AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let entry = entries
            .get_mut(execution_name)
            .ok_or(AccessLedgerError::Invalid("execution reservation"))?;
        if entry.request_digest != expected_digest || entry.pod_uid != expected_pod_uid {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        if entry.execution_uid.is_some()
            || entry.effective_creation_state() == ExecutionCreationState::Bound
        {
            return Ok(false);
        }
        if entry.creation_state == ExecutionCreationState::Rejected {
            return Ok(false);
        }
        entry.creation_state = ExecutionCreationState::Rejected;
        entry.active = false;
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Remove a definitively rejected CREATE after the gate is closed.
pub async fn retire_rejected_execution(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    expected: &ExecutionManifestEntry,
) -> Result<bool, AccessLedgerError> {
    if expected.active
        || expected.execution_uid.is_some()
        || expected.creation_state != ExecutionCreationState::Rejected
    {
        return Err(AccessLedgerError::Invalid(
            "execution CREATE is not rejected",
        ));
    }
    retire_inactive_execution(client, ledger_namespace, lease, expected).await
}

/// Remove one inactive manifest row after its exact execution CR is absent.
///
/// `active=false` is the durable proof that exact target destruction or a
/// definitive pre-spawn rejection completed. A `Creating`
/// tombstone is never eligible: its request may still land. The complete entry
/// is compared before the CAS, so a same-named key or UID replacement cannot be
/// retired as somebody else's evidence.
pub async fn retire_inactive_execution(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
    expected: &ExecutionManifestEntry,
) -> Result<bool, AccessLedgerError> {
    if expected.active || expected.creation_state == ExecutionCreationState::Creating {
        return Err(AccessLedgerError::Invalid("active execution reservation"));
    }
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(CLOSED) {
            return Err(AccessLedgerError::Invalid("execution gate is not closed"));
        }
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let mut entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        let Some(entry) = entries.get(&expected.name) else {
            return Ok(false);
        };
        if entry.active
            || entry.request_digest != expected.request_digest
            || entry.pod_uid != expected.pod_uid
            || entry.reserved_at != expected.reserved_at
            || entry.execution_uid != expected.execution_uid
            || entry.effective_creation_state() != expected.creation_state
        {
            return Err(AccessLedgerError::Invalid("execution reservation identity"));
        }
        entries.remove(&expected.name);
        match patch_execution_entries(&api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

/// Clear the manifest after every exact execution record is absent.
///
/// Returns `true` when this call wrote the checkpoint. The caller requeues and
/// re-lists records before accepting the next pass as clean, so a lost response
/// cannot skip the final absence observation.
pub async fn clear_execution_manifest(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
) -> Result<bool, AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = exact_gate_for_lease(&api, lease).await?;
        if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(CLOSED)
            || !parse_entries::<GateEntry>(&gate)?.is_empty()
        {
            return Err(AccessLedgerError::Invalid("execution cleanup gate state"));
        }
        let previous = gate
            .annotations()
            .get(EXECUTIONS_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("executions annotation"))?;
        let entries: BTreeMap<String, ExecutionEntry> = serde_json::from_str(&previous)?;
        if entries.is_empty() {
            return Ok(false);
        }
        if entries.values().any(|entry| {
            entry.active || entry.effective_creation_state() == ExecutionCreationState::Creating
        }) {
            return Err(AccessLedgerError::Invalid("active execution reservation"));
        }
        match patch_execution_entries(&api, &gate, &previous, &BTreeMap::new()).await {
            Ok(_) => return Ok(true),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

async fn remove_principal_entry(
    api: &Api<Lease>,
    name: &str,
    expected_uid: &str,
    expected_principal_hash: &str,
    operation_id: &str,
    expected_entry: &PrincipalEntry,
) -> Result<(), AccessLedgerError> {
    let ledger_namespace = api
        .namespace()
        .ok_or(AccessLedgerError::Invalid("ledger namespace"))?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let ledger = match api.get(name).await {
            Ok(ledger) => ledger,
            Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if lease_uid(&ledger)? != expected_uid {
            // The expected object is gone. Never interpret its deterministic
            // name as authority to mutate a replacement; the old operation
            // entry could only have been committed under the recorded UID.
            return Ok(());
        }
        validate_principal(&ledger, ledger_namespace, expected_principal_hash)?;
        let previous = ledger
            .annotations()
            .get(ENTRIES_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("entries annotation"))?;
        let mut entries: BTreeMap<String, PrincipalEntry> = serde_json::from_str(&previous)?;
        let Some(entry) = entries.get(operation_id) else {
            return Ok(());
        };
        if entry != expected_entry {
            return Err(AccessLedgerError::Invalid("principal entry identity"));
        }
        entries.remove(operation_id);
        match patch_entries(api, &ledger, &previous, &entries).await {
            Ok(_) => return Ok(()),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

async fn remove_gate_entry(
    api: &Api<Lease>,
    name: &str,
    expected_uid: &str,
    expected_sandbox_name: &str,
    expected_sandbox_uid: &str,
    operation_id: &str,
    expected_entry: &GateEntry,
) -> Result<(), AccessLedgerError> {
    let ledger_namespace = api
        .namespace()
        .ok_or(AccessLedgerError::Invalid("ledger namespace"))?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = match api.get(name).await {
            Ok(gate) => gate,
            Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if lease_uid(&gate)? != expected_uid {
            // A same-named replacement cannot contain a PATCH committed under
            // the old UID/resourceVersion. Leave it untouched; controller
            // callers return Waiting and re-read the new gate on the next pass.
            return Ok(());
        }
        validate_gate(
            &gate,
            ledger_namespace,
            expected_sandbox_name,
            expected_sandbox_uid,
        )?;
        let previous = gate
            .annotations()
            .get(ENTRIES_ANNOTATION)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("entries annotation"))?;
        let mut entries: BTreeMap<String, GateEntry> = serde_json::from_str(&previous)?;
        let Some(entry) = entries.get(operation_id) else {
            return Ok(());
        };
        if entry != expected_entry {
            return Err(AccessLedgerError::Invalid("lease gate entry identity"));
        }
        entries.remove(operation_id);
        match patch_entries(api, &gate, &previous, &entries).await {
            Ok(_) => return Ok(()),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AccessLedgerError::Contended)
}

async fn release_exact(
    access: &AccessClient,
    registration: &ReleaseRegistration,
) -> Result<(), AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(access.client.clone(), &access.namespace);
    if let Some(principal_uid) = registration.principal_uid.as_deref() {
        remove_principal_entry(
            &api,
            &registration.principal_name,
            principal_uid,
            &registration.principal_hash,
            &registration.operation_id,
            &PrincipalEntry {
                lease_uid: registration.sandbox_uid.clone(),
                gate_name: registration.gate_name.clone(),
                replica: registration.replica.clone(),
            },
        )
        .await?;
    }
    if let Some(gate_uid) = registration.gate_uid.as_deref() {
        remove_gate_entry(
            &api,
            &registration.gate_name,
            gate_uid,
            &registration.sandbox_name,
            &registration.sandbox_uid,
            &registration.operation_id,
            &GateEntry {
                principal_hash: registration.principal_hash.clone(),
                replica: registration.replica.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

async fn close_gate(api: &Api<Lease>, gate: &Lease) -> Result<(), AccessLedgerError> {
    let current = gate
        .annotations()
        .get(STATE_ANNOTATION)
        .ok_or(AccessLedgerError::Invalid("lease gate state"))?;
    if current == CLOSED {
        return Ok(());
    }
    if current != OPEN {
        return Err(AccessLedgerError::Invalid("lease gate state"));
    }
    let patch = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": lease_uid(gate)? },
        { "op": "test", "path": "/metadata/resourceVersion", "value": lease_rv(gate)? },
        { "op": "test", "path": annotation_path(STATE_ANNOTATION), "value": OPEN },
        { "op": "replace", "path": annotation_path(STATE_ANNOTATION), "value": CLOSED }
    ]);
    api.patch(
        &gate.name_any(),
        &PatchParams::default(),
        &Patch::<()>::Json(serde_json::from_value(patch).expect("valid access-gate close patch")),
    )
    .await?;
    Ok(())
}

async fn replica_is_live(
    client: &Client,
    replica: &ServingReplica,
) -> Result<bool, AccessLedgerError> {
    replica.validate()?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), &replica.namespace);
    match pods.get(&replica.pod_name).await {
        Ok(pod) => {
            if pod.namespace().as_deref() != Some(replica.namespace.as_str())
                || pod.name_any() != replica.pod_name
            {
                return Err(AccessLedgerError::Invalid(
                    "observed serving replica Pod provenance",
                ));
            }
            let observed_uid =
                pod.uid()
                    .filter(|uid| !uid.is_empty())
                    .ok_or(AccessLedgerError::Invalid(
                        "observed serving replica Pod UID",
                    ))?;
            Ok(observed_uid == replica.pod_uid)
        }
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Close the global gate and prove all replica-owned operations drained.
pub async fn close_and_drain(
    client: &Client,
    ledger_namespace: &str,
    lease: &SandboxLease,
) -> Result<AccessDrain, AccessLedgerError> {
    let sandbox_name = lease.name_any();
    let sandbox_uid = lease
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(AccessLedgerError::Invalid("SandboxLease UID"))?;
    let expected_gate = persisted_gate_reference(lease)?;
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let gate = match api.get(&expected_gate.name).await {
        Ok(gate) => gate,
        Err(kube::Error::Api(response)) if response.code == 404 => {
            return Err(AccessLedgerError::Invalid("missing admitted lease gate"));
        }
        Err(error) => return Err(error.into()),
    };
    validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
    if lease_uid(&gate)? != expected_gate.uid {
        return Err(AccessLedgerError::Invalid("persisted access gate UID"));
    }
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) == Some(OPEN) {
        match close_gate(&api, &gate).await {
            Ok(()) => return Ok(AccessDrain::Checkpointed),
            Err(AccessLedgerError::Kubernetes(error)) if optimistic_conflict(&error) => {
                return Ok(AccessDrain::Waiting);
            }
            Err(error) => return Err(error),
        }
    }

    let gate_uid = lease_uid(&gate)?.to_string();
    let entries: BTreeMap<String, GateEntry> = parse_entries(&gate)?;
    if entries.is_empty() {
        return Ok(AccessDrain::Drained);
    }
    for (operation_id, entry) in entries {
        if replica_is_live(client, &entry.replica).await? {
            continue;
        }
        let principal_name = principal_name(&entry.principal_hash);
        let principal = match api.get(&principal_name).await {
            Ok(principal) => Some(principal),
            Err(kube::Error::Api(response)) if response.code == 404 => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(principal) = principal {
            let principal_uid = lease_uid(&principal)?.to_string();
            remove_principal_entry(
                &api,
                &principal_name,
                &principal_uid,
                &entry.principal_hash,
                &operation_id,
                &PrincipalEntry {
                    lease_uid: sandbox_uid.clone(),
                    gate_name: gate.name_any(),
                    replica: entry.replica.clone(),
                },
            )
            .await?;
        }
        remove_gate_entry(
            &api,
            &gate.name_any(),
            &gate_uid,
            &sandbox_name,
            &sandbox_uid,
            &operation_id,
            &entry,
        )
        .await?;
    }
    Ok(AccessDrain::Waiting)
}

/// Remove entries left by an older process in this Pod serving slot.
///
/// Called after the lease watch reaches `InitDone` and before Sandbox routes
/// serve. The current process is then the only process that can own this
/// namespace/name: a different boot id in the same Pod or a different UID from
/// a replaced Pod both prove that the old socket disappeared.
pub async fn recover_replica(
    client: &Client,
    ledger_namespace: &str,
    replica: &ServingReplica,
) -> Result<(), AccessLedgerError> {
    replica.validate()?;
    if !replica_is_live(client, replica).await? {
        return Err(AccessLedgerError::Invalid("serving replica Pod identity"));
    }
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let gates = api
        .list(&ListParams::default().labels(&format!("{LEDGER_KIND_LABEL}={GATE_KIND}")))
        .await?;
    for gate in gates {
        let sandbox_name = gate
            .labels()
            .get(LEASE_NAME_LABEL)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("lease gate name label"))?;
        let sandbox_uid = gate
            .labels()
            .get(LEASE_UID_LABEL)
            .cloned()
            .ok_or(AccessLedgerError::Invalid("lease gate UID label"))?;
        validate_gate(&gate, ledger_namespace, &sandbox_name, &sandbox_uid)?;
        let gate_uid = lease_uid(&gate)?.to_string();
        let entries: BTreeMap<String, GateEntry> = parse_entries(&gate)?;
        for (operation_id, entry) in entries {
            if !stale_for_current_replica(&entry.replica, replica) {
                continue;
            }
            let principal_name = principal_name(&entry.principal_hash);
            if let Some(principal) = api.get_opt(&principal_name).await? {
                let principal_uid = lease_uid(&principal)?.to_string();
                remove_principal_entry(
                    &api,
                    &principal_name,
                    &principal_uid,
                    &entry.principal_hash,
                    &operation_id,
                    &PrincipalEntry {
                        lease_uid: sandbox_uid.clone(),
                        gate_name: gate.name_any(),
                        replica: entry.replica.clone(),
                    },
                )
                .await?;
            }
            remove_gate_entry(
                &api,
                &gate.name_any(),
                &gate_uid,
                &sandbox_name,
                &sandbox_uid,
                &operation_id,
                &entry,
            )
            .await?;
        }
    }
    debug!(pod = %replica.pod_name, "recovered stale Sandbox access registrations");
    Ok(())
}

/// Retire operation entries only after the exact recorded Pod is absent or a
/// same-named replacement has a different UID.
///
/// This runs periodically because a rolling Deployment can start the new API
/// Pod while the old one is still live, then delete the old Pod without another
/// startup pass. Every mutation re-reads the exact ledger object and uses its
/// UID/resourceVersion plus the complete typed operation entry as CAS fences.
/// An unreadable or malformed Pod/principal/gate is retained for a later pass.
async fn reap_dead_replica_entries(
    client: &Client,
    api: &Api<Lease>,
    gate: &Lease,
    sandbox_name: &str,
    sandbox_uid: &str,
    entries: &BTreeMap<String, GateEntry>,
) {
    let Ok(gate_uid) = lease_uid(gate).map(str::to_string) else {
        return;
    };
    for (operation_id, entry) in entries {
        match replica_is_live(client, &entry.replica).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                warn!(
                    gate = %gate.name_any(),
                    operation = %operation_id,
                    pod = %entry.replica.pod_name,
                    %error,
                    "retaining Sandbox access entry because replica identity is unverifiable"
                );
                continue;
            }
        }

        let principal_name = principal_name(&entry.principal_hash);
        let principal = match api.get(&principal_name).await {
            Ok(principal) => Some(principal),
            Err(kube::Error::Api(response)) if response.code == 404 => None,
            Err(error) => {
                warn!(
                    gate = %gate.name_any(),
                    operation = %operation_id,
                    %error,
                    "retaining Sandbox access entry because its principal ledger is unreadable"
                );
                continue;
            }
        };
        if let Some(principal) = principal {
            let principal_uid = match lease_uid(&principal) {
                Ok(uid) => uid.to_string(),
                Err(error) => {
                    warn!(
                        gate = %gate.name_any(),
                        operation = %operation_id,
                        %error,
                        "retaining Sandbox access entry because its principal identity is malformed"
                    );
                    continue;
                }
            };
            if let Err(error) = remove_principal_entry(
                api,
                &principal_name,
                &principal_uid,
                &entry.principal_hash,
                operation_id,
                &PrincipalEntry {
                    lease_uid: sandbox_uid.to_string(),
                    gate_name: gate.name_any(),
                    replica: entry.replica.clone(),
                },
            )
            .await
            {
                warn!(
                    gate = %gate.name_any(),
                    operation = %operation_id,
                    %error,
                    "retaining Sandbox gate entry because principal cleanup is unverified"
                );
                continue;
            }
        }
        if let Err(error) = remove_gate_entry(
            api,
            &gate.name_any(),
            &gate_uid,
            sandbox_name,
            sandbox_uid,
            operation_id,
            entry,
        )
        .await
        {
            warn!(
                gate = %gate.name_any(),
                operation = %operation_id,
                %error,
                "could not retire a dead-replica Sandbox gate entry"
            );
        }
    }
}

/// Retire principal-ledger entries independently of their paired gate.
///
/// This second direction is required for a process crash with a principal
/// PATCH still in flight: the gate cleanup can linearize first and the late
/// principal commit can otherwise survive without any gate entry pointing to
/// it. The exact recorded Pod absence plus the full typed entry and object
/// UID/resourceVersion are the only removal authority.
async fn reap_dead_principal_entries(
    client: &Client,
    api: &Api<Lease>,
    principal: &Lease,
    principal_hash: &str,
    entries: &BTreeMap<String, PrincipalEntry>,
) {
    let Ok(principal_uid) = lease_uid(principal).map(str::to_string) else {
        return;
    };
    for (operation_id, entry) in entries {
        match replica_is_live(client, &entry.replica).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                warn!(
                    principal = %principal.name_any(),
                    operation = %operation_id,
                    pod = %entry.replica.pod_name,
                    %error,
                    "retaining Sandbox principal entry because replica identity is unverifiable"
                );
                continue;
            }
        }
        if let Err(error) = remove_principal_entry(
            api,
            &principal.name_any(),
            &principal_uid,
            principal_hash,
            operation_id,
            entry,
        )
        .await
        {
            warn!(
                principal = %principal.name_any(),
                operation = %operation_id,
                %error,
                "could not retire a dead-replica Sandbox principal entry"
            );
        }
    }
}

/// Retire dead-replica entries and delete empty access ledgers only after their
/// authority object is gone.
pub async fn reap_empty(
    client: &Client,
    sandbox_namespace: &str,
    ledger_namespace: &str,
) -> Result<(), AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let sandboxes: Api<SandboxLease> = Api::namespaced(client.clone(), sandbox_namespace);
    let objects = api.list(&ListParams::default()).await?;
    // A gate's immutable name commits to the parent UID, but its parent-name
    // label is mutable. Never use that label's GET/404 as orphan proof: a
    // damaged label could point away from a live parent. One unfiltered,
    // unpaginated snapshot lets every gate candidate correlate by immutable
    // parent UID while principal-only sweeps avoid the extra request.
    let sandbox_snapshot = if objects
        .iter()
        .any(|object| object.labels().get(LEDGER_KIND_LABEL).map(String::as_str) == Some(GATE_KIND))
    {
        Some(sandboxes.list(&ListParams::default()).await?)
    } else {
        None
    };
    let sandbox_snapshot_complete = sandbox_snapshot.as_ref().is_none_or(|snapshot| {
        snapshot
            .metadata
            .continue_
            .as_deref()
            .unwrap_or_default()
            .is_empty()
            && snapshot
                .metadata
                .resource_version
                .as_deref()
                .is_some_and(|resource_version| !resource_version.is_empty())
            && snapshot.iter().all(|lease| {
                lease.namespace().as_deref() == Some(sandbox_namespace)
                    && lease.uid().is_some_and(|uid| !uid.is_empty())
                    && !lease.name_any().is_empty()
            })
    });
    // A strict gate entry owns cleanup ordering for its paired principal entry:
    // principal first, gate second. Sweep only unpaired principal entries in
    // their own pass so one stale LIST snapshot cannot attempt the same entry
    // twice after its first CAS succeeds.
    let mut paired_principal_entries = BTreeSet::new();
    for gate in &objects {
        if gate.labels().get(LEDGER_KIND_LABEL).map(String::as_str) != Some(GATE_KIND) {
            continue;
        }
        let Some(sandbox_name) = gate.labels().get(LEASE_NAME_LABEL) else {
            continue;
        };
        let Some(sandbox_uid) = gate.labels().get(LEASE_UID_LABEL) else {
            continue;
        };
        if validate_gate(gate, ledger_namespace, sandbox_name, sandbox_uid).is_err() {
            continue;
        }
        let Ok(entries) = parse_entries::<GateEntry>(gate) else {
            continue;
        };
        paired_principal_entries.extend(
            entries
                .into_iter()
                .map(|(operation_id, entry)| (principal_name(&entry.principal_hash), operation_id)),
        );
    }
    for object in objects {
        let kind = object.labels().get(LEDGER_KIND_LABEL).map(String::as_str);
        let removable = match kind {
            Some(PRINCIPAL_KIND) => {
                let Some(principal_hash) = object.annotations().get(PRINCIPAL_ANNOTATION) else {
                    warn!(object = %object.name_any(), "ignoring malformed Sandbox principal ledger during reap");
                    continue;
                };
                if let Err(error) = validate_principal(&object, ledger_namespace, principal_hash)
                    .and_then(|()| lease_uid(&object).map(|_| ()))
                    .and_then(|()| lease_rv(&object).map(|_| ()))
                {
                    warn!(object = %object.name_any(), %error, "ignoring malformed Sandbox principal ledger during reap");
                    continue;
                }
                match parse_entries::<PrincipalEntry>(&object) {
                    Ok(entries) if entries.is_empty() => true,
                    Ok(entries) => {
                        let principal_name = object.name_any();
                        let unpaired: BTreeMap<_, _> = entries
                            .into_iter()
                            .filter(|(operation_id, _)| {
                                !paired_principal_entries
                                    .contains(&(principal_name.clone(), operation_id.clone()))
                            })
                            .collect();
                        reap_dead_principal_entries(
                            client,
                            &api,
                            &object,
                            principal_hash,
                            &unpaired,
                        )
                        .await;
                        // Re-list after any cleanup attempt before deleting the
                        // ledger object under a now-stale resourceVersion.
                        false
                    }
                    Err(error) => {
                        warn!(object = %object.name_any(), %error, "ignoring malformed Sandbox principal entries during reap");
                        continue;
                    }
                }
            }
            Some(GATE_KIND) => {
                let Some(name) = object.labels().get(LEASE_NAME_LABEL).cloned() else {
                    warn!(object = %object.name_any(), "ignoring malformed Sandbox lease gate during reap");
                    continue;
                };
                let Some(expected_uid) = object.labels().get(LEASE_UID_LABEL).cloned() else {
                    warn!(object = %object.name_any(), "ignoring malformed Sandbox lease gate during reap");
                    continue;
                };
                if let Err(error) = validate_gate(&object, ledger_namespace, &name, &expected_uid)
                    .and_then(|()| lease_uid(&object).map(|_| ()))
                    .and_then(|()| lease_rv(&object).map(|_| ()))
                {
                    warn!(object = %object.name_any(), %error, "ignoring malformed Sandbox lease gate during reap");
                    continue;
                }
                let entries = match parse_entries::<GateEntry>(&object) {
                    Ok(entries) => entries,
                    Err(error) => {
                        warn!(object = %object.name_any(), %error, "ignoring malformed Sandbox lease-gate entries during reap");
                        continue;
                    }
                };
                if !entries.is_empty() {
                    reap_dead_replica_entries(
                        client,
                        &api,
                        &object,
                        &name,
                        &expected_uid,
                        &entries,
                    )
                    .await;
                    // Any successful cleanup changed resourceVersion; any
                    // retained entry still owns the gate. Re-list before ever
                    // considering object deletion.
                    false
                } else if !parse_execution_entries(&object)?.is_empty() {
                    // Durable executions share the exact gate. The gate name
                    // remains occupied until their manifest has been drained.
                    false
                } else {
                    if !sandbox_snapshot_complete {
                        warn!(object = %object.name_any(), "retaining empty Sandbox lease gate because the parent ledger snapshot is incomplete");
                        continue;
                    }
                    let Some(snapshot) = sandbox_snapshot.as_ref() else {
                        warn!(object = %object.name_any(), "retaining empty Sandbox lease gate without a parent ledger snapshot");
                        continue;
                    };
                    let mut matching = snapshot
                        .iter()
                        .filter(|lease| lease.uid().as_deref() == Some(expected_uid.as_str()));
                    let parent = matching.next();
                    if matching.next().is_some() {
                        warn!(object = %object.name_any(), "retaining empty Sandbox lease gate because the parent UID is not unique");
                        continue;
                    }
                    match parent {
                        Some(lease) if lease.name_any() != name => {
                            warn!(object = %object.name_any(), parent = %lease.name_any(), "retaining Sandbox lease gate with mutated parent-name provenance");
                            continue;
                        }
                        Some(lease) => clean_terminal_lease(lease),
                        None => true,
                    }
                }
            }
            _ => false,
        };
        if !removable {
            continue;
        }
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(lease_uid(&object)?.to_string()),
                resource_version: Some(lease_rv(&object)?.to_string()),
            }),
            ..DeleteParams::default()
        };
        match api.delete(&object.name_any(), &params).await {
            Ok(_) => {}
            Err(kube::Error::Api(response)) if response.code == 404 || response.code == 409 => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn clean_terminal_lease(lease: &SandboxLease) -> bool {
    let Some(status) = lease.status.as_ref() else {
        return false;
    };
    matches!(
        status.phase,
        SandboxLeasePhase::Released | SandboxLeasePhase::Expired
    ) && ["FootprintAbsent", "CleanupVerified"]
        .iter()
        .all(|expected| {
            status.conditions.iter().any(|condition| {
                condition.condition_type == *expected
                    && condition.status == SandboxConditionStatus::True
            })
        })
}

/// Whether startup can prove an operation belongs to a dead predecessor of
/// this serving slot. Once the current Pod name resolves to `current.pod_uid`,
/// Kubernetes name uniqueness proves both an older boot in the same Pod and a
/// same-named Pod with an older UID can no longer own a live connection.
fn stale_for_current_replica(entry: &ServingReplica, current: &ServingReplica) -> bool {
    entry.namespace == current.namespace
        && entry.pod_name == current.pod_name
        && (entry.pod_uid != current.pod_uid || entry.boot_id != current.boot_id)
}

/// Periodically retire empty gate/principal records after their authority is
/// gone. The task is critical: silently stopping it would eventually exhaust
/// the protected namespace's ResourceQuota and deny every new Sandbox.
pub async fn run_reaper(
    client: Client,
    sandbox_namespace: String,
    ledger_namespace: String,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = reap_empty(&client, &sandbox_namespace, &ledger_namespace).await {
                    warn!(error = %error, "could not reap empty Sandbox access ledgers");
                }
            }
            _ = shutdown.cancelled() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    fn k8s_error(code: u16) -> ResponseTemplate {
        let reason = match code {
            404 => "NotFound",
            409 => "Conflict",
            _ => "InternalError",
        };
        ResponseTemplate::new(code).set_body_json(json!({
            "apiVersion":"v1", "kind":"Status", "status":"Failure",
            "reason":reason, "message":reason, "code":code
        }))
    }

    fn lease_object(
        name: &str,
        uid: &str,
        resource_version: &str,
        labels: BTreeMap<String, String>,
        mut annotations: BTreeMap<String, String>,
    ) -> Value {
        if labels.get(LEDGER_KIND_LABEL).map(String::as_str) == Some(GATE_KIND) {
            annotations
                .entry(EXECUTIONS_ANNOTATION.into())
                .or_insert_with(|| "{}".into());
        }
        json!({
            "apiVersion":"coordination.k8s.io/v1", "kind":"Lease",
            "metadata":{
                "name":name, "namespace":"ledger", "uid":uid,
                "resourceVersion":resource_version,
                "labels":labels, "annotations":annotations
            },
            "spec":{}
        })
    }

    fn sandbox_lease() -> SandboxLease {
        serde_json::from_value(json!({
            "apiVersion":"kobe.kunobi.ninja/v1alpha1", "kind":"SandboxLease",
            "metadata":{
                "name":"sandbox-a","namespace":"kobe-system","uid":"sandbox-uid",
                "annotations":{
                    ACCESS_GATE_ANNOTATION: serde_json::to_string(&AccessGateReference {
                        name: gate_name("sandbox-uid"), uid: "gate-uid".into()
                    }).unwrap()
                }
            },
            "spec":{
                "poolRef":{"name":"pool","uid":"pool-uid","generation":1},
                "ttl":"1m",
                "requester":{"provider":"test","type":"oidc:user","issuer":"https://issuer.invalid","identity":"alice"}
            }
        }))
        .unwrap()
    }

    fn gate_path(lease_uid: &str) -> String {
        format!(
            "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{}",
            gate_name(lease_uid)
        )
    }

    /// One unbound Creating tombstone, as the reaper observes it through
    /// [`execution_manifest`], with an optional recorded writer.
    fn manifest_entry_with_writer(writer: Option<&ServingReplica>) -> ExecutionManifestEntry {
        ExecutionManifestEntry {
            name: "execution-a".into(),
            request_digest: "d".repeat(64),
            pod_uid: "pod-uid".into(),
            reserved_at: "2026-08-20T00:00:00Z".into(),
            execution_uid: None,
            creation_state: ExecutionCreationState::Creating,
            active: true,
            writer: writer.cloned(),
        }
    }

    fn gate_with_creating_entry(writer: Option<&ServingReplica>) -> Value {
        let entry = ExecutionEntry {
            request_digest: "d".repeat(64),
            pod_uid: "pod-uid".into(),
            reserved_at: "2026-08-20T00:00:00Z".into(),
            execution_uid: None,
            creation_state: ExecutionCreationState::Creating,
            active: true,
            writer: writer.cloned(),
        };
        let existing = BTreeMap::from([("execution-a".to_string(), entry)]);
        lease_object(
            &gate_name("sandbox-uid"),
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
                (
                    EXECUTIONS_ANNOTATION.into(),
                    serde_json::to_string(&existing).unwrap(),
                ),
            ]),
        )
    }

    fn test_registration(replica: &ServingReplica) -> ReleaseRegistration {
        ReleaseRegistration {
            sandbox_name: "sandbox-a".into(),
            sandbox_uid: "sandbox-uid".into(),
            gate_name: gate_name("sandbox-uid"),
            expected_gate_uid: "gate-uid".into(),
            gate_uid: None,
            principal_name: principal_name("principal-hash"),
            principal_uid: None,
            principal_hash: "principal-hash".into(),
            operation_id: "new-operation".into(),
            replica: replica.clone(),
        }
    }

    fn ledgers_with_one_operation(replica: &ServingReplica) -> (String, String, Value, Value) {
        let gate_name = gate_name("sandbox-uid");
        let principal_name = principal_name("principal-hash");
        let operation_id = "operation-1";
        let gate_entries = BTreeMap::from([(
            operation_id.to_string(),
            GateEntry {
                principal_hash: "principal-hash".into(),
                replica: replica.clone(),
            },
        )]);
        let principal_entries = BTreeMap::from([(
            operation_id.to_string(),
            PrincipalEntry {
                lease_uid: "sandbox-uid".into(),
                gate_name: gate_name.clone(),
                replica: replica.clone(),
            },
        )]);
        let gate = lease_object(
            &gate_name,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&gate_entries).unwrap(),
                ),
            ]),
        );
        let principal = lease_object(
            &principal_name,
            "principal-uid",
            "1",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&principal_entries).unwrap(),
                ),
            ]),
        );
        (gate_name, principal_name, gate, principal)
    }

    async fn mount_reaper_snapshots(server: &MockServer, gate: &Value, principal: &Value) {
        Mock::given(method("GET"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"2"},
                "items":[gate.clone(), principal.clone()]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxLeaseList",
                "metadata":{"resourceVersion":"2"},
                "items":[sandbox_lease()]
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[derive(Clone)]
    struct PatchedLease {
        object: Value,
    }

    impl Respond for PatchedLease {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let patch: Value = serde_json::from_slice(&request.body).expect("JSON Patch body");
            let entries = patch
                .as_array()
                .and_then(|operations| operations.last())
                .and_then(|operation| operation.get("value"))
                .and_then(Value::as_str)
                .expect("last operation replaces entries");
            let mut object = self.object.clone();
            object["metadata"]["resourceVersion"] = json!("2");
            object["metadata"]["annotations"][ENTRIES_ANNOTATION] = json!(entries);
            ResponseTemplate::new(200).set_body_json(object)
        }
    }

    #[derive(Clone)]
    struct AmbiguousGateLedger {
        object: Value,
        state: Arc<std::sync::Mutex<(String, u64)>>,
        acquisition_patch_seen: Arc<tokio::sync::Notify>,
    }

    impl Respond for AmbiguousGateLedger {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let mut state = self.state.lock().unwrap();
            let mut object = self.object.clone();
            match request.method.as_str() {
                "GET" => {
                    object["metadata"]["resourceVersion"] = json!(state.1.to_string());
                    object["metadata"]["annotations"][ENTRIES_ANNOTATION] = json!(state.0.clone());
                    ResponseTemplate::new(200).set_body_json(object)
                }
                "PATCH" => {
                    let patch: Value = serde_json::from_slice(&request.body).unwrap();
                    let current_resource_version = state.1.to_string();
                    if patch[0]["value"] != object["metadata"]["uid"]
                        || patch[1]["value"].as_str() != Some(current_resource_version.as_str())
                        || patch[2]["value"] != state.0
                    {
                        return k8s_error(409);
                    }
                    let next = patch[3]["value"].as_str().unwrap().to_string();
                    let is_acquisition = next != "{}";
                    state.0 = next;
                    state.1 += 1;
                    object["metadata"]["resourceVersion"] = json!(state.1.to_string());
                    object["metadata"]["annotations"][ENTRIES_ANNOTATION] = json!(state.0.clone());
                    drop(state);
                    let response = ResponseTemplate::new(200).set_body_json(object);
                    if is_acquisition {
                        self.acquisition_patch_seen.notify_one();
                        response.set_delay(std::time::Duration::from_millis(500))
                    } else {
                        response
                    }
                }
                _ => ResponseTemplate::new(405),
            }
        }
    }

    #[derive(Clone)]
    struct PatchedExecutionLease {
        object: Value,
    }

    impl Respond for PatchedExecutionLease {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let patch: Value = serde_json::from_slice(&request.body).expect("JSON Patch body");
            let executions = patch
                .as_array()
                .and_then(|operations| operations.last())
                .and_then(|operation| operation.get("value"))
                .and_then(Value::as_str)
                .expect("last operation replaces execution entries");
            let mut object = self.object.clone();
            object["metadata"]["resourceVersion"] = json!("2");
            object["metadata"]["annotations"][EXECUTIONS_ANNOTATION] = json!(executions);
            ResponseTemplate::new(200).set_body_json(object)
        }
    }

    #[test]
    fn names_are_dns_bounded_and_identity_derived() {
        let gate = gate_name("12345678-1234-1234-1234-123456789012");
        let principal = principal_name(&"f".repeat(64));
        assert!(gate.len() <= 63);
        assert!(principal.len() <= 63);
        assert_ne!(gate, gate_name("other"));
        assert_ne!(principal, principal_name(&"e".repeat(64)));
    }

    #[test]
    fn replica_identity_is_complete() {
        let valid = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };
        assert!(valid.validate().is_ok());
        let mut invalid = valid;
        invalid.pod_uid.clear();
        assert!(invalid.validate().is_err());
    }

    /// Lifetime and concurrent execution limits are one mutation of the same
    /// map, so racing replicas cannot each observe a spare slot. Exact retries
    /// reuse their entry; changed content under the same derived name cannot.
    #[test]
    fn execution_capacity_is_bounded_by_history_and_active_processes() {
        let digest = "d".repeat(64);
        let mut entries = BTreeMap::new();
        assert_eq!(
            reserve_execution_entry(
                &mut entries,
                "execution-0",
                &digest,
                "pod-uid",
                "2026-08-20T00:00:00Z",
                None,
            ),
            ExecutionCapacity::Reserved
        );
        assert_eq!(
            reserve_execution_entry(
                &mut entries,
                "execution-0",
                &digest,
                "pod-uid",
                "2026-08-20T00:01:00Z",
                None,
            ),
            ExecutionCapacity::ExistingActive {
                execution_uid: None
            }
        );
        assert_eq!(entries.len(), 1, "an exact retry spends no second slot");
        assert_eq!(
            reserve_execution_entry(
                &mut entries,
                "execution-0",
                &"e".repeat(64),
                "pod-uid",
                "2026-08-20T00:01:00Z",
                None,
            ),
            ExecutionCapacity::Conflict
        );

        for index in 1..crate::api::sandbox_executions::MAX_ACTIVE_EXECUTIONS_PER_LEASE {
            assert_eq!(
                reserve_execution_entry(
                    &mut entries,
                    &format!("execution-{index}"),
                    &digest,
                    "pod-uid",
                    "2026-08-20T00:00:00Z",
                    None,
                ),
                ExecutionCapacity::Reserved
            );
        }
        // The started-execution bound must never be the binding lifetime
        // budget: an execution that crossed startedAt holds its slot until the
        // exact target is destroyed, so any gap between the two bounds would
        // silently shrink a lease's lifetime budget to this one.
        assert_eq!(
            crate::api::sandbox_executions::MAX_ACTIVE_EXECUTIONS_PER_LEASE,
            crate::api::sandbox_executions::MAX_EXECUTIONS_PER_LEASE
        );
        assert_eq!(
            reserve_execution_entry(
                &mut entries,
                "execution-overflow",
                &digest,
                "pod-uid",
                "2026-08-20T00:00:00Z",
                None,
            ),
            ExecutionCapacity::LimitReached
        );

        for entry in entries.values_mut() {
            entry.active = false;
        }
        assert_eq!(
            entries.len(),
            crate::api::sandbox_executions::MAX_EXECUTIONS_PER_LEASE
        );
        assert_eq!(
            reserve_execution_entry(
                &mut entries,
                "execution-lifetime-overflow",
                &digest,
                "pod-uid",
                "2026-08-20T00:00:00Z",
                None,
            ),
            ExecutionCapacity::LimitReached,
            "freeing concurrency cannot bypass the lifetime history bound"
        );
    }

    /// A runner verdict is tenant-controlled evidence, not proof that a process
    /// group is gone. Every command that reached Running holds its active slot
    /// until destruction of the exact target supplies that proof.
    #[test]
    fn unknown_running_execution_keeps_its_active_capacity() {
        use crate::crd::ExecutionState;

        assert!(!execution_can_release_active_capacity(
            ExecutionState::Running,
            true,
            true
        ));
        assert!(!execution_can_release_active_capacity(
            ExecutionState::Unknown,
            true,
            false
        ));
        assert!(execution_can_release_active_capacity(
            ExecutionState::Unknown,
            true,
            true
        ));
        assert!(execution_can_release_active_capacity(
            ExecutionState::Unknown,
            false,
            false
        ));
        for settled in [
            ExecutionState::Succeeded,
            ExecutionState::Failed,
            ExecutionState::Cancelled,
            ExecutionState::TimedOut,
        ] {
            assert!(!execution_can_release_active_capacity(settled, true, false));
            assert!(execution_can_release_active_capacity(settled, true, true));
        }
    }

    /// Reserving capacity is one UID/resourceVersion/previous-value CAS. A
    /// second replica cannot reserve from the same snapshot after the first
    /// wins, which is what makes the pure numerical bounds real under load.
    #[tokio::test]
    async fn execution_capacity_reservation_is_exactly_cas_fenced() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let gate = gate_name("sandbox-uid");
        let gate_path = format!("/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}");
        let object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
                (EXECUTIONS_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(object.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&gate_path))
            .respond_with(PatchedExecutionLease { object })
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            reserve_execution_capacity(
                &client,
                "ledger",
                &sandbox_lease(),
                "execution-a",
                &"d".repeat(64),
                "pod-uid",
                None,
            )
            .await
            .unwrap(),
            ExecutionCapacity::Reserved
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("capacity CAS");
        let patch: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            patch[0],
            json!({"op":"test","path":"/metadata/uid","value":"gate-uid"})
        );
        assert_eq!(
            patch[1],
            json!({"op":"test","path":"/metadata/resourceVersion","value":"1"})
        );
        assert_eq!(
            patch[2],
            json!({
                "op":"test",
                "path":"/metadata/annotations/kobe.kunobi.ninja~1sandbox-executions",
                "value":"{}"
            })
        );
        let entries: BTreeMap<String, ExecutionEntry> =
            serde_json::from_str(patch[3]["value"].as_str().unwrap()).unwrap();
        assert!(entries["execution-a"].active);
        assert_eq!(entries["execution-a"].execution_uid, None);
    }

    /// Closing an unbound slot and adopting a late exact CR is one CAS. A
    /// concurrent binder either wins first or sees the inactive entry; there
    /// is no state in which both the reaper and a new process can proceed.
    #[tokio::test]
    async fn late_execution_record_is_adopted_only_while_closing_its_slot() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let gate = gate_name("sandbox-uid");
        let gate_path = format!("/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}");
        let existing = BTreeMap::from([(
            "execution-a".to_string(),
            ExecutionEntry {
                request_digest: "d".repeat(64),
                pod_uid: "pod-uid".into(),
                reserved_at: "2026-08-20T00:00:00Z".into(),
                execution_uid: None,
                creation_state: ExecutionCreationState::Creating,
                active: true,
                writer: None,
            },
        )]);
        let object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), CLOSED.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
                (
                    EXECUTIONS_ANNOTATION.into(),
                    serde_json::to_string(&existing).unwrap(),
                ),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(object.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&gate_path))
            .respond_with(PatchedExecutionLease { object })
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            expire_unbound_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                "execution-a",
                &"d".repeat(64),
                "pod-uid",
                Some("execution-uid"),
            )
            .await
            .unwrap()
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("unbound retirement CAS");
        let patch: Value = serde_json::from_slice(&request.body).unwrap();
        let entries: BTreeMap<String, ExecutionEntry> =
            serde_json::from_str(patch[3]["value"].as_str().unwrap()).unwrap();
        assert!(!entries["execution-a"].active);
        assert_eq!(
            entries["execution-a"].execution_uid.as_deref(),
            Some("execution-uid")
        );
    }

    /// A 404 observation cannot retire a CREATE request that may still land.
    #[tokio::test]
    async fn missing_execution_keeps_its_creating_tombstone_and_active_slot() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let gate = gate_name("sandbox-uid");
        let gate_path = format!("/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}");
        let existing = BTreeMap::from([(
            "execution-a".to_string(),
            ExecutionEntry {
                request_digest: "d".repeat(64),
                pod_uid: "pod-uid".into(),
                reserved_at: "2026-08-20T00:00:00Z".into(),
                execution_uid: None,
                creation_state: ExecutionCreationState::Creating,
                active: true,
                writer: None,
            },
        )]);
        let object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), CLOSED.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
                (
                    EXECUTIONS_ANNOTATION.into(),
                    serde_json::to_string(&existing).unwrap(),
                ),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(object))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !expire_unbound_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                "execution-a",
                &"d".repeat(64),
                "pod-uid",
                None,
            )
            .await
            .unwrap(),
            "absence is not a terminal CREATE receipt"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH"),
            "404 recovery must not free or rewrite the tombstone"
        );
    }

    /// A Creating tombstone whose recorded writer is provably gone — this
    /// replica wears the same Pod name with a different boot — resolves to
    /// Rejected with its active slot released, the same durable shape as a
    /// definitive API rejection, so teardown's ordinary retirement takes over.
    #[tokio::test]
    async fn orphaned_creating_tombstone_is_retired_once_its_writer_is_gone() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let stale_boot_replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-1".into(),
        };
        let current = ServingReplica {
            boot_id: "boot-2".into(),
            ..stale_boot_replica.clone()
        };
        let expected = manifest_entry_with_writer(Some(&stale_boot_replica));
        let object = gate_with_creating_entry(expected.writer.as_ref());

        Mock::given(method("GET"))
            .and(path(gate_path("sandbox-uid")))
            .respond_with(ResponseTemplate::new(200).set_body_json(object.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(gate_path("sandbox-uid")))
            .respond_with(PatchedExecutionLease { object })
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            expire_orphaned_creating_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                &expected,
                &current,
            )
            .await
            .unwrap()
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("tombstone retirement CAS");
        let patch: Value = serde_json::from_slice(&request.body).unwrap();
        let entries: BTreeMap<String, ExecutionEntry> =
            serde_json::from_str(patch[3]["value"].as_str().unwrap()).unwrap();
        assert_eq!(
            entries["execution-a"].creation_state,
            ExecutionCreationState::Rejected
        );
        assert!(!entries["execution-a"].active);
        assert_eq!(entries["execution-a"].execution_uid, None);
        assert_eq!(
            entries["execution-a"].writer.as_ref(),
            Some(&stale_boot_replica)
        );
    }

    /// A live writer keeps its tombstone. This replica IS the writer, so the
    /// CREATE may be in flight right now and the resolve task still owns bind
    /// and spawn authority.
    #[tokio::test]
    async fn creating_tombstone_of_a_live_writer_is_never_retired() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let current = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-1".into(),
        };
        let expected = manifest_entry_with_writer(Some(&current));
        Mock::given(method("GET"))
            .and(path(gate_path("sandbox-uid")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(gate_with_creating_entry(Some(&current))),
            )
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !expire_orphaned_creating_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                &expected,
                &current,
            )
            .await
            .unwrap()
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method.as_str() == "PATCH")
        );
    }

    /// Only the writer's own successor boot may judge a tombstone orphaned. A
    /// different Pod cannot prove anything about a process it never was, so it
    /// refuses even when both Pods happen to serve simultaneously.
    #[tokio::test]
    async fn creating_tombstone_on_a_foreign_pod_is_never_retired_here() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let writer = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-1".into(),
        };
        let foreign = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-1".into(),
            pod_uid: "other-pod-uid".into(),
            boot_id: "boot-9".into(),
        };
        let expected = manifest_entry_with_writer(Some(&writer));
        Mock::given(method("GET"))
            .and(path(gate_path("sandbox-uid")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(gate_with_creating_entry(Some(&writer))),
            )
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !expire_orphaned_creating_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                &expected,
                &foreign,
            )
            .await
            .unwrap()
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method.as_str() == "PATCH")
        );
    }

    /// Rows predating the writer fence have no provable owner. They stay
    /// fail-closed exactly like before the fence existed rather than being
    /// retired on a guess.
    #[tokio::test]
    async fn legacy_creating_tombstone_without_a_writer_is_never_retired() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let current = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-2".into(),
        };
        let expected = manifest_entry_with_writer(None);
        Mock::given(method("GET"))
            .and(path(gate_path("sandbox-uid")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_with_creating_entry(None)))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !expire_orphaned_creating_execution(
                &client,
                "ledger",
                &sandbox_lease(),
                &expected,
                &current,
            )
            .await
            .unwrap()
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method.as_str() == "PATCH")
        );
    }

    /// Teardown must remove each durable manifest row, not merely mark it
    /// inactive. Otherwise the next pass sees a missing bound record and
    /// quarantines, while an unbound inactive row loops forever.
    #[tokio::test]
    async fn teardown_retires_each_execution_manifest_row() {
        async fn assert_row_removed(execution_uid: Option<&str>) {
            let server = MockServer::start().await;
            let client = mock_client(&server);
            let gate = gate_name("sandbox-uid");
            let gate_path = format!("/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}");
            let entry = ExecutionEntry {
                request_digest: "d".repeat(64),
                pod_uid: "pod-uid".into(),
                reserved_at: "2026-08-20T00:00:00Z".into(),
                execution_uid: execution_uid.map(str::to_string),
                creation_state: if execution_uid.is_some() {
                    ExecutionCreationState::Bound
                } else {
                    ExecutionCreationState::Rejected
                },
                active: false,
                writer: None,
            };
            let existing = BTreeMap::from([("execution-a".to_string(), entry.clone())]);
            let object = lease_object(
                &gate,
                "gate-uid",
                "1",
                BTreeMap::from([
                    (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                    (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                    (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
                ]),
                BTreeMap::from([
                    (STATE_ANNOTATION.into(), CLOSED.into()),
                    (ENTRIES_ANNOTATION.into(), "{}".into()),
                    (
                        EXECUTIONS_ANNOTATION.into(),
                        serde_json::to_string(&existing).unwrap(),
                    ),
                ]),
            );
            Mock::given(method("GET"))
                .and(path(&gate_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(object.clone()))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("PATCH"))
                .and(path(&gate_path))
                .respond_with(PatchedExecutionLease { object })
                .expect(1)
                .mount(&server)
                .await;

            if let Some(execution_uid) = execution_uid {
                assert!(
                    retire_inactive_execution(
                        &client,
                        "ledger",
                        &sandbox_lease(),
                        &ExecutionManifestEntry {
                            name: "execution-a".into(),
                            request_digest: entry.request_digest,
                            pod_uid: entry.pod_uid,
                            reserved_at: entry.reserved_at,
                            execution_uid: Some(execution_uid.into()),
                            creation_state: ExecutionCreationState::Bound,
                            active: false,
                            writer: None,
                        },
                    )
                    .await
                    .unwrap()
                );
            } else {
                retire_rejected_execution(
                    &client,
                    "ledger",
                    &sandbox_lease(),
                    &ExecutionManifestEntry {
                        name: "execution-a".into(),
                        request_digest: entry.request_digest,
                        pod_uid: entry.pod_uid,
                        reserved_at: entry.reserved_at,
                        execution_uid: None,
                        creation_state: ExecutionCreationState::Rejected,
                        active: false,
                        writer: None,
                    },
                )
                .await
                .unwrap();
            }

            let request = server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|request| request.method.as_str() == "PATCH")
                .expect("manifest retirement CAS");
            let patch: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(patch[0]["value"], "gate-uid");
            assert_eq!(patch[1]["value"], "1");
            assert_eq!(patch[3]["value"], "{}");
        }

        assert_row_removed(None).await;
        assert_row_removed(Some("execution-uid")).await;
    }

    #[test]
    fn startup_recovers_old_boots_and_same_named_pod_replacements_only() {
        let current = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "new-pod-uid".into(),
            boot_id: "new-boot-id".into(),
        };
        assert!(stale_for_current_replica(
            &ServingReplica {
                boot_id: "old-boot-id".into(),
                ..current.clone()
            },
            &current
        ));
        assert!(stale_for_current_replica(
            &ServingReplica {
                pod_uid: "old-pod-uid".into(),
                boot_id: "old-pod-boot-id".into(),
                ..current.clone()
            },
            &current
        ));
        assert!(!stale_for_current_replica(&current, &current));
        assert!(!stale_for_current_replica(
            &ServingReplica {
                pod_name: "kobe-1".into(),
                pod_uid: "other-pod-uid".into(),
                boot_id: "other-boot-id".into(),
                ..current.clone()
            },
            &current
        ));
    }

    #[test]
    fn gate_and_principal_objects_start_empty() {
        let gate = build_gate("ledger", "sandbox-a", "uid-a", OPEN);
        validate_gate(&gate, "ledger", "sandbox-a", "uid-a").unwrap();
        assert_eq!(parse_entries::<GateEntry>(&gate).unwrap(), BTreeMap::new());
        assert_eq!(parse_execution_entries(&gate).unwrap(), BTreeMap::new());
        let principal = build_principal("ledger", "principal");
        assert_eq!(
            parse_entries::<PrincipalEntry>(&principal).unwrap(),
            BTreeMap::new()
        );
    }

    #[test]
    fn only_a_fully_proven_clean_terminal_lease_releases_its_gate_object() {
        let mut lease = sandbox_lease();
        let mut status = crate::crd::SandboxLeaseStatus {
            phase: SandboxLeasePhase::Released,
            ..Default::default()
        };
        lease.status = Some(status.clone());
        assert!(!clean_terminal_lease(&lease));

        for condition_type in ["FootprintAbsent", "CleanupVerified"] {
            status.conditions.push(crate::crd::SandboxCondition {
                condition_type: condition_type.into(),
                status: SandboxConditionStatus::True,
                ..Default::default()
            });
        }
        lease.status = Some(status);
        assert!(clean_terminal_lease(&lease));

        lease.status.as_mut().unwrap().phase = SandboxLeasePhase::Quarantined;
        assert!(!clean_terminal_lease(&lease));
    }

    #[tokio::test]
    async fn admission_prepares_the_empty_open_gate_before_capacity() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{name}")))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;
        let created = lease_object(
            &name,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("POST"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(201).set_body_json(created))
            .expect(1)
            .mount(&server)
            .await;

        prepare_open_gate(&client, "ledger", &sandbox_lease())
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let post: Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "POST")
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(post["metadata"]["annotations"][STATE_ANNOTATION], OPEN);
        assert_eq!(post["metadata"]["annotations"][ENTRIES_ANNOTATION], "{}");
        assert_eq!(post["metadata"]["annotations"][EXECUTIONS_ANNOTATION], "{}");
    }

    #[tokio::test]
    async fn teardown_never_allocates_a_missing_gate_under_quota_pressure() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{name}")))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            close_and_drain(&client, "ledger", &sandbox_lease()).await,
            Err(AccessLedgerError::Invalid("missing admitted lease gate"))
        ));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "POST")
        );
    }

    #[tokio::test]
    async fn same_named_gate_replacement_never_becomes_teardown_authority() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        let replacement = lease_object(
            &name,
            "replacement-gate-uid",
            "9",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            close_and_drain(&client, "ledger", &sandbox_lease()).await,
            Err(AccessLedgerError::Invalid("persisted access gate UID"))
        ));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }

    #[tokio::test]
    async fn same_named_gate_replacement_never_becomes_placement_authority() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        let replacement = lease_object(
            &name,
            "replacement-gate-uid",
            "9",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(replacement))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            verify_open_admitted_gate(&client, "ledger", &sandbox_lease()).await,
            Err(AccessLedgerError::Invalid("persisted access gate UID"))
        ));
    }

    #[tokio::test]
    async fn clean_terminal_parent_releases_the_empty_gate_before_record_retention() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        let gate = lease_object(
            &name,
            "gate-uid",
            "7",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), CLOSED.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"8"}, "items":[gate]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut parent = sandbox_lease();
        let conditions = ["FootprintAbsent", "CleanupVerified"]
            .into_iter()
            .map(|condition_type| crate::crd::SandboxCondition {
                condition_type: condition_type.into(),
                status: SandboxConditionStatus::True,
                ..Default::default()
            })
            .collect();
        parent.status = Some(crate::crd::SandboxLeaseStatus {
            phase: SandboxLeasePhase::Released,
            conditions,
            ..Default::default()
        });
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxLeaseList",
                "metadata":{"resourceVersion":"9"},
                "items":[parent]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("{collection}/{name}")))
            .and(body_partial_json(json!({
                "preconditions":{"uid":"gate-uid","resourceVersion":"7"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"v1", "kind":"Status", "status":"Success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();
    }

    /// The parent-name hint is mutable and therefore cannot establish orphan
    /// status. The immutable gate name still commits to the live parent UID;
    /// a full unfiltered snapshot must find it and retain the gate.
    #[tokio::test]
    async fn mutated_parent_name_cannot_hide_a_live_gate_from_the_reaper() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let gate_name = gate_name("sandbox-uid");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        let gate = lease_object(
            &gate_name,
            "gate-uid",
            "7",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "missing-parent".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"8"}, "items":[gate]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxLeaseList",
                "metadata":{"resourceVersion":"9"},
                "items":[sandbox_lease()]
            })))
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();

        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// A Deployment rollout can replace `kobe-old` with a differently named
    /// Pod. Once the old exact Pod is 404, its operation is dead even though
    /// the Sandbox gate remains open; both global ledgers must release only
    /// that exact typed entry under UID/resourceVersion CAS.
    #[tokio::test]
    async fn periodic_reaper_recovers_entries_from_a_differently_named_rollout_pod() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let old_replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-old".into(),
            pod_uid: "old-pod-uid".into(),
            boot_id: "old-boot-id".into(),
        };
        let (gate_name, principal_name, gate, principal) = ledgers_with_one_operation(&old_replica);
        mount_reaper_snapshots(&server, &gate, &principal).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-old"))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal.clone()))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(PatchedLease { object: principal })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{gate_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{gate_name}")))
            .respond_with(PatchedLease { object: gate })
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let patches: Vec<Value> = requests
            .iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect();
        assert_eq!(patches.len(), 2);
        assert!(patches.iter().all(|patch| {
            patch[0]["path"] == "/metadata/uid"
                && patch[1]["path"] == "/metadata/resourceVersion"
                && patch[3]["value"] == "{}"
        }));
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// A process can die with the principal PATCH still in flight after its
    /// gate entry has already been retired. The independent principal pass
    /// must recover that late orphan from exact Pod absence and typed CAS.
    #[tokio::test]
    async fn periodic_reaper_recovers_an_unpaired_late_principal_entry() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let old_replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-old".into(),
            pod_uid: "old-pod-uid".into(),
            boot_id: "old-boot-id".into(),
        };
        let (_, principal_name, _, principal) = ledgers_with_one_operation(&old_replica);
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"2"}, "items":[principal.clone()]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-old"))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(PatchedLease { object: principal })
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let patch: Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "PATCH")
                .expect("dead exact replica must release its principal entry")
                .body,
        )
        .unwrap();
        assert_eq!(patch[0]["value"], "principal-uid");
        assert_eq!(patch[1]["value"], "1");
        let previous: BTreeMap<String, PrincipalEntry> =
            serde_json::from_str(patch[2]["value"].as_str().unwrap()).unwrap();
        assert_eq!(previous.len(), 1);
        assert_eq!(previous.values().next().unwrap().replica, old_replica);
        assert_eq!(patch[3]["value"], "{}");
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    async fn assert_periodic_reaper_preserves_entry(pod_response: ResponseTemplate) {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-live".into(),
            pod_uid: "live-pod-uid".into(),
            boot_id: "live-boot-id".into(),
        };
        let (_, principal_name, gate, principal) = ledgers_with_one_operation(&replica);
        mount_reaper_snapshots(&server, &gate, &principal).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-live"))
            .respond_with(pod_response)
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method.as_str() != "PATCH" && request.method.as_str() != "DELETE"
        }));
        assert!(requests.iter().all(|request| {
            request.url.path()
                != format!("/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{principal_name}")
        }));
    }

    #[tokio::test]
    async fn periodic_reaper_preserves_entries_owned_by_a_live_exact_pod() {
        assert_periodic_reaper_preserves_entry(ResponseTemplate::new(200).set_body_json(json!({
            "apiVersion":"v1", "kind":"Pod",
            "metadata":{
                "name":"kobe-live", "namespace":"kobe-system", "uid":"live-pod-uid"
            },
            "spec":{"containers":[]}
        })))
        .await;
    }

    /// A transient GET failure and a 200 response without exact UID identity
    /// are both uncertainty, never absence. Neither may free a global limit.
    #[tokio::test]
    async fn periodic_reaper_fails_closed_on_replica_observation_uncertainty() {
        assert_periodic_reaper_preserves_entry(k8s_error(500)).await;
        assert_periodic_reaper_preserves_entry(ResponseTemplate::new(200).set_body_json(json!({
            "apiVersion":"v1", "kind":"Pod",
            "metadata":{"name":"kobe-live", "namespace":"kobe-system"},
            "spec":{"containers":[]}
        })))
        .await;
    }

    /// Every field on an admission token except its name is mutable. Even when
    /// all of those hints are rewritten to imitate either access-ledger kind,
    /// the reaper must not free live admission capacity. Malformed objects also
    /// must not stop a later canonical empty ledger from being reclaimed.
    #[tokio::test]
    async fn reaper_skips_a_disguised_admission_token_and_continues() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";

        let disguised_token = lease_object(
            "sbx-quota-live-principal-0",
            "quota-token-uid",
            "11",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "forged-principal".into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        let disguised_gate_token = lease_object(
            "sbx-alias-live-principal-demo",
            "alias-token-uid",
            "12",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "absent-parent".into()),
                (LEASE_UID_LABEL.into(), "forged-parent-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        let canonical_name = principal_name("idle-principal");
        let canonical_principal = lease_object(
            &canonical_name,
            "principal-uid",
            "13",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "idle-principal".into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"14"},
                "items":[disguised_token, disguised_gate_token, canonical_principal]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxLeaseList",
                "metadata":{"resourceVersion":"15"}, "items":[]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("{collection}/{canonical_name}")))
            .and(body_partial_json(json!({
                "preconditions":{"uid":"principal-uid","resourceVersion":"13"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"v1", "kind":"Status", "status":"Success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        reap_empty(&client, "kobe-system", "ledger").await.unwrap();

        let deletes: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            deletes[0].url.path(),
            format!("{collection}/{canonical_name}")
        );
    }

    #[tokio::test]
    async fn acquisition_uses_uid_rv_cas_for_both_global_limits() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let gate = gate_name("sandbox-uid");
        let principal = principal_name("principal-hash");
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        let gate_labels = BTreeMap::from([
            (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
            (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
            (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
        ]);
        let gate_annotations = BTreeMap::from([
            (STATE_ANNOTATION.into(), OPEN.into()),
            (ENTRIES_ANNOTATION.into(), "{}".into()),
        ]);
        let gate_object = lease_object(&gate, "gate-uid", "1", gate_labels, gate_annotations);
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{gate}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{gate}")))
            .respond_with(PatchedLease {
                object: gate_object,
            })
            .expect(1)
            .mount(&server)
            .await;

        let principal_annotations = BTreeMap::from([
            (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
            (ENTRIES_ANNOTATION.into(), "{}".into()),
        ]);
        let principal_object = lease_object(
            &principal,
            "principal-uid",
            "1",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            principal_annotations,
        );
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{principal}")))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(collection))
            .and(body_partial_json(json!({"metadata":{"name":principal}})))
            .respond_with(ResponseTemplate::new(201).set_body_json(principal_object.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{principal}")))
            .respond_with(PatchedLease {
                object: principal_object,
            })
            .expect(1)
            .mount(&server)
            .await;

        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };
        let AccessAcquire::Acquired(guard) = acquire(
            &client,
            "ledger",
            &sandbox_lease(),
            "principal-hash",
            &replica,
        )
        .await
        .unwrap() else {
            panic!("expected both slots to be acquired");
        };
        std::mem::forget(guard);

        let requests = server.received_requests().await.unwrap();
        let patches: Vec<Value> = requests
            .iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect();
        assert_eq!(patches.len(), 2);
        for patch in patches {
            let operations = patch.as_array().unwrap();
            assert_eq!(operations[0]["path"], "/metadata/uid");
            assert_eq!(operations[1]["path"], "/metadata/resourceVersion");
            assert_eq!(operations[2]["op"], "test");
            assert_eq!(operations[3]["op"], "replace");
        }
    }

    #[tokio::test]
    async fn cleanup_uids_are_armed_before_entry_patches() {
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };

        let gate_server = MockServer::start().await;
        let gate_api: Api<Lease> = Api::namespaced(mock_client(&gate_server), "ledger");
        let gate = gate_name("sandbox-uid");
        let gate_object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .expect(1)
            .mount(&gate_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}"
            )))
            .respond_with(k8s_error(500))
            .expect(1)
            .mount(&gate_server)
            .await;
        let mut gate_registration = test_registration(&replica);
        let mut pending_write = None;
        assert!(
            add_gate_entry(&gate_api, &mut gate_registration, &mut pending_write)
                .await
                .is_err()
        );
        assert_eq!(gate_registration.gate_uid.as_deref(), Some("gate-uid"));

        let principal_server = MockServer::start().await;
        let principal_api: Api<Lease> = Api::namespaced(mock_client(&principal_server), "ledger");
        let principal = principal_name("principal-hash");
        let principal_object = lease_object(
            &principal,
            "principal-uid",
            "1",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{principal}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal_object))
            .expect(1)
            .mount(&principal_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{principal}"
            )))
            .respond_with(k8s_error(500))
            .expect(1)
            .mount(&principal_server)
            .await;
        let gate_object: Lease = serde_json::from_value(gate_object).unwrap();
        let mut principal_registration = test_registration(&replica);
        let mut pending_write = None;
        assert!(
            add_principal_entry(
                &principal_api,
                "ledger",
                &gate_object,
                &mut principal_registration,
                &mut pending_write,
            )
            .await
            .is_err()
        );
        assert_eq!(
            principal_registration.principal_uid.as_deref(),
            Some("principal-uid")
        );
    }

    /// Cancelling a handler drops its acquisition future, but that does not
    /// cancel a PATCH already accepted by the API server. Drop must await the
    /// exact PATCH task before its GET+CAS cleanup, or a late response-lost
    /// commit can recreate a same-boot entry after cleanup saw it absent.
    #[tokio::test]
    async fn aborted_acquisition_waits_for_the_ambiguous_patch_before_cleanup() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };
        let gate = gate_name("sandbox-uid");
        let object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        let state = Arc::new(std::sync::Mutex::new(("{}".to_string(), 1)));
        let acquisition_patch_seen = Arc::new(tokio::sync::Notify::new());
        Mock::given(path(format!(
            "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}"
        )))
        .respond_with(AmbiguousGateLedger {
            object,
            state: state.clone(),
            acquisition_patch_seen: acquisition_patch_seen.clone(),
        })
        .expect(4)
        .mount(&server)
        .await;

        let acquire_client = client.clone();
        let acquire_replica = replica.clone();
        let acquire_task = tokio::spawn(async move {
            acquire(
                &acquire_client,
                "ledger",
                &sandbox_lease(),
                "principal-hash",
                &acquire_replica,
            )
            .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            acquisition_patch_seen.notified(),
        )
        .await
        .expect("acquisition PATCH must become in flight");
        acquire_task.abort();
        assert!(matches!(
            acquire_task.await,
            Err(error) if error.is_cancelled()
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let before_patch_terminal = server.received_requests().await.unwrap();
        assert_eq!(
            before_patch_terminal
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["GET", "PATCH"],
            "cleanup GET must wait for the ambiguous PATCH task"
        );

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state.lock().unwrap().0 == "{}" {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Drop cleanup must remove the committed entry");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["GET", "PATCH", "GET", "PATCH"]
        );
        let patches: Vec<Value> = requests
            .iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect();
        let admitted_entries: BTreeMap<String, GateEntry> =
            serde_json::from_str(patches[0][3]["value"].as_str().unwrap()).unwrap();
        assert_eq!(admitted_entries.len(), 1);
        assert_eq!(admitted_entries.values().next().unwrap().replica, replica);
        assert_eq!(patches[1][0]["value"], "gate-uid");
        assert_eq!(patches[1][1]["value"], "2");
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, GateEntry>>(
                patches[1][2]["value"].as_str().unwrap()
            )
            .unwrap(),
            admitted_entries
        );
        assert_eq!(patches[1][3]["value"], "{}");
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    #[tokio::test]
    async fn same_named_replacements_are_never_mutated_during_release() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };
        let registration = ReleaseRegistration {
            gate_uid: Some("old-gate-uid".into()),
            principal_uid: Some("old-principal-uid".into()),
            ..test_registration(&replica)
        };
        let principal = lease_object(
            &registration.principal_name,
            "replacement-principal-uid",
            "2",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        let gate = lease_object(
            &registration.gate_name,
            "replacement-gate-uid",
            "2",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        );
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(format!(
                "{collection}/{}",
                registration.principal_name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{}", registration.gate_name)))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate))
            .expect(1)
            .mount(&server)
            .await;

        let access = AccessClient {
            client,
            namespace: "ledger".into(),
        };
        release_exact(&access, &registration).await.unwrap();
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }

    #[tokio::test]
    async fn global_lease_and_principal_limits_refuse_before_any_patch() {
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };

        let gate_server = MockServer::start().await;
        let gate_api: Api<Lease> = Api::namespaced(mock_client(&gate_server), "ledger");
        let gate = gate_name("sandbox-uid");
        let gate_entries: BTreeMap<String, GateEntry> = (0
            ..crate::api::sandbox_streams::MAX_STREAMS_PER_LEASE)
            .map(|index| {
                (
                    format!("operation-{index}"),
                    GateEntry {
                        principal_hash: format!("principal-{index}"),
                        replica: replica.clone(),
                    },
                )
            })
            .collect();
        let gate_object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&gate_entries).unwrap(),
                ),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object))
            .expect(1)
            .mount(&gate_server)
            .await;
        let mut gate_registration = test_registration(&replica);
        gate_registration.principal_hash = "principal-new".into();
        let mut pending_write = None;
        assert!(
            add_gate_entry(&gate_api, &mut gate_registration, &mut pending_write)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            gate_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );

        let principal_server = MockServer::start().await;
        let principal_api: Api<Lease> = Api::namespaced(mock_client(&principal_server), "ledger");
        let principal = principal_name("principal-hash");
        let principal_entries: BTreeMap<String, PrincipalEntry> = (0
            ..crate::api::sandbox_streams::MAX_STREAMS_PER_PRINCIPAL)
            .map(|index| {
                (
                    format!("operation-{index}"),
                    PrincipalEntry {
                        lease_uid: format!("lease-{index}"),
                        gate_name: format!("gate-{index}"),
                        replica: replica.clone(),
                    },
                )
            })
            .collect();
        let principal_object = lease_object(
            &principal,
            "principal-uid",
            "1",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&principal_entries).unwrap(),
                ),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{principal}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal_object))
            .expect(1)
            .mount(&principal_server)
            .await;
        let gate_object: Lease = serde_json::from_value(lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (ENTRIES_ANNOTATION.into(), "{}".into()),
            ]),
        ))
        .unwrap();
        let mut principal_registration = test_registration(&replica);
        let mut pending_write = None;
        assert!(
            add_principal_entry(
                &principal_api,
                "ledger",
                &gate_object,
                &mut principal_registration,
                &mut pending_write,
            )
            .await
            .unwrap()
            .is_none()
        );
        assert!(
            principal_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }

    #[tokio::test]
    async fn a_live_exact_replica_keeps_the_closed_gate_blocked() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "boot-id".into(),
        };
        let gate = gate_name("sandbox-uid");
        let entries = BTreeMap::from([(
            "operation-1".to_string(),
            GateEntry {
                principal_hash: "principal-hash".into(),
                replica: replica.clone(),
            },
        )]);
        let gate_object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), CLOSED.into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&entries).unwrap(),
                ),
            ]),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/coordination.k8s.io/v1/namespaces/ledger/leases/{gate}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"v1", "kind":"Pod",
                "metadata":{"name":"kobe-0","namespace":"kobe-system","uid":"pod-uid"},
                "spec":{"containers":[]}
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            close_and_drain(&client, "ledger", &sandbox_lease())
                .await
                .unwrap(),
            AccessDrain::Waiting
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }

    #[tokio::test]
    async fn a_replaced_replica_is_pruned_before_drain_can_pass() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let replica = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "old-pod-uid".into(),
            boot_id: "old-boot-id".into(),
        };
        let gate = gate_name("sandbox-uid");
        let operation_id = "operation-1";
        let entries = BTreeMap::from([(
            operation_id.to_string(),
            GateEntry {
                principal_hash: "principal-hash".into(),
                replica,
            },
        )]);
        let gate_object = lease_object(
            &gate,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), CLOSED.into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&entries).unwrap(),
                ),
            ]),
        );
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{gate}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"v1", "kind":"Pod",
                "metadata":{"name":"kobe-0","namespace":"kobe-system","uid":"replacement-pod-uid"},
                "spec":{"containers":[]}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "{collection}/{}",
                principal_name("principal-hash")
            )))
            .respond_with(k8s_error(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{gate}")))
            .respond_with(PatchedLease {
                object: gate_object,
            })
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            close_and_drain(&client, "ledger", &sandbox_lease())
                .await
                .unwrap(),
            AccessDrain::Waiting
        );
        let requests = server.received_requests().await.unwrap();
        let patch: Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "PATCH")
                .expect("stale entry must be removed")
                .body,
        )
        .unwrap();
        assert_eq!(patch[0]["path"], "/metadata/uid");
        assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
        let tested_entries: Value =
            serde_json::from_str(patch[2]["value"].as_str().unwrap()).unwrap();
        assert_eq!(tested_entries, serde_json::to_value(entries).unwrap());
        assert_eq!(patch[3]["value"], "{}");
    }

    #[tokio::test]
    async fn startup_removes_only_the_previous_boots_exact_entries() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let current = ServingReplica {
            namespace: "kobe-system".into(),
            pod_name: "kobe-0".into(),
            pod_uid: "pod-uid".into(),
            boot_id: "new-boot-id".into(),
        };
        let previous = ServingReplica {
            boot_id: "old-boot-id".into(),
            ..current.clone()
        };
        let gate_name = gate_name("sandbox-uid");
        let principal_name = principal_name("principal-hash");
        let operation_id = "operation-1";
        let gate_entries = BTreeMap::from([(
            operation_id.to_string(),
            GateEntry {
                principal_hash: "principal-hash".into(),
                replica: previous.clone(),
            },
        )]);
        let principal_entries = BTreeMap::from([(
            operation_id.to_string(),
            PrincipalEntry {
                lease_uid: "sandbox-uid".into(),
                gate_name: gate_name.clone(),
                replica: previous,
            },
        )]);
        let gate = lease_object(
            &gate_name,
            "gate-uid",
            "1",
            BTreeMap::from([
                (LEDGER_KIND_LABEL.into(), GATE_KIND.into()),
                (LEASE_NAME_LABEL.into(), "sandbox-a".into()),
                (LEASE_UID_LABEL.into(), "sandbox-uid".into()),
            ]),
            BTreeMap::from([
                (STATE_ANNOTATION.into(), OPEN.into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&gate_entries).unwrap(),
                ),
            ]),
        );
        let principal = lease_object(
            &principal_name,
            "principal-uid",
            "1",
            BTreeMap::from([(LEDGER_KIND_LABEL.into(), PRINCIPAL_KIND.into())]),
            BTreeMap::from([
                (PRINCIPAL_ANNOTATION.into(), "principal-hash".into()),
                (
                    ENTRIES_ANNOTATION.into(),
                    serde_json::to_string(&principal_entries).unwrap(),
                ),
            ]),
        );
        let collection = "/apis/coordination.k8s.io/v1/namespaces/ledger/leases";
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/kobe-system/pods/kobe-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"v1", "kind":"Pod",
                "metadata":{"name":"kobe-0","namespace":"kobe-system","uid":"pod-uid"},
                "spec":{"containers":[]}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(collection))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "apiVersion":"coordination.k8s.io/v1", "kind":"LeaseList",
                "metadata":{"resourceVersion":"1"}, "items":[gate.clone()]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(principal.clone()))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{principal_name}")))
            .respond_with(PatchedLease { object: principal })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{collection}/{gate_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{collection}/{gate_name}")))
            .respond_with(PatchedLease { object: gate })
            .expect(1)
            .mount(&server)
            .await;

        recover_replica(&client, "ledger", &current).await.unwrap();

        let patches: Vec<Value> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect();
        assert_eq!(patches.len(), 2);
        assert!(
            patches
                .iter()
                .all(|patch| patch[0]["path"] == "/metadata/uid")
        );
        assert!(patches.iter().all(|patch| patch[3]["value"] == "{}"));
    }
}
