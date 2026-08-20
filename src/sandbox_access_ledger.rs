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

use std::collections::BTreeMap;
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
        if registration.gate_uid.is_none() && registration.principal_uid.is_none() {
            return;
        }
        tokio::spawn(async move {
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
    validate_gate(&gate, &sandbox_name, &sandbox_uid)?;
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN) {
        return Err(AccessLedgerError::Invalid("lease gate state"));
    }
    if !parse_entries::<GateEntry>(&gate)?.is_empty() {
        return Err(AccessLedgerError::Invalid(
            "pre-admission lease gate entries",
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
    validate_gate(&gate, &sandbox_name, &sandbox_uid)?;
    if gate.annotations().get(STATE_ANNOTATION).map(String::as_str) != Some(OPEN)
        || !parse_entries::<GateEntry>(&gate)?.is_empty()
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
    expected_lease_name: &str,
    expected_lease_uid: &str,
) -> Result<(), AccessLedgerError> {
    if gate.name_any() != gate_name(expected_lease_uid)
        || gate.labels().get(LEDGER_KIND_LABEL).map(String::as_str) != Some(GATE_KIND)
        || gate.labels().get(LEASE_NAME_LABEL).map(String::as_str) != Some(expected_lease_name)
        || gate.labels().get(LEASE_UID_LABEL).map(String::as_str) != Some(expected_lease_uid)
        || gate.spec.as_ref() != Some(&LeaseSpec::default())
    {
        return Err(AccessLedgerError::Invalid("lease gate provenance"));
    }
    match gate.annotations().get(STATE_ANNOTATION).map(String::as_str) {
        Some(OPEN | CLOSED) => Ok(()),
        _ => Err(AccessLedgerError::Invalid("lease gate state")),
    }
}

fn validate_principal(
    ledger: &Lease,
    expected_principal_hash: &str,
) -> Result<(), AccessLedgerError> {
    if ledger.name_any() != principal_name(expected_principal_hash)
        || ledger.labels().get(LEDGER_KIND_LABEL).map(String::as_str) != Some(PRINCIPAL_KIND)
        || ledger
            .annotations()
            .get(PRINCIPAL_ANNOTATION)
            .map(String::as_str)
            != Some(expected_principal_hash)
        || ledger.spec.as_ref() != Some(&LeaseSpec::default())
    {
        return Err(AccessLedgerError::Invalid("principal ledger provenance"));
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

async fn add_gate_entry(
    api: &Api<Lease>,
    registration: &mut ReleaseRegistration,
) -> Result<Option<Lease>, AccessLedgerError> {
    for _ in 0..MAX_CAS_ATTEMPTS {
        let gate = api.get(&registration.gate_name).await?;
        validate_gate(&gate, &registration.sandbox_name, &registration.sandbox_uid)?;
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
        match patch_entries(api, &gate, &previous, &entries).await {
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
        validate_principal(&ledger, &registration.principal_hash)?;
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
        match patch_entries(api, &ledger, &previous, &entries).await {
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
    });
    let Some(gate) = add_gate_entry(&api, &mut guard.registration).await? else {
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
    let principal =
        add_principal_entry(&api, ledger_namespace, &gate, &mut guard.registration).await?;
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

async fn remove_principal_entry(
    api: &Api<Lease>,
    name: &str,
    expected_uid: &str,
    expected_principal_hash: &str,
    operation_id: &str,
    expected_entry: &PrincipalEntry,
) -> Result<(), AccessLedgerError> {
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
        validate_principal(&ledger, expected_principal_hash)?;
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
        validate_gate(&gate, expected_sandbox_name, expected_sandbox_uid)?;
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
    let pods: Api<Pod> = Api::namespaced(client.clone(), &replica.namespace);
    match pods.get(&replica.pod_name).await {
        Ok(pod) => Ok(pod.uid().as_deref() == Some(replica.pod_uid.as_str())),
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
    validate_gate(&gate, &sandbox_name, &sandbox_uid)?;
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

/// Remove entries left by an older process in the same exact Pod.
///
/// Called after the lease watch reaches `InitDone` and before Sandbox routes
/// serve. The current process is then the only process that can own this Pod
/// identity, making a different boot id proof that the old socket disappeared.
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
        validate_gate(&gate, &sandbox_name, &sandbox_uid)?;
        let gate_uid = lease_uid(&gate)?.to_string();
        let entries: BTreeMap<String, GateEntry> = parse_entries(&gate)?;
        for (operation_id, entry) in entries {
            if entry.replica.namespace != replica.namespace
                || entry.replica.pod_name != replica.pod_name
                || entry.replica.pod_uid != replica.pod_uid
                || entry.replica.boot_id == replica.boot_id
            {
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

/// Delete empty access ledgers only after their authority object is gone.
pub async fn reap_empty(
    client: &Client,
    sandbox_namespace: &str,
    ledger_namespace: &str,
) -> Result<(), AccessLedgerError> {
    let api: Api<Lease> = Api::namespaced(client.clone(), ledger_namespace);
    let sandboxes: Api<SandboxLease> = Api::namespaced(client.clone(), sandbox_namespace);
    let objects = api.list(&ListParams::default()).await?;
    for object in objects {
        let kind = object.labels().get(LEDGER_KIND_LABEL).map(String::as_str);
        let removable = match kind {
            Some(PRINCIPAL_KIND) => parse_entries::<serde_json::Value>(&object)?.is_empty(),
            Some(GATE_KIND) if parse_entries::<serde_json::Value>(&object)?.is_empty() => {
                let Some(name) = object.labels().get(LEASE_NAME_LABEL) else {
                    return Err(AccessLedgerError::Invalid("lease gate name label"));
                };
                let expected_uid = object
                    .labels()
                    .get(LEASE_UID_LABEL)
                    .ok_or(AccessLedgerError::Invalid("lease gate UID label"))?;
                match sandboxes.get(name).await {
                    Ok(lease) => {
                        lease.uid().as_deref() != Some(expected_uid.as_str())
                            || clean_terminal_lease(&lease)
                    }
                    Err(kube::Error::Api(response)) if response.code == 404 => true,
                    Err(error) => return Err(error.into()),
                }
            }
            _ => false,
        };
        if !removable {
            continue;
        }
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: object.metadata.uid.clone(),
                resource_version: object.metadata.resource_version.clone(),
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
        annotations: BTreeMap<String, String>,
    ) -> Value {
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

    #[test]
    fn gate_and_principal_objects_start_empty() {
        let gate = build_gate("ledger", "sandbox-a", "uid-a", OPEN);
        validate_gate(&gate, "sandbox-a", "uid-a").unwrap();
        assert_eq!(parse_entries::<GateEntry>(&gate).unwrap(), BTreeMap::new());
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
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxleases/sandbox-a",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(parent))
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
        assert!(
            add_gate_entry(&gate_api, &mut gate_registration)
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
        assert!(
            add_principal_entry(
                &principal_api,
                "ledger",
                &gate_object,
                &mut principal_registration,
            )
            .await
            .is_err()
        );
        assert_eq!(
            principal_registration.principal_uid.as_deref(),
            Some("principal-uid")
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
        assert!(
            add_gate_entry(&gate_api, &mut gate_registration)
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
        assert!(
            add_principal_entry(
                &principal_api,
                "ledger",
                &gate_object,
                &mut principal_registration,
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
