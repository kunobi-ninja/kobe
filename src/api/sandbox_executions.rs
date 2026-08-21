//! The execution API: reserve, then spawn (#82).
//!
//! # The order is the entire guarantee
//!
//! ```text
//! reserve the idempotency key  ->  spawn  ->  record the outcome
//! ```
//!
//! Spawning first and recording afterwards is the obvious implementation and it
//! is wrong in exactly the case that matters: a crash between the two leaves no
//! trace that anything ran, so the retry runs it again. For an agent calling
//! `terraform apply`, running twice is far worse than failing.
//!
//! Reserving first inverts that. A crash after the reservation leaves a record
//! that says "this may have run", the retry finds it, and nobody spawns
//! anything a second time. The cost is that some executions end in `Unknown` —
//! which is the honest answer, and the one #82 asks for.
//!
//! # Capacity and identity are both reserved before spawn
//!
//! A UID/resourceVersion CAS first spends one bounded lifetime/active slot in
//! the lease's access gate. The derived execution object is then created by
//! name. Concurrent retries can win each checkpoint only once, and the gate
//! binds that object's API-server UID before anything may spawn. A read-then-
//! write here is the classic way to produce two spawns from one idempotency key.
//!
//! # Two matching reservations
//!
//! Kobe first reserves the caller's key in its own API so an operator restart
//! cannot forget it. `kobe-runner` then reserves the same derived execution id
//! inside the exact target before spawning. The API object is the durable
//! cross-restart authority; the target spool is what makes a lost runner-start
//! response idempotent without trusting a long-lived exec connection.

use kube::ResourceExt;
use kube::api::{
    Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions,
};

use crate::api::sandbox_access::{SandboxAccessDenied, SandboxTarget};
use crate::crd::{
    ExecutionState, ReuseVerdict, SandboxExecution, SandboxExecutionSpec, SandboxExecutionTarget,
    SandboxLease, execution_name, legacy_request_digest, request_digest, reuse_verdict,
};

/// Finalizer that keeps an execution record present until its exact process
/// group and Kubernetes record have both been cleaned.
pub const SANDBOX_EXECUTION_FINALIZER: &str = "kobe.kunobi.ninja/sandbox-execution-cleanup";

/// Maximum number of execution records retained for one Sandbox lifetime.
///
/// This bounds Kubernetes history and, together with
/// [`EXECUTION_OUTPUT_RETENTION_BYTES`], bounds the runner spool even when a
/// caller uses a fresh idempotency key for every command.
pub const MAX_EXECUTIONS_PER_LEASE: usize = 256;

/// Maximum process groups that may be active in one Sandbox at once.
pub const MAX_ACTIVE_EXECUTIONS_PER_LEASE: usize = 8;

/// Per-stream runner retention used by Kobe.
///
/// The runner accepts up to eight MiB, but Kobe deliberately uses the smaller
/// production cap. At the lifetime record limit, stdout plus stderr therefore
/// occupy at most 512 MiB before small metadata overhead.
pub const EXECUTION_OUTPUT_RETENTION_BYTES: u64 = 1024 * 1024;

/// Longest a reserved record may remain Queued before it becomes Unknown.
///
/// The slot is written before the CR and the CR before `Running`. A process
/// crash in either gap must not hold one of eight active slots forever; after
/// this bound the gate keeps the idempotency key spent, while the active slot
/// is retired with an honest Unknown record.
pub const EXECUTION_SETUP_GRACE: chrono::Duration = chrono::Duration::minutes(5);

const STATUS_CAS_ATTEMPTS: usize = 64;

/// Why an execution request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionRequestError {
    #[error("idempotency key is already in use by a different command")]
    IdempotencyConflict,
    #[error("{what} is not acceptable")]
    Invalid { what: &'static str },
    #[error(transparent)]
    Denied(#[from] SandboxAccessDenied),
    #[error("execution store is unavailable")]
    Backend,
    #[error("sandbox execution limit reached")]
    LimitReached,
}

impl ExecutionRequestError {
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::IdempotencyConflict => StatusCode::CONFLICT,
            Self::Invalid { .. } => StatusCode::BAD_REQUEST,
            Self::Denied(denied) => denied.http_status(),
            Self::Backend => StatusCode::SERVICE_UNAVAILABLE,
            Self::LimitReached => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Invalid { .. } => "invalid_request",
            Self::Denied(denied) => denied.reason_code(),
            Self::Backend => "backend_error",
            Self::LimitReached => "execution_limit",
        }
    }
}

/// A validated execution request.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub timeout: String,
    pub idempotency_key: String,
    pub detached: bool,
}

/// Longest a caller-supplied idempotency key may be.
///
/// It is hashed into the object name, so length is not a naming constraint —
/// it is a storage one: the key is kept verbatim in the spec so an operator can
/// correlate a record with a caller's own logs.
pub const MAX_IDEMPOTENCY_KEY: usize = 253;

/// Longest a command may be allowed to run.
///
/// The caller picks the timeout; this is the ceiling. An execution outliving
/// its own lease would be cancelled mid-flight by teardown, which is a worse
/// outcome than refusing the request.
pub const MAX_EXECUTION_TIMEOUT: chrono::Duration = chrono::Duration::hours(1);

/// Clamp one execution to the time its exact lease still owns.
///
/// Runner timeouts are whole seconds and are rounded up so a caller's
/// fractional timeout is not shortened. Lease time is rounded down instead:
/// granting the runner a partial second past `expiresAt` would let the command
/// outlive the authority that started it. Less than one full second remaining
/// is therefore already expired for a new execution.
pub fn effective_timeout(
    requested: std::time::Duration,
    lease: &SandboxLease,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<std::time::Duration, ExecutionRequestError> {
    let expires_at = lease
        .status
        .as_ref()
        .and_then(|status| status.expires_at.as_deref())
        .and_then(|expires_at| chrono::DateTime::parse_from_rfc3339(expires_at).ok())
        .ok_or(ExecutionRequestError::Denied(SandboxAccessDenied::Expired))?;
    let remaining_millis = expires_at
        .signed_duration_since(now)
        .num_milliseconds()
        .max(0) as u64;
    let remaining_seconds = remaining_millis / 1_000;
    if remaining_seconds == 0 {
        return Err(ExecutionRequestError::Denied(SandboxAccessDenied::Expired));
    }

    let requested_seconds = requested
        .as_secs()
        .saturating_add(u64::from(requested.subsec_nanos() > 0))
        .max(1);
    Ok(std::time::Duration::from_secs(
        requested_seconds.min(remaining_seconds),
    ))
}

/// Validate a request before anything is reserved.
///
/// Every check here is one that would otherwise become a partially-reserved
/// execution: a record whose command could never have run, which a retry then
/// has to reason about.
pub fn validate_request(request: &ExecutionRequest) -> Result<(), ExecutionRequestError> {
    if request.argv.is_empty() || request.argv.iter().any(String::is_empty) {
        // There is no reading of "run nothing" that should reach a workload,
        // and an empty argument is decided by the container runtime rather
        // than by the caller.
        return Err(ExecutionRequestError::Invalid { what: "command" });
    }
    if request.idempotency_key.is_empty() || request.idempotency_key.len() > MAX_IDEMPOTENCY_KEY {
        return Err(ExecutionRequestError::Invalid {
            what: "idempotencyKey",
        });
    }
    if let Some(cwd) = request.cwd.as_deref() {
        // Validated here AND by the runner. Kobe never implements `cwd` with a
        // shell — `cd X && ...` would make quoting the security boundary — so
        // this is a sanity check on a value the runner passes to `chdir`, not
        // the enforcement.
        if cwd.is_empty() || !cwd.starts_with('/') || cwd.contains('\0') {
            return Err(ExecutionRequestError::Invalid { what: "cwd" });
        }
    }
    match crate::pool::parse_duration(&request.timeout) {
        Some(timeout) if timeout > chrono::Duration::zero() && timeout <= MAX_EXECUTION_TIMEOUT => {
            Ok(())
        }
        _ => Err(ExecutionRequestError::Invalid { what: "timeout" }),
    }
}

/// The outcome of reserving one idempotency key.
#[derive(Debug, Clone)]
pub enum Reservation {
    /// This request reserved the key. It may now spawn — and nothing else will.
    Reserved(Box<SandboxExecution>),
    /// The same request already reserved it. Return the original; spawn
    /// nothing.
    AlreadyExists(Box<SandboxExecution>),
    /// Capacity is durable and the exact CREATE/bind resolver owns the request,
    /// but this HTTP task reached its absolute deadline or process shutdown.
    /// The caller receives a non-retry 202 handle; retrying the same key/digest
    /// may observe the record but can never mint a second spawn authority.
    Pending(Box<SandboxExecution>),
}

/// Absolute budget for capacity reservation, CR CREATE, and UID binding.
pub const EXECUTION_RESERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn build_execution_record(
    namespace: &str,
    name: &str,
    lease: &SandboxLease,
    target: &SandboxTarget,
    request: &ExecutionRequest,
    digest: &str,
    recorded_target: SandboxExecutionTarget,
) -> SandboxExecution {
    SandboxExecution {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            // Never owner-reference this record to the outer lease. Foreground
            // GC could otherwise erase it before process-group cancellation.
            // Its own finalizer survives every outer propagation mode until
            // explicit cleanup succeeds.
            finalizers: Some(vec![SANDBOX_EXECUTION_FINALIZER.into()]),
            labels: Some(
                [
                    (
                        "kobe.kunobi.ninja/sandbox-lease-uid".to_string(),
                        target.lease_uid.clone(),
                    ),
                    (
                        "kobe.kunobi.ninja/sandbox-lease-name".to_string(),
                        lease.name_any(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        },
        spec: SandboxExecutionSpec {
            lease_name: Some(lease.name_any()),
            lease_uid: target.lease_uid.clone(),
            pod_uid: target.pod_uid.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_digest: digest.to_string(),
            timeout: request.timeout.clone(),
            detached: request.detached,
            // Response timing is not supervision provenance: both wait and
            // detached mode use the runner now.
            runner_managed: Some(true),
            target: Some(recorded_target),
        },
        status: None,
    }
}

/// Reserve the idempotency key, atomically, before anything is spawned.
///
/// One access-gate CAS first spends bounded capacity. The name is then derived
/// from lease UID and key, so concurrent retries race for one object CREATE;
/// its exact UID is bound back into the same gate before spawn. On 409 the
/// existing record decides: same request digest returns it, a different one
/// conflicts.
#[allow(clippy::too_many_arguments)]
pub async fn reserve_execution(
    client: &kube::Client,
    namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    target: &SandboxTarget,
    container: &str,
    request: &ExecutionRequest,
    deadline: tokio::time::Instant,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<Reservation, ExecutionRequestError> {
    validate_request(request)?;

    let digest = request_digest(
        &request.argv,
        request.cwd.as_deref(),
        &request.timeout,
        container,
        request.detached,
    );
    let legacy_digest =
        legacy_request_digest(&request.argv, request.cwd.as_deref(), &request.timeout);
    let name = execution_name(&target.lease_uid, &request.idempotency_key);
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    let runner_path = target
        .runner_path
        .clone()
        .ok_or(ExecutionRequestError::Backend)?;

    let capacity = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Err(ExecutionRequestError::Backend),
        _ = tokio::time::sleep_until(deadline) => return Err(ExecutionRequestError::Backend),
        capacity = crate::sandbox_access_ledger::reserve_execution_capacity(
            client,
            ledger_namespace,
            lease,
            &name,
            &digest,
            &target.pod_uid,
        ) => capacity.map_err(|_| ExecutionRequestError::Backend)?,
    };

    let reserved = build_execution_record(
        namespace,
        &name,
        lease,
        target,
        request,
        &digest,
        SandboxExecutionTarget {
            namespace: target.namespace.clone(),
            pod_name: target.pod_name.clone(),
            pod_uid: target.pod_uid.clone(),
            container: container.to_string(),
            runner_path: runner_path.clone(),
        },
    );
    match capacity {
        crate::sandbox_access_ledger::ExecutionCapacity::LimitReached => {
            return Err(ExecutionRequestError::LimitReached);
        }
        crate::sandbox_access_ledger::ExecutionCapacity::LeaseClosed => {
            return Err(ExecutionRequestError::Denied(
                SandboxAccessDenied::NotReady {
                    phase: "Releasing".into(),
                },
            ));
        }
        crate::sandbox_access_ledger::ExecutionCapacity::Conflict => {
            return Err(ExecutionRequestError::IdempotencyConflict);
        }
        crate::sandbox_access_ledger::ExecutionCapacity::ExistingTerminal { execution_uid } => {
            let existing = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    return Ok(Reservation::Pending(Box::new(reserved)));
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Ok(Reservation::Pending(Box::new(reserved)));
                }
                existing = executions.get(&name) => {
                    existing.map_err(|_| ExecutionRequestError::Backend)?
                }
            };
            if execution_uid.as_deref() != existing.uid().as_deref() {
                return Err(ExecutionRequestError::Backend);
            }
            if !execution_reuse_target_holds(&existing.spec, target, container, &runner_path) {
                return Err(ExecutionRequestError::Denied(
                    SandboxAccessDenied::TargetUnresolved,
                ));
            }
            return match compatible_reuse_verdict(
                &existing.spec,
                &target.lease_uid,
                &digest,
                &legacy_digest,
                request.detached,
            ) {
                ReuseVerdict::SameRequest => Ok(Reservation::AlreadyExists(Box::new(existing))),
                ReuseVerdict::Conflict => Err(ExecutionRequestError::IdempotencyConflict),
                ReuseVerdict::Foreign => {
                    Err(ExecutionRequestError::Denied(SandboxAccessDenied::NotFound))
                }
            };
        }
        crate::sandbox_access_ledger::ExecutionCapacity::Reserved
        | crate::sandbox_access_ledger::ExecutionCapacity::ExistingActive { .. } => {}
    }

    // Once the capacity CAS is visible, run CREATE/bind in its own task. Axum
    // cancellation or shutdown may drop the JoinHandle, but Tokio detaches the
    // task and the durable `Creating` tombstone keeps teardown fail-closed until
    // this request resolves or an exact retry observes the same object.
    let resolver_client = client.clone();
    let resolver_namespace = namespace.to_string();
    let resolver_ledger_namespace = ledger_namespace.to_string();
    let resolver_lease = lease.clone();
    let resolver_target = target.clone();
    let resolver_container = container.to_string();
    let resolver_runner_path = runner_path.clone();
    let resolver_digest = digest.clone();
    let resolver_legacy_digest = legacy_digest.clone();
    let resolver_detached = request.detached;
    let pending = reserved.clone();
    let mut resolver = tokio::spawn(async move {
        let result = resolve_execution_create(
            &resolver_client,
            &resolver_namespace,
            &resolver_ledger_namespace,
            &resolver_lease,
            &resolver_target,
            &resolver_container,
            &resolver_runner_path,
            &resolver_digest,
            &resolver_legacy_digest,
            resolver_detached,
            reserved,
        )
        .await;
        if let Err(error) = &result {
            tracing::warn!(execution = %name, %error, "execution CREATE/bind resolver did not complete");
        }
        result
    });

    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(Reservation::Pending(Box::new(pending))),
        _ = tokio::time::sleep_until(deadline) => Ok(Reservation::Pending(Box::new(pending))),
        resolved = &mut resolver => resolved
            .map_err(|_| ExecutionRequestError::Backend)?,
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_execution_create(
    client: &kube::Client,
    namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    digest: &str,
    legacy_digest: &str,
    detached: bool,
    reserved: SandboxExecution,
) -> Result<Reservation, ExecutionRequestError> {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    let name = reserved.name_any();
    let reservation = match executions.create(&PostParams::default(), &reserved).await {
        Ok(created) => Reservation::Reserved(Box::new(created)),
        Err(kube::Error::Api(error)) if error.code == 409 => {
            // Somebody reserved it first — possibly this same caller retrying.
            let existing = executions
                .get(&name)
                .await
                .map_err(|_| ExecutionRequestError::Backend)?;
            if existing.spec.lease_uid == target.lease_uid
                && !execution_reuse_target_holds(&existing.spec, target, container, runner_path)
            {
                // The key still names the old execution, but its runner spool
                // belonged to a different Pod. Never reinterpret that id in a
                // replacement Pod wearing the lease's current target name.
                return Err(ExecutionRequestError::Denied(
                    SandboxAccessDenied::TargetUnresolved,
                ));
            }
            match compatible_reuse_verdict(
                &existing.spec,
                &target.lease_uid,
                digest,
                legacy_digest,
                detached,
            ) {
                ReuseVerdict::SameRequest => Reservation::AlreadyExists(Box::new(existing)),
                ReuseVerdict::Conflict => {
                    return Err(ExecutionRequestError::IdempotencyConflict);
                }
                // A key belonging to another lease is not this caller's to
                // reuse or to conflict with. Reporting a conflict would confirm
                // the other lease exists.
                ReuseVerdict::Foreign => {
                    return Err(ExecutionRequestError::Denied(SandboxAccessDenied::NotFound));
                }
            }
        }
        Err(kube::Error::Api(error)) if definitive_create_rejection(error.code) => {
            if let Err(rejection_error) = crate::sandbox_access_ledger::reject_execution_creation(
                client,
                ledger_namespace,
                lease,
                &name,
                digest,
                &target.pod_uid,
            )
            .await
            {
                tracing::warn!(execution = %name, error = %rejection_error, "could not checkpoint definitive execution CREATE rejection");
            }
            return Err(ExecutionRequestError::Backend);
        }
        Err(_) => return Err(ExecutionRequestError::Backend),
    };
    let execution = match &reservation {
        Reservation::Reserved(execution) | Reservation::AlreadyExists(execution) => execution,
        Reservation::Pending(execution) => execution,
    };
    if !crate::sandbox_access_ledger::bind_execution_capacity(
        client,
        ledger_namespace,
        lease,
        execution,
    )
    .await
    .map_err(|_| ExecutionRequestError::Backend)?
    {
        return Err(ExecutionRequestError::Denied(
            SandboxAccessDenied::NotReady {
                phase: "Releasing".into(),
            },
        ));
    }
    Ok(reservation)
}

/// API responses that prove the object was not created.
///
/// Transport errors, request timeout, throttling, conflict, and every 5xx stay
/// ambiguous. Their `Creating` tombstone remains occupied because a late CREATE
/// can still become visible.
fn definitive_create_rejection(code: u16) -> bool {
    matches!(
        code,
        400 | 401 | 403 | 404 | 405 | 406 | 410 | 411 | 413 | 414 | 415 | 422
    )
}

/// Whether an execution still addresses the exact Pod that reserved it.
///
/// The runner id is meaningful only inside that Pod's spool. Re-pointing it at
/// a replacement Pod could turn `NotFound` into a false outcome or, worse,
/// address an unrelated process that happens to use the same derived id.
pub fn execution_pod_identity_holds(existing: &SandboxExecutionSpec, pod_uid: &str) -> bool {
    existing.pod_uid == pod_uid
}

/// Recover the exact runner address for reads, cancellation, and teardown.
///
/// Current records must match the lease's exact Pod identity and then use
/// their immutable container/path. Legacy runner records stored only the Pod
/// UID, so they may use the current Pod's default address; legacy raw-wait
/// records return `None` because no runner ever owned them.
pub fn execution_runner_address(
    existing: &SandboxExecutionSpec,
    target: &SandboxTarget,
) -> Result<Option<(String, String)>, &'static str> {
    if !execution_pod_identity_holds(existing, &target.pod_uid) {
        return Err("execution_pod_replaced");
    }
    match existing.target.as_ref() {
        Some(recorded)
            if recorded.namespace == target.namespace
                && recorded.pod_name == target.pod_name
                && recorded.pod_uid == target.pod_uid
                && recorded.pod_uid == existing.pod_uid =>
        {
            Ok(Some((
                recorded.container.clone(),
                recorded.runner_path.clone(),
            )))
        }
        Some(_) => Err("execution_runner_provenance_changed"),
        None if existing.runner_managed.unwrap_or(existing.detached) => target
            .runner_path
            .clone()
            .map(|path| Some((target.container.clone(), path)))
            .ok_or("execution_runner_missing"),
        None => Ok(None),
    }
}

/// Whether an existing record can be observed through this exact target.
///
/// Current records carry the full immutable runner address. Legacy records can
/// only prove a Pod UID, so they are accepted on that same Pod only through its
/// default container; an explicit sidecar selection cannot be reconstructed
/// safely from the old schema.
fn execution_reuse_target_holds(
    existing: &SandboxExecutionSpec,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
) -> bool {
    match execution_runner_address(existing, target) {
        Ok(Some((recorded_container, recorded_path))) if existing.target.is_some() => {
            recorded_container == container && recorded_path == runner_path
        }
        Ok(Some(_)) => existing.runner_managed.is_none() && container == target.container,
        Ok(None) => existing.runner_managed.is_none() && container == target.container,
        Err(_) => false,
    }
}

/// Compare a retry across the digest-format rolling upgrade.
///
/// The legacy hash omitted response mode. It is accepted only for a record
/// that also predates explicit runner provenance and whose stored `detached`
/// bit matches the request, so compatibility cannot collapse wait and detached
/// commands back into one identity.
fn compatible_reuse_verdict(
    existing: &SandboxExecutionSpec,
    lease_uid: &str,
    digest: &str,
    legacy_digest: &str,
    detached: bool,
) -> ReuseVerdict {
    match reuse_verdict(existing, lease_uid, digest) {
        ReuseVerdict::Conflict
            if existing.runner_managed.is_none()
                && existing.detached == detached
                && existing.request_digest == legacy_digest =>
        {
            ReuseVerdict::SameRequest
        }
        verdict => verdict,
    }
}

/// Whether a reserved execution may still be spawned.
///
/// Only a fresh `Queued` reservation may. Anything else has already been acted
/// on by somebody, and spawning again is the duplicate this whole design
/// exists to prevent.
pub fn may_spawn(execution: &SandboxExecution) -> bool {
    execution
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default()
        == ExecutionState::Queued
}

/// Whether a reservation stayed Queued past the only window in which Kobe may
/// checkpoint it Running.
pub fn queued_verdict_due(
    execution: &SandboxExecution,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let state = execution
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if state != ExecutionState::Queued {
        return false;
    }
    execution
        .metadata
        .creation_timestamp
        .as_ref()
        .and_then(|created| chrono::DateTime::parse_from_rfc3339(&created.0.to_string()).ok())
        .is_some_and(|created| now >= created + EXECUTION_SETUP_GRACE)
}

/// Move a reservation to `Running` before the runner may see it.
///
/// Written BEFORE the spawn. After this point nothing may spawn this key
/// again, whatever happens next — including this process disappearing.
pub async fn mark_running(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
    _timeout: std::time::Duration,
) -> Result<(), ExecutionRequestError> {
    let started = chrono::Utc::now();
    mutate_status(client, namespace, execution, |status| {
        crate::crd::transition_execution(status.state, ExecutionState::Running, None)
            .map_err(|_| ExecutionRequestError::Backend)?;
        status.state = ExecutionState::Running;
        status.started_at = Some(started.to_rfc3339());
        // A wall clock cannot prove that the runner stopped. Legacy records may
        // carry this field, but current writers never use it as a terminal CAS.
        status.verdict_deadline = None;
        Ok(())
    })
    .await
    .map(|_| ())
}

/// Record a settled outcome and return the authoritative durable winner.
///
/// Terminal state is monotonic. If another exact writer wins the UID/RV CAS,
/// this retries from a strong GET; if that writer already committed a terminal
/// state, that durable state is returned instead of overlaying a different
/// runner observation in the HTTP response.
pub async fn record_terminal(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
    state: ExecutionState,
    exit_code: Option<i32>,
    reason: &str,
) -> Option<SandboxExecution> {
    match persist_terminal(client, namespace, execution, state, exit_code, reason).await {
        Ok(durable) => Some(durable),
        Err(error) => {
            tracing::warn!(
                execution = %execution.name_any(),
                error = %error,
                "could not durably record the execution outcome"
            );
            None
        }
    }
}

async fn persist_terminal(
    client: &kube::Client,
    namespace: &str,
    expected: &SandboxExecution,
    state: ExecutionState,
    exit_code: Option<i32>,
    reason: &str,
) -> Result<SandboxExecution, ExecutionRequestError> {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    let expected_uid = expected.uid().ok_or(ExecutionRequestError::Backend)?;
    let finished_at = chrono::Utc::now().to_rfc3339();
    for _ in 0..STATUS_CAS_ATTEMPTS {
        let live = executions
            .get(&expected.name_any())
            .await
            .map_err(|_| ExecutionRequestError::Backend)?;
        if live.uid().as_deref() != Some(expected_uid.as_str()) {
            return Err(ExecutionRequestError::Backend);
        }
        let mut status = live.status.clone().unwrap_or_default();
        if status.state.is_terminal() {
            return Ok(live);
        }
        crate::crd::transition_execution(status.state, state, exit_code)
            .map_err(|_| ExecutionRequestError::Backend)?;
        status.state = state;
        status.finished_at = Some(finished_at.clone());
        status.exit_code = exit_code;
        status.reason = Some(reason.to_string());
        let resource_version = live
            .resource_version()
            .ok_or(ExecutionRequestError::Backend)?;
        let patch = fenced_status_patch(&expected_uid, &resource_version, &status)?;
        match executions
            .patch_status(
                &expected.name_any(),
                &PatchParams::default(),
                &Patch::Json::<()>(patch),
            )
            .await
        {
            Ok(updated) => return Ok(updated),
            Err(kube::Error::Api(error)) if error.code == 409 || error.code == 422 => continue,
            Err(_) => return Err(ExecutionRequestError::Backend),
        }
    }
    Err(ExecutionRequestError::Backend)
}

/// Settle a setup timeout only while the exact record is still `Queued`.
///
/// This is deliberately not [`record_terminal`]. A concurrent request may have
/// won the `Queued -> Running` CAS immediately after the reaper's LIST. If the
/// reaper then accepted `Running -> Unknown`, it would free the active slot
/// while that request proceeded to spawn. Re-reading and requiring `Queued`
/// makes exactly one of setup expiry and runner start win.
async fn record_queued_setup_unknown(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
) -> Option<SandboxExecution> {
    let finished_at = chrono::Utc::now().to_rfc3339();
    mutate_status(client, namespace, execution, |status| {
        if status.state != ExecutionState::Queued {
            return Err(ExecutionRequestError::Backend);
        }
        crate::crd::transition_execution(status.state, ExecutionState::Unknown, None)
            .map_err(|_| ExecutionRequestError::Backend)?;
        status.state = ExecutionState::Unknown;
        status.finished_at = Some(finished_at);
        status.reason = Some("setup_unconfirmed".into());
        Ok(())
    })
    .await
    .ok()
}

/// Mutate one execution status under exact object identity and version.
///
/// The strong GET establishes the current state and resourceVersion. The JSON
/// Patch then tests both UID and resourceVersion before replacing status, so a
/// same-name successor or a concurrent terminal writer can never be
/// overwritten by a stale request.
async fn mutate_status<F>(
    client: &kube::Client,
    namespace: &str,
    expected: &SandboxExecution,
    mutate: F,
) -> Result<SandboxExecution, ExecutionRequestError>
where
    F: FnOnce(&mut crate::crd::SandboxExecutionStatus) -> Result<(), ExecutionRequestError>,
{
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    let expected_uid = expected.uid().ok_or(ExecutionRequestError::Backend)?;
    let live = executions
        .get(&expected.name_any())
        .await
        .map_err(|_| ExecutionRequestError::Backend)?;
    if live.uid().as_deref() != Some(expected_uid.as_str()) {
        return Err(ExecutionRequestError::Backend);
    }
    let resource_version = live
        .resource_version()
        .ok_or(ExecutionRequestError::Backend)?;
    let mut status = live.status.clone().unwrap_or_default();
    mutate(&mut status)?;
    let patch = fenced_status_patch(&expected_uid, &resource_version, &status)?;

    executions
        .patch_status(
            &expected.name_any(),
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Json::<()>(patch),
        )
        .await
        .map_err(|_| ExecutionRequestError::Backend)
}

fn fenced_status_patch(
    uid: &str,
    resource_version: &str,
    status: &crate::crd::SandboxExecutionStatus,
) -> Result<json_patch::Patch, ExecutionRequestError> {
    serde_json::from_value(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version
        },
        { "op": "add", "path": "/status", "value": status }
    ]))
    .map_err(|_| ExecutionRequestError::Backend)
}

/// Re-read one execution after its outcome was recorded.
pub async fn refresh(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
) -> Option<SandboxExecution> {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    executions.get(&execution.name_any()).await.ok()
}

/// Read one execution, but only if it belongs to this lease.
///
/// Execution names are derived from a caller's own idempotency key, so a
/// second caller could construct one. Ownership of the LEASE is what
/// authorises the read, and a record belonging to another lease answers
/// exactly as an absent one does.
pub async fn get_owned(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    lease_uid: &str,
) -> Result<Option<SandboxExecution>, ExecutionRequestError> {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    match executions.get(name).await {
        Ok(execution) if execution.spec.lease_uid == lease_uid => Ok(Some(execution)),
        Ok(_) => Ok(None),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(None),
        Err(_) => Err(ExecutionRequestError::Backend),
    }
}

/// Cancel one execution, if it has not already settled.
///
/// A settled execution is not re-opened: every answer already given about it
/// would otherwise become provisional. The caller is told the state that
/// actually applies rather than the one they asked for.
pub async fn cancel_owned(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    lease_uid: &str,
) -> Result<Option<SandboxExecution>, ExecutionRequestError> {
    let Some(execution) = get_owned(client, namespace, name, lease_uid).await? else {
        return Ok(None);
    };
    let current = execution
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if current.is_terminal() {
        return Ok(Some(execution));
    }

    crate::crd::transition_execution(current, ExecutionState::Cancelled, None)
        .map_err(|_| ExecutionRequestError::Backend)?;
    record_terminal(
        client,
        namespace,
        &execution,
        ExecutionState::Cancelled,
        None,
        "cancelled_by_caller",
    )
    .await;
    Ok(refresh(client, namespace, &execution)
        .await
        .or(Some(execution)))
}

/// Resolve setup reservations nobody is left to resolve.
///
/// The reserve-then-spawn order guarantees no duplicate spawn, and pays for it
/// with records that can be left `Queued` before any runner started. This
/// settles only that proven pre-spawn state. A `Running` record is never judged
/// by wall clock: only an exact runner report or exact target-destruction receipt
/// can establish its terminal state.
///
/// `Unknown`, and never `Failed`. A caller reading `Failed` retries; a caller
/// reading `Unknown` has to decide, which is the correct amount of work to
/// impose when the truth is that nobody knows.
///
/// Runs on every replica: the sweep is idempotent — a settled execution is
/// never re-judged — so several replicas reaching the same verdict is a
/// no-op rather than a conflict.
pub async fn run_execution_reaper(
    client: kube::Client,
    namespace: &str,
    ledger_namespace: &str,
    interval: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    tracing::info!("Starting Sandbox execution reaper");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }

        let listed = match executions.list(&kube::api::ListParams::default()).await {
            Ok(listed) => listed,
            Err(error) => {
                tracing::warn!(error = %error, "could not list Sandbox executions");
                continue;
            }
        };
        let now = chrono::Utc::now();
        for execution in listed {
            let state = execution
                .status
                .as_ref()
                .map(|status| status.state)
                .unwrap_or_default();
            if state.is_terminal() {
                complete_capacity_for_record(&client, &leases, ledger_namespace, &execution).await;
                continue;
            }
            let setup_due = state == ExecutionState::Queued && queued_verdict_due(&execution, now);
            if !setup_due {
                continue;
            }
            tracing::warn!(
                execution = %execution.name_any(),
                "execution never reached Running; declaring setup Unknown"
            );
            let terminal = record_queued_setup_unknown(&client, namespace, &execution).await;
            if let Some(terminal) = terminal {
                complete_capacity_for_record(&client, &leases, ledger_namespace, &terminal).await;
            }
        }

        reap_unbound_execution_capacity(&client, &leases, &executions, ledger_namespace, now).await;
    }
    tracing::info!("Sandbox execution reaper shut down");
}

/// Retire setup reservations that never reached the UID-bind checkpoint.
///
/// A 404 never closes `Creating`: a late CREATE may still produce its finalised
/// record. An exact record is adopted into the inactive manifest by CAS so a
/// racing bind either wins first or can never start the runner afterward.
async fn reap_unbound_execution_capacity(
    client: &kube::Client,
    leases: &Api<SandboxLease>,
    executions: &Api<SandboxExecution>,
    ledger_namespace: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let listed = match leases.list(&ListParams::default()).await {
        Ok(listed) => listed,
        Err(error) => {
            tracing::warn!(error = %error, "could not list Sandbox leases for execution setup recovery");
            return;
        }
    };
    for lease in listed {
        let manifest = match crate::sandbox_access_ledger::execution_manifest(
            client,
            ledger_namespace,
            &lease,
        )
        .await
        {
            Ok(manifest) => manifest,
            // Not every retained/pre-upgrade lease has an access gate. Those
            // are handled fail-closed by lifecycle migration, not guessed at
            // by a background reaper.
            Err(_) => continue,
        };
        for entry in manifest {
            if entry.execution_uid.is_some() {
                continue;
            }
            let due = chrono::DateTime::parse_from_rfc3339(&entry.reserved_at)
                .ok()
                .map(|reserved| reserved.with_timezone(&chrono::Utc) + EXECUTION_SETUP_GRACE)
                .is_some_and(|deadline| now >= deadline);
            if !due {
                continue;
            }

            let observed = match executions.get(&entry.name).await {
                Ok(execution) => {
                    let exact_uid = match execution_identity_holds(&execution, &lease) {
                        Ok(uid) => uid,
                        Err(reason) => {
                            tracing::error!(execution = %entry.name, reason, "execution setup recovery found unverifiable identity");
                            continue;
                        }
                    };
                    let status = execution.status.clone().unwrap_or_default();
                    if execution.spec.request_digest != entry.request_digest
                        || execution.spec.pod_uid != entry.pod_uid
                        || status.started_at.is_some()
                        || !(status.state == ExecutionState::Queued || status.state.is_terminal())
                    {
                        tracing::error!(execution = %entry.name, "execution setup recovery found impossible state");
                        continue;
                    }
                    Some((execution, exact_uid))
                }
                Err(kube::Error::Api(error)) if error.code == 404 => None,
                Err(error) => {
                    tracing::warn!(execution = %entry.name, error = %error, "could not inspect an unbound execution");
                    continue;
                }
            };
            let observed_uid = observed.as_ref().map(|(_, uid)| uid.as_str());
            match crate::sandbox_access_ledger::expire_unbound_execution(
                client,
                ledger_namespace,
                &lease,
                &entry.name,
                &entry.request_digest,
                &entry.pod_uid,
                observed_uid,
            )
            .await
            {
                Ok(true) => {
                    if let Some((execution, _)) = observed
                        && execution
                            .status
                            .as_ref()
                            .map(|status| status.state)
                            .unwrap_or_default()
                            == ExecutionState::Queued
                    {
                        record_terminal(
                            client,
                            &execution.namespace().unwrap_or_default(),
                            &execution,
                            ExecutionState::Unknown,
                            None,
                            "setup_unconfirmed",
                        )
                        .await;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(execution = %entry.name, error = %error, "could not retire an unbound execution reservation");
                }
            }
        }
    }
}

async fn complete_capacity_for_record(
    client: &kube::Client,
    leases: &Api<SandboxLease>,
    ledger_namespace: &str,
    execution: &SandboxExecution,
) {
    if execution.status.as_ref().is_some_and(|status| {
        status.state == ExecutionState::Unknown && status.started_at.is_some()
    }) {
        // Unknown says only that the verdict disappeared. It does not prove
        // the runner killed the process group, so this slot remains active
        // until lease cleanup obtains a terminal runner report.
        return;
    }
    let Some(lease_name) = execution.spec.lease_name.as_deref() else {
        // Legacy records were not admitted through the execution-capacity
        // ledger. Lifecycle cleanup fails closed on them; this generic reaper
        // must not guess which same-named parent used to own one.
        return;
    };
    let lease = match leases.get(lease_name).await {
        Ok(lease) if lease.uid().as_deref() == Some(execution.spec.lease_uid.as_str()) => lease,
        Ok(_) => return,
        Err(kube::Error::Api(error)) if error.code == 404 => return,
        Err(error) => {
            tracing::warn!(execution = %execution.name_any(), error = %error, "could not read execution parent while retiring capacity");
            return;
        }
    };
    if let Err(error) = crate::sandbox_access_ledger::complete_execution_capacity(
        client,
        ledger_namespace,
        &lease,
        execution,
        false,
    )
    .await
    {
        tracing::warn!(execution = %execution.name_any(), error = %error, "could not retire terminal execution capacity");
    }
}

/// Result of one restart-safe execution-cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionCleanupOutcome {
    Clean,
    /// One durable mutation landed; re-list before doing anything destructive.
    Checkpointed,
    Retry,
    Quarantine(&'static str),
}

fn cleanup_target(
    lease: &SandboxLease,
    execution: &SandboxExecution,
) -> Result<crate::api::sandbox_access::SandboxTarget, &'static str> {
    use crate::api::sandbox_access::{SandboxTarget, TargetPlacement};
    use crate::crd::ResolvedSandboxPlacement;

    let status = lease
        .status
        .as_ref()
        .ok_or("execution_lease_status_missing")?;
    let provenance = status
        .target
        .as_ref()
        .ok_or("execution_target_provenance_missing")?;
    let claim = provenance
        .sandbox_claim
        .as_ref()
        .ok_or("execution_claim_provenance_missing")?;
    let sandbox = provenance
        .sandbox
        .as_ref()
        .ok_or("execution_sandbox_provenance_missing")?;
    let pod = provenance
        .pod
        .as_ref()
        .ok_or("execution_pod_provenance_missing")?;
    let recorded = execution
        .spec
        .target
        .as_ref()
        .ok_or("execution_runner_provenance_missing")?;
    if provenance.namespace != recorded.namespace
        || pod.name != recorded.pod_name
        || pod.uid != recorded.pod_uid
        || execution.spec.pod_uid != recorded.pod_uid
    {
        return Err("execution_runner_provenance_changed");
    }
    let placement = match status.placement {
        Some(ResolvedSandboxPlacement::Management {}) => TargetPlacement::Management,
        Some(ResolvedSandboxPlacement::ChildCluster { .. }) => TargetPlacement::ChildCluster,
        None => return Err("execution_placement_missing"),
    };
    Ok(SandboxTarget {
        lease_uid: execution.spec.lease_uid.clone(),
        placement,
        namespace: recorded.namespace.clone(),
        claim_uid: claim.uid.clone(),
        sandbox_name: sandbox.name.clone(),
        sandbox_uid: sandbox.uid.clone(),
        pod_name: recorded.pod_name.clone(),
        pod_uid: recorded.pod_uid.clone(),
        container: recorded.container.clone(),
        ports: vec![],
        runner_path: Some(recorded.runner_path.clone()),
    })
}

fn execution_identity_holds(
    execution: &SandboxExecution,
    lease: &SandboxLease,
) -> Result<String, &'static str> {
    let lease_uid = lease.uid().ok_or("execution_parent_uid_missing")?;
    let uid = execution
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or("execution_uid_missing")?;
    if execution.namespace().as_deref() != lease.namespace().as_deref()
        || execution.spec.lease_uid != lease_uid
        || execution.spec.lease_name.as_deref() != Some(lease.name_any().as_str())
        || execution
            .labels()
            .get("kobe.kunobi.ninja/sandbox-lease-uid")
            .map(String::as_str)
            != Some(lease_uid.as_str())
        || execution
            .labels()
            .get("kobe.kunobi.ninja/sandbox-lease-name")
            .map(String::as_str)
            != Some(lease.name_any().as_str())
        || !execution
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || execution.metadata.finalizers.as_deref()
            != Some(&[SANDBOX_EXECUTION_FINALIZER.to_string()])
    {
        return Err("execution_identity_unverifiable");
    }
    Ok(uid)
}

async fn remove_execution_record(
    executions: &Api<SandboxExecution>,
    execution: &SandboxExecution,
    expected_uid: &str,
) -> ExecutionCleanupOutcome {
    let resource_version = match execution.resource_version() {
        Some(version) => version,
        None => return ExecutionCleanupOutcome::Quarantine("execution_rv_missing"),
    };
    let finalizers = execution.metadata.finalizers.clone().unwrap_or_default();
    if finalizers.as_slice() != [SANDBOX_EXECUTION_FINALIZER] {
        return ExecutionCleanupOutcome::Quarantine("execution_finalizer_unverifiable");
    }
    let patch = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": expected_uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/metadata/finalizers", "value": finalizers },
        { "op": "remove", "path": "/metadata/finalizers" }
    ]);
    match executions
        .patch(
            &execution.name_any(),
            &PatchParams::default(),
            &Patch::<()>::Json(
                serde_json::from_value(patch).expect("valid execution-finalizer patch"),
            ),
        )
        .await
    {
        Ok(_) => {}
        Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {
            return ExecutionCleanupOutcome::Retry;
        }
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return ExecutionCleanupOutcome::Quarantine("execution_delete_forbidden");
        }
        Err(_) => return ExecutionCleanupOutcome::Retry,
    }

    let current = match executions.get(&execution.name_any()).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return ExecutionCleanupOutcome::Checkpointed;
        }
        Err(_) => return ExecutionCleanupOutcome::Retry,
    };
    if current.uid().as_deref() != Some(expected_uid) {
        return ExecutionCleanupOutcome::Quarantine("execution_replaced_during_cleanup");
    }
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(expected_uid.to_string()),
            resource_version: current.resource_version(),
        }),
        ..DeleteParams::default()
    };
    match executions.delete(&execution.name_any(), &params).await {
        Ok(_) => {}
        Err(kube::Error::Api(error)) if error.code == 404 => {}
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return ExecutionCleanupOutcome::Quarantine("execution_delete_forbidden");
        }
        Err(kube::Error::Api(error)) if error.code == 409 => {
            return ExecutionCleanupOutcome::Retry;
        }
        Err(_) => return ExecutionCleanupOutcome::Retry,
    }
    match executions.get(&execution.name_any()).await {
        Err(kube::Error::Api(error)) if error.code == 404 => ExecutionCleanupOutcome::Checkpointed,
        Ok(replacement) if replacement.uid().as_deref() != Some(expected_uid) => {
            ExecutionCleanupOutcome::Quarantine("execution_replaced_during_cleanup")
        }
        Ok(_) | Err(_) => ExecutionCleanupOutcome::Retry,
    }
}

/// Cancel, prove, and delete every execution before credential/workload cleanup.
///
/// The distributed access gate must already be closed and stream-empty. The
/// gate's execution manifest is then the durable inventory: a bound entry may
/// disappear only after its exact runner outcome and record deletion are
/// proven. A `Creating` tombstone is never retired merely because its object is
/// absent: a lost CREATE response may still land after that observation.
pub async fn cleanup_lease_executions(
    management_client: &kube::Client,
    execution_namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    target_client: &kube::Client,
    shutdown: &tokio_util::sync::CancellationToken,
) -> ExecutionCleanupOutcome {
    cleanup_lease_executions_inner(
        management_client,
        execution_namespace,
        ledger_namespace,
        lease,
        Some(target_client),
        false,
        shutdown,
    )
    .await
}

/// Retire exact execution records after an authenticated destroy receipt has
/// proven their entire target cluster absent.
///
/// This variant performs every manifest/record UID, resourceVersion and
/// finalizer check used by reachable cleanup, but deliberately makes no runner
/// call: the receipt is stronger evidence that no process group survives. It
/// must never be called for a mere credential error, timeout, or name-based
/// 404; the caller owns the exact receipt check.
pub async fn cleanup_lease_executions_after_target_absence(
    management_client: &kube::Client,
    execution_namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    shutdown: &tokio_util::sync::CancellationToken,
) -> ExecutionCleanupOutcome {
    cleanup_lease_executions_inner(
        management_client,
        execution_namespace,
        ledger_namespace,
        lease,
        None,
        false,
        shutdown,
    )
    .await
}

/// Prove a NeverBound child never acquired execution authority.
///
/// A non-empty manifest is contradictory evidence and is quarantined rather
/// than rewritten as target-destroyed. With an empty manifest the ordinary
/// exact-owned record scan still rejects any orphan record and clears only the
/// empty durable manifest checkpoint.
pub async fn prove_never_bound_execution_footprint_empty(
    management_client: &kube::Client,
    execution_namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    shutdown: &tokio_util::sync::CancellationToken,
) -> ExecutionCleanupOutcome {
    cleanup_lease_executions_inner(
        management_client,
        execution_namespace,
        ledger_namespace,
        lease,
        None,
        true,
        shutdown,
    )
    .await
}

async fn cleanup_lease_executions_inner(
    management_client: &kube::Client,
    execution_namespace: &str,
    ledger_namespace: &str,
    lease: &SandboxLease,
    target_client: Option<&kube::Client>,
    require_empty_manifest: bool,
    shutdown: &tokio_util::sync::CancellationToken,
) -> ExecutionCleanupOutcome {
    use crate::api::sandbox_runner::{self as runner, RunnerCallFailure};
    use kobe_runner::protocol::RunnerErrorCode;

    let manifest = match crate::sandbox_access_ledger::execution_manifest(
        management_client,
        ledger_namespace,
        lease,
    )
    .await
    {
        Ok(manifest) => manifest,
        Err(_) => return ExecutionCleanupOutcome::Quarantine("execution_manifest_unverifiable"),
    };
    if require_empty_manifest && !manifest.is_empty() {
        return ExecutionCleanupOutcome::Quarantine("never_bound_execution_manifest_nonempty");
    }
    let executions: Api<SandboxExecution> =
        Api::namespaced(management_client.clone(), execution_namespace);
    let listed = match executions.list(&ListParams::default()).await {
        Ok(listed) => listed,
        Err(kube::Error::Api(error)) if error.code == 401 || error.code == 403 => {
            return ExecutionCleanupOutcome::Quarantine("execution_list_forbidden");
        }
        Err(_) => return ExecutionCleanupOutcome::Retry,
    };
    let lease_uid = match lease.uid() {
        Some(uid) => uid,
        None => return ExecutionCleanupOutcome::Quarantine("execution_parent_uid_missing"),
    };
    let mut owned = std::collections::BTreeMap::new();
    for execution in listed {
        let labelled = execution
            .labels()
            .get("kobe.kunobi.ninja/sandbox-lease-uid")
            .map(String::as_str)
            == Some(lease_uid.as_str());
        if execution.spec.lease_uid != lease_uid && !labelled {
            continue;
        }
        if execution.spec.lease_uid != lease_uid || !labelled {
            return ExecutionCleanupOutcome::Quarantine("execution_identity_unverifiable");
        }
        if owned.insert(execution.name_any(), execution).is_some() {
            return ExecutionCleanupOutcome::Quarantine("execution_name_duplicated");
        }
    }
    if owned
        .keys()
        .any(|name| !manifest.iter().any(|entry| entry.name == *name))
    {
        return ExecutionCleanupOutcome::Quarantine("execution_not_in_manifest");
    }

    // One durable mutation per pass. Re-listing after every record prevents a
    // lost response or concurrent status writer from carrying stale identity
    // into the next destructive operation.
    if let Some(entry) = manifest.first() {
        let Some(execution) = owned.remove(&entry.name) else {
            if !entry.active {
                let retired = match entry.creation_state {
                    crate::sandbox_access_ledger::ExecutionCreationState::Rejected => {
                        crate::sandbox_access_ledger::retire_rejected_execution(
                            management_client,
                            ledger_namespace,
                            lease,
                            entry,
                        )
                        .await
                    }
                    crate::sandbox_access_ledger::ExecutionCreationState::Bound => {
                        crate::sandbox_access_ledger::retire_inactive_execution(
                            management_client,
                            ledger_namespace,
                            lease,
                            entry,
                        )
                        .await
                    }
                    crate::sandbox_access_ledger::ExecutionCreationState::Creating => {
                        return ExecutionCleanupOutcome::Retry;
                    }
                };
                return match retired {
                    Ok(true) => ExecutionCleanupOutcome::Checkpointed,
                    Ok(false) => ExecutionCleanupOutcome::Retry,
                    Err(_) => ExecutionCleanupOutcome::Retry,
                };
            }
            if entry.execution_uid.is_some() {
                return ExecutionCleanupOutcome::Quarantine("bound_execution_missing");
            }
            // Neither age nor a strong 404 proves that an API request whose
            // response was lost cannot still create this exact object.
            return ExecutionCleanupOutcome::Retry;
        };
        let execution_uid = match execution_identity_holds(&execution, lease) {
            Ok(uid) => uid,
            Err(reason) => return ExecutionCleanupOutcome::Quarantine(reason),
        };
        if entry.request_digest != execution.spec.request_digest
            || entry.pod_uid != execution.spec.pod_uid
        {
            return ExecutionCleanupOutcome::Quarantine("execution_manifest_mismatch");
        }
        if entry.execution_uid.is_none() {
            return match crate::sandbox_access_ledger::expire_unbound_execution(
                management_client,
                ledger_namespace,
                lease,
                &entry.name,
                &entry.request_digest,
                &entry.pod_uid,
                Some(&execution_uid),
            )
            .await
            {
                Ok(true) => ExecutionCleanupOutcome::Checkpointed,
                Ok(false) => ExecutionCleanupOutcome::Retry,
                Err(_) => ExecutionCleanupOutcome::Retry,
            };
        }
        if entry.execution_uid.as_deref() != Some(execution_uid.as_str()) {
            return ExecutionCleanupOutcome::Quarantine("execution_manifest_mismatch");
        }
        let target = match cleanup_target(lease, &execution) {
            Ok(target) => target,
            Err(reason) => return ExecutionCleanupOutcome::Quarantine(reason),
        };
        let state = execution
            .status
            .as_ref()
            .map(|status| status.state)
            .unwrap_or_default();
        let mut terminal = execution.clone();
        if state == ExecutionState::Queued {
            record_terminal(
                management_client,
                execution_namespace,
                &execution,
                ExecutionState::Cancelled,
                None,
                "lease_released_before_spawn",
            )
            .await;
            let Some(refreshed) = refresh(management_client, execution_namespace, &execution).await
            else {
                return ExecutionCleanupOutcome::Retry;
            };
            if !refreshed
                .status
                .as_ref()
                .is_some_and(|status| status.state.is_terminal())
            {
                return ExecutionCleanupOutcome::Retry;
            }
            terminal = refreshed;
        } else if execution
            .status
            .as_ref()
            .and_then(|status| status.started_at.as_ref())
            .is_some()
        {
            let runner_path = target
                .runner_path
                .as_deref()
                .expect("cleanup target always carries runnerPath");
            if let Some(target_client) = target_client {
                let report = match runner::cancel(
                    target_client,
                    &target,
                    &target.container,
                    runner_path,
                    &execution.name_any(),
                    shutdown,
                )
                .await
                {
                    Ok(report) => report,
                    Err(RunnerCallFailure::Unreachable) => return ExecutionCleanupOutcome::Retry,
                    Err(RunnerCallFailure::Refused(RunnerErrorCode::NotFound)) => {
                        return ExecutionCleanupOutcome::Quarantine(
                            "execution_runner_record_missing",
                        );
                    }
                    Err(_) => {
                        return ExecutionCleanupOutcome::Quarantine(
                            "execution_runner_unverifiable",
                        );
                    }
                };
                let outcome = runner::outcome_from_report(&report);
                if !outcome.state.is_terminal() {
                    return ExecutionCleanupOutcome::Retry;
                }
                record_terminal(
                    management_client,
                    execution_namespace,
                    &execution,
                    outcome.state,
                    outcome.exit_code,
                    &outcome.reason,
                )
                .await;
            } else if !state.is_terminal() {
                // The exact target no longer exists, so this is a proven
                // cancellation even though no runner remains to answer.
                record_terminal(
                    management_client,
                    execution_namespace,
                    &execution,
                    ExecutionState::Cancelled,
                    None,
                    "target_destroyed",
                )
                .await;
            }
            let Some(refreshed) = refresh(management_client, execution_namespace, &execution).await
            else {
                return ExecutionCleanupOutcome::Retry;
            };
            if !refreshed
                .status
                .as_ref()
                .is_some_and(|status| status.state.is_terminal())
            {
                return ExecutionCleanupOutcome::Retry;
            }
            terminal = refreshed;
        } else if !state.is_terminal() {
            return ExecutionCleanupOutcome::Quarantine("execution_state_unverifiable");
        }

        if crate::sandbox_access_ledger::complete_execution_capacity(
            management_client,
            ledger_namespace,
            lease,
            &terminal,
            target_client.is_none(),
        )
        .await
        .is_err()
        {
            return ExecutionCleanupOutcome::Retry;
        }
        return remove_execution_record(&executions, &terminal, &execution_uid).await;
    }

    match crate::sandbox_access_ledger::clear_execution_manifest(
        management_client,
        ledger_namespace,
        lease,
    )
    .await
    {
        Ok(true) => ExecutionCleanupOutcome::Checkpointed,
        Ok(false) => ExecutionCleanupOutcome::Clean,
        Err(_) => ExecutionCleanupOutcome::Retry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_definitive_create_rejections_release_a_creating_tombstone() {
        for code in [400, 401, 403, 404, 405, 406, 410, 411, 413, 414, 415, 422] {
            assert!(definitive_create_rejection(code), "HTTP {code}");
        }
        for code in [408, 409, 425, 429, 500, 502, 503, 504] {
            assert!(!definitive_create_rejection(code), "HTTP {code}");
        }
    }

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            argv: vec!["/agent".into(), "run".into()],
            cwd: None,
            timeout: "60s".into(),
            idempotency_key: "key-1".into(),
            detached: false,
        }
    }

    fn lease() -> SandboxLease {
        serde_json::from_value(serde_json::json!({
            "apiVersion":"kobe.kunobi.ninja/v1alpha1",
            "kind":"SandboxLease",
            "metadata":{"name":"sandbox-a","namespace":"kobe-system","uid":"lease-uid"},
            "spec":{
                "poolRef":{"name":"pool","uid":"pool-uid","generation":1},
                "ttl":"1m",
                "requester":{
                    "provider":"test","type":"oidc:user",
                    "issuer":"https://issuer.invalid","identity":"alice"
                }
            }
        }))
        .unwrap()
    }

    fn target() -> SandboxTarget {
        SandboxTarget {
            lease_uid: "lease-uid".into(),
            placement: crate::api::sandbox_access::TargetPlacement::Management,
            namespace: "kobe-system".into(),
            claim_uid: "claim-uid".into(),
            sandbox_name: "sandbox-a-upstream".into(),
            sandbox_uid: "sandbox-uid".into(),
            pod_name: "sandbox-a-pod".into(),
            pod_uid: "pod-uid".into(),
            container: "workspace".into(),
            ports: vec![],
            runner_path: Some("/kobe-runner".into()),
        }
    }

    fn recorded_target(container: &str) -> SandboxExecutionTarget {
        SandboxExecutionTarget {
            namespace: "kobe-system".into(),
            pod_name: "sandbox-a-pod".into(),
            pod_uid: "pod-uid".into(),
            container: container.into(),
            runner_path: "/kobe-runner".into(),
        }
    }

    /// The record survives every outer DELETE propagation mode until its exact
    /// runner group is terminal. Its immutable target can be cancelled without
    /// trusting a changed pool or a replacement Pod.
    #[test]
    fn current_execution_records_are_finalized_ownerless_and_exactly_addressed() {
        let request = request();
        let record = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target(),
            &request,
            &"d".repeat(64),
            recorded_target("sidecar"),
        );
        assert!(
            record
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        );
        assert_eq!(
            record.metadata.finalizers.as_deref(),
            Some(&[SANDBOX_EXECUTION_FINALIZER.to_string()][..])
        );
        assert_eq!(record.spec.lease_name.as_deref(), Some("sandbox-a"));
        assert_eq!(record.spec.lease_uid, "lease-uid");
        assert_eq!(record.spec.pod_uid, "pod-uid");
        assert_eq!(
            record.spec.target,
            Some(SandboxExecutionTarget {
                namespace: "kobe-system".into(),
                pod_name: "sandbox-a-pod".into(),
                pod_uid: "pod-uid".into(),
                container: "sidecar".into(),
                runner_path: "/kobe-runner".into(),
            })
        );
    }

    /// A retry may observe only the same immutable runner address. Legacy
    /// records lacked that address, so their compatibility path is restricted
    /// to the exact Pod UID and its default container.
    #[test]
    fn execution_reuse_never_redirects_to_a_sidecar_or_replacement_runner() {
        let target = target();
        let current = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target,
            &request(),
            &"d".repeat(64),
            recorded_target("sidecar"),
        );
        assert!(execution_reuse_target_holds(
            &current.spec,
            &target,
            "sidecar",
            "/kobe-runner"
        ));
        assert!(!execution_reuse_target_holds(
            &current.spec,
            &target,
            "workspace",
            "/kobe-runner"
        ));

        let mut legacy = current.spec.clone();
        legacy.target = None;
        legacy.runner_managed = None;
        assert!(execution_reuse_target_holds(
            &legacy,
            &target,
            "workspace",
            "/kobe-runner"
        ));
        assert!(!execution_reuse_target_holds(
            &legacy,
            &target,
            "sidecar",
            "/kobe-runner"
        ));
        legacy.pod_uid = "replacement-pod-uid".into();
        assert!(!execution_reuse_target_holds(
            &legacy,
            &target,
            "workspace",
            "/kobe-runner"
        ));
    }

    /// Cleanup authority is the complete immutable record shape, never only a
    /// caller-mutable label or deterministic name.
    #[test]
    fn execution_cleanup_rejects_every_identity_drift() {
        let mut record = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target(),
            &request(),
            &"d".repeat(64),
            recorded_target("workspace"),
        );
        record.metadata.uid = Some("execution-uid".into());
        record.metadata.resource_version = Some("7".into());
        assert_eq!(
            execution_identity_holds(&record, &lease()).unwrap(),
            "execution-uid"
        );

        let mut changed = record.clone();
        changed.spec.lease_uid = "foreign".into();
        assert!(execution_identity_holds(&changed, &lease()).is_err());
        let mut changed = record.clone();
        changed.metadata.labels.as_mut().unwrap().insert(
            "kobe.kunobi.ninja/sandbox-lease-uid".into(),
            "foreign".into(),
        );
        assert!(execution_identity_holds(&changed, &lease()).is_err());
        let mut changed = record.clone();
        changed.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "v1".into(),
                kind: "Pod".into(),
                name: "foreign".into(),
                uid: "foreign".into(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            },
        ]);
        assert!(execution_identity_holds(&changed, &lease()).is_err());
        let mut changed = record;
        changed.metadata.finalizers = Some(vec!["foreign/finalizer".into()]);
        assert!(execution_identity_holds(&changed, &lease()).is_err());
    }

    /// A terminal record loses only Kobe's exact finalizer, is deleted under
    /// UID/resourceVersion preconditions, and counts absent only after a 404.
    #[tokio::test]
    async fn terminal_execution_record_is_uid_fenced_through_confirmed_absence() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct GetThenAbsent {
            current: serde_json::Value,
            calls: Arc<AtomicUsize>,
        }
        impl Respond for GetThenAbsent {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(self.current.clone())
                } else {
                    ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion":"v1","kind":"Status","status":"Failure",
                        "reason":"NotFound","code":404
                    }))
                }
            }
        }

        let server = MockServer::start().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = crate::testutil::mock_k8s_client(&server);
        let mut record = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target(),
            &request(),
            &"d".repeat(64),
            recorded_target("workspace"),
        );
        record.metadata.uid = Some("execution-uid".into());
        record.metadata.resource_version = Some("7".into());
        record.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Cancelled,
            finished_at: Some("2026-08-20T00:00:00Z".into()),
            reason: Some("lease_released_before_spawn".into()),
            ..Default::default()
        });
        let path_value =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxexecutions/execution-a";
        let mut after_finalizer = serde_json::to_value(&record).unwrap();
        after_finalizer["metadata"]["resourceVersion"] = serde_json::json!("8");
        after_finalizer["metadata"]["finalizers"] = serde_json::json!([]);
        Mock::given(method("PATCH"))
            .and(path(path_value))
            .respond_with(ResponseTemplate::new(200).set_body_json(after_finalizer.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(path_value))
            .respond_with(GetThenAbsent {
                current: after_finalizer,
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(path_value))
            .and(body_partial_json(serde_json::json!({
                "preconditions":{"uid":"execution-uid","resourceVersion":"8"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion":"v1","kind":"Status","status":"Success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let executions: Api<SandboxExecution> = Api::namespaced(client, "kobe-system");
        assert_eq!(
            remove_execution_record(&executions, &record, "execution-uid").await,
            ExecutionCleanupOutcome::Checkpointed
        );
        let patch = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert_eq!(body[0]["value"], "execution-uid");
        assert_eq!(body[1]["value"], "7");
        assert_eq!(body[3]["op"], "remove");
    }

    /// An exact destroy receipt proves the runner target absent, but the
    /// management-cluster record still follows every UID/RV/finalizer fence.
    /// A running record is first durably cancelled as `target_destroyed`, then
    /// its capacity and object are retired without any runner request.
    #[tokio::test]
    async fn target_absence_cleanup_terminalizes_and_uid_fences_a_running_record() {
        use sha2::{Digest as _, Sha256};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct ExecutionReads {
            running: serde_json::Value,
            terminal: serde_json::Value,
            unfinalized: serde_json::Value,
            calls: Arc<AtomicUsize>,
        }
        impl Respond for ExecutionReads {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                match self.calls.fetch_add(1, Ordering::SeqCst) {
                    0 => ResponseTemplate::new(200).set_body_json(self.running.clone()),
                    1 => ResponseTemplate::new(200).set_body_json(self.terminal.clone()),
                    2 => ResponseTemplate::new(200).set_body_json(self.unfinalized.clone()),
                    _ => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion":"v1","kind":"Status","status":"Failure",
                        "reason":"NotFound","code":404
                    })),
                }
            }
        }

        let server = MockServer::start().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = crate::testutil::mock_k8s_client(&server);
        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        let lease_uid = lease.uid().unwrap();
        let gate = format!(
            "kobe-access-g-{}",
            &format!("{:x}", Sha256::digest(lease_uid.as_bytes()))[..40]
        );
        lease.metadata.annotations.as_mut().unwrap().insert(
            crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION.into(),
            crate::sandbox_access_ledger::encode_gate_reference(
                &crate::sandbox_access_ledger::AccessGateReference {
                    name: gate.clone(),
                    uid: "gate-uid".into(),
                },
            )
            .unwrap(),
        );
        let target = SandboxTarget {
            lease_uid: lease_uid.clone(),
            placement: crate::api::sandbox_access::TargetPlacement::Management,
            namespace: "test-ns".into(),
            claim_uid: "claim-uid".into(),
            sandbox_name: "sbx".into(),
            sandbox_uid: "sandbox-uid".into(),
            pod_name: "sandbox-pod".into(),
            pod_uid: "pod-uid".into(),
            container: "agent".into(),
            ports: vec![],
            runner_path: Some("/kobe-runner".into()),
        };
        let mut running = build_execution_record(
            "test-ns",
            "execution-a",
            &lease,
            &target,
            &request(),
            &"d".repeat(64),
            SandboxExecutionTarget {
                namespace: "test-ns".into(),
                pod_name: "sandbox-pod".into(),
                pod_uid: "pod-uid".into(),
                container: "agent".into(),
                runner_path: "/kobe-runner".into(),
            },
        );
        running.metadata.uid = Some("execution-uid".into());
        running.metadata.resource_version = Some("execution-rv-1".into());
        running.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Running,
            started_at: Some("2026-08-20T00:00:00Z".into()),
            ..Default::default()
        });
        let mut terminal = running.clone();
        terminal.metadata.resource_version = Some("execution-rv-2".into());
        terminal.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Cancelled,
            started_at: Some("2026-08-20T00:00:00Z".into()),
            finished_at: Some("2026-08-20T00:01:00Z".into()),
            reason: Some("target_destroyed".into()),
            ..Default::default()
        });
        let mut unfinalized = terminal.clone();
        unfinalized.metadata.resource_version = Some("execution-rv-3".into());
        unfinalized.metadata.finalizers = Some(vec![]);

        let execution_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions/execution-a";
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion":"kobe.kunobi.ninja/v1alpha1",
                "kind":"SandboxExecutionList",
                "metadata":{"resourceVersion":"1"},
                "items":[running.clone()]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(execution_path))
            .respond_with(ExecutionReads {
                running: serde_json::to_value(&running).unwrap(),
                terminal: serde_json::to_value(&terminal).unwrap(),
                unfinalized: serde_json::to_value(&unfinalized).unwrap(),
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect(4)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{execution_path}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&terminal))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(execution_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(&unfinalized))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(execution_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion":"v1","kind":"Status","status":"Success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let manifest = serde_json::json!({
            "execution-a": {
                "requestDigest": "d".repeat(64),
                "podUid": "pod-uid",
                "reservedAt": "2026-08-20T00:00:00Z",
                "executionUid": "execution-uid",
                "creationState": "bound",
                "active": true
            }
        })
        .to_string();
        let gate_path = format!("/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/{gate}");
        let gate_object = serde_json::json!({
            "apiVersion":"coordination.k8s.io/v1",
            "kind":"Lease",
            "metadata":{
                "name":gate,"namespace":"test-ns","uid":"gate-uid","resourceVersion":"1",
                "labels":{
                    "kobe.kunobi.ninja/sandbox-access-kind":"lease-gate",
                    "kobe.kunobi.ninja/sandbox-lease-name":lease.name_any(),
                    "kobe.kunobi.ninja/sandbox-access-lease-uid":lease_uid,
                },
                "annotations":{
                    "kobe.kunobi.ninja/sandbox-access-state":"closed",
                    "kobe.kunobi.ninja/sandbox-access-entries":"{}",
                    "kobe.kunobi.ninja/sandbox-executions":manifest,
                }
            },
            "spec":{}
        });
        Mock::given(method("GET"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object.clone()))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&gate_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_object))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            cleanup_lease_executions_after_target_absence(
                &client,
                "test-ns",
                "test-ns",
                &lease,
                &tokio_util::sync::CancellationToken::new(),
            )
            .await,
            ExecutionCleanupOutcome::Checkpointed
        );
        let requests = server.received_requests().await.unwrap();
        let terminal_patch: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.url.path() == format!("{execution_path}/status"))
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(terminal_patch[2]["value"]["state"], "Cancelled");
        assert_eq!(terminal_patch[2]["value"]["reason"], "target_destroyed");
        assert!(
            requests
                .iter()
                .all(|request| !request.url.path().contains("/proxy"))
        );
        let delete: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method.as_str() == "DELETE")
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(delete["preconditions"]["uid"], "execution-uid");
        assert_eq!(delete["preconditions"]["resourceVersion"], "execution-rv-3");
    }

    /// A stale setup-timeout observation cannot overwrite a concurrent
    /// `Running` checkpoint and release its active slot.
    #[tokio::test]
    async fn queued_setup_expiry_loses_to_a_running_checkpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = crate::testutil::mock_k8s_client(&server);
        let mut observed = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target(),
            &request(),
            &"d".repeat(64),
            recorded_target("workspace"),
        );
        observed.metadata.uid = Some("execution-uid".into());
        observed.metadata.resource_version = Some("1".into());
        observed.status = Some(Default::default());
        let mut live = observed.clone();
        live.metadata.resource_version = Some("2".into());
        live.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Running,
            started_at: Some("2026-08-20T00:00:00Z".into()),
            verdict_deadline: Some("2026-08-20T01:00:00Z".into()),
            ..Default::default()
        });
        let path_value =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxexecutions/execution-a";
        Mock::given(method("GET"))
            .and(path(path_value))
            .respond_with(ResponseTemplate::new(200).set_body_json(live))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            record_queued_setup_unknown(&client, "kobe-system", &observed)
                .await
                .is_none()
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

    /// A request that could never run is refused before anything is reserved.
    ///
    /// Otherwise it becomes a reservation for a command that cannot exist,
    /// which every subsequent retry then has to reason about.
    #[test]
    fn an_unrunnable_request_never_reserves_anything() {
        assert!(validate_request(&request()).is_ok());

        let with = |mutate: &dyn Fn(&mut ExecutionRequest)| {
            let mut request = request();
            mutate(&mut request);
            validate_request(&request)
        };

        // There is no reading of "run nothing" that should reach a workload.
        assert!(with(&|r| r.argv = vec![]).is_err());
        assert!(with(&|r| r.argv = vec![String::new()]).is_err());
        assert!(with(&|r| r.argv = vec!["sh".into(), String::new()]).is_err());

        assert!(with(&|r| r.idempotency_key = String::new()).is_err());
        assert!(with(&|r| r.idempotency_key = "k".repeat(MAX_IDEMPOTENCY_KEY + 1)).is_err());
        assert!(with(&|r| r.idempotency_key = "k".repeat(MAX_IDEMPOTENCY_KEY)).is_ok());
    }

    /// `cwd` is a path, and a nul byte is not part of one.
    ///
    /// Kobe never implements `cwd` with a shell — `cd X && ...` would make
    /// quoting the security boundary — so this validates a value the runner
    /// hands to `chdir`, where an embedded nul truncates rather than fails.
    #[test]
    fn a_working_directory_must_be_an_absolute_path() {
        let with_cwd = |cwd: &str| {
            let mut request = request();
            request.cwd = Some(cwd.to_string());
            validate_request(&request)
        };

        assert!(with_cwd("/work").is_ok());
        assert!(with_cwd("/").is_ok());

        for bad in ["", "work", "./work", "../work", "/work\0/etc", "\0"] {
            assert!(with_cwd(bad).is_err(), "cwd {bad:?} must be refused");
        }
    }

    /// A command may not be allowed to outlive its own lease.
    ///
    /// One that did would be cancelled mid-flight by teardown, which is a
    /// worse outcome — and a less legible one — than refusing the request.
    #[test]
    fn a_timeout_is_bounded_at_both_ends() {
        let with_timeout = |timeout: &str| {
            let mut request = request();
            request.timeout = timeout.to_string();
            validate_request(&request)
        };

        assert!(with_timeout("1s").is_ok());
        assert!(with_timeout("1h").is_ok());

        for bad in ["", "0s", "-1m", "2h", "24h", "forever", "60"] {
            assert!(
                with_timeout(bad).is_err(),
                "timeout {bad:?} must be refused"
            );
        }
    }

    /// Only a fresh reservation may spawn.
    ///
    /// Every other state has already been acted on by somebody. Spawning again
    /// is precisely the duplicate this design exists to prevent — and the
    /// state that most needs refusing is `Unknown`, where the temptation to
    /// "just retry" is strongest and the risk is highest.
    #[test]
    fn only_a_fresh_reservation_may_spawn() {
        let execution = |state: Option<ExecutionState>| SandboxExecution {
            metadata: Default::default(),
            spec: SandboxExecutionSpec {
                lease_name: None,
                lease_uid: "lease".into(),
                pod_uid: "pod".into(),
                idempotency_key: "key".into(),
                request_digest: "d".repeat(64),
                timeout: "60s".into(),
                detached: false,
                runner_managed: None,
                target: None,
            },
            status: state.map(|state| crate::crd::SandboxExecutionStatus {
                state,
                ..Default::default()
            }),
        };

        // A just-created object has no status yet, which is Queued.
        assert!(may_spawn(&execution(None)));
        assert!(may_spawn(&execution(Some(ExecutionState::Queued))));

        for state in [
            ExecutionState::Running,
            ExecutionState::Succeeded,
            ExecutionState::Failed,
            ExecutionState::Cancelled,
            ExecutionState::TimedOut,
            ExecutionState::Unknown,
        ] {
            assert!(
                !may_spawn(&execution(Some(state))),
                "{state} must not spawn again"
            );
        }
    }

    /// An exact retry survives a rolling upgrade from the legacy digest, but
    /// the compatibility path cannot erase the wait/detached distinction or
    /// apply to records written with current runner provenance.
    #[test]
    fn legacy_digest_reuse_is_exact_and_upgrade_bounded() {
        let argv = vec!["/agent".to_string(), "run".to_string()];
        let legacy_digest = legacy_request_digest(&argv, Some("/work"), "60s");
        let current_digest = request_digest(&argv, Some("/work"), "60s", "workspace", false);
        assert_eq!(
            legacy_digest, "030c080c54aa88834e6249c7c3b544e9754b49a565a0c7696c4a06d38a8b5751",
            "the pre-upgrade digest format is a persisted compatibility vector"
        );
        assert_ne!(legacy_digest, current_digest);

        let mut existing = SandboxExecutionSpec {
            lease_name: None,
            lease_uid: "lease-uid".into(),
            pod_uid: "pod-uid".into(),
            idempotency_key: "key-1".into(),
            request_digest: legacy_digest.clone(),
            timeout: "60s".into(),
            detached: false,
            runner_managed: None,
            target: None,
        };
        assert_eq!(
            compatible_reuse_verdict(
                &existing,
                "lease-uid",
                &current_digest,
                &legacy_digest,
                false,
            ),
            ReuseVerdict::SameRequest
        );
        assert_eq!(
            compatible_reuse_verdict(
                &existing,
                "lease-uid",
                &request_digest(&argv, Some("/work"), "60s", "workspace", true),
                &legacy_digest,
                true,
            ),
            ReuseVerdict::Conflict,
            "a legacy wait record cannot answer a detached request"
        );
        let changed_argv = vec!["/agent".to_string(), "other".to_string()];
        assert_eq!(
            compatible_reuse_verdict(
                &existing,
                "lease-uid",
                &request_digest(&changed_argv, Some("/work"), "60s", "workspace", false,),
                &legacy_request_digest(&changed_argv, Some("/work"), "60s"),
                false,
            ),
            ReuseVerdict::Conflict,
            "changed argv must remain a conflict"
        );

        existing.runner_managed = Some(true);
        assert_eq!(
            compatible_reuse_verdict(
                &existing,
                "lease-uid",
                &current_digest,
                &legacy_digest,
                false,
            ),
            ReuseVerdict::Conflict,
            "current records never use the compatibility digest"
        );
        assert_eq!(
            compatible_reuse_verdict(
                &existing,
                "another-lease",
                &current_digest,
                &legacy_digest,
                false,
            ),
            ReuseVerdict::Foreign
        );
        assert!(execution_pod_identity_holds(&existing, "pod-uid"));
        assert!(
            !execution_pod_identity_holds(&existing, "replacement-pod-uid"),
            "a runner id may never be reinterpreted in a replacement Pod"
        );
    }

    /// An execution's wall-clock bound is never longer than the lease that
    /// authorises it, even when the caller asks for the global maximum.
    #[test]
    fn an_execution_timeout_never_outlives_its_lease() {
        let now = chrono::Utc::now();
        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        lease.status.as_mut().unwrap().expires_at = Some(
            (now + chrono::Duration::seconds(17) + chrono::Duration::milliseconds(900))
                .to_rfc3339(),
        );

        assert_eq!(
            effective_timeout(std::time::Duration::from_secs(3_600), &lease, now).unwrap(),
            std::time::Duration::from_secs(17),
            "lease time is rounded down, never granted past expiresAt"
        );
        assert_eq!(
            effective_timeout(std::time::Duration::from_millis(1_500), &lease, now).unwrap(),
            std::time::Duration::from_secs(2),
            "the caller timeout keeps the runner's existing round-up semantics"
        );

        lease.status.as_mut().unwrap().expires_at =
            Some((now + chrono::Duration::milliseconds(999)).to_rfc3339());
        assert!(matches!(
            effective_timeout(std::time::Duration::from_secs(1), &lease, now),
            Err(ExecutionRequestError::Denied(SandboxAccessDenied::Expired))
        ));

        lease.status.as_mut().unwrap().expires_at = Some("not-a-time".into());
        assert!(matches!(
            effective_timeout(std::time::Duration::from_secs(1), &lease, now),
            Err(ExecutionRequestError::Denied(SandboxAccessDenied::Expired))
        ));
    }

    /// Status writes are conditional on both immutable identity and the exact
    /// version that was read. A same-name replacement or concurrent terminal
    /// writer therefore makes the patch fail instead of being overwritten.
    #[test]
    fn every_execution_status_patch_is_uid_and_resource_version_fenced() {
        let status = crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Running,
            ..Default::default()
        };
        let patch = fenced_status_patch("execution-uid", "42", &status).unwrap();
        let value = serde_json::to_value(patch).unwrap();

        assert_eq!(
            value,
            serde_json::json!([
                {
                    "op": "test",
                    "path": "/metadata/uid",
                    "value": "execution-uid"
                },
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": "42"
                },
                {
                    "op": "add",
                    "path": "/status",
                    "value": { "state": "Running" }
                }
            ])
        );
    }

    /// A concurrent terminal writer wins permanently and becomes the HTTP
    /// answer; a stale observation is never overlaid on top of it.
    #[tokio::test]
    async fn terminal_status_cas_returns_the_durable_winner() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct RunningThenSucceeded {
            running: serde_json::Value,
            succeeded: serde_json::Value,
            calls: Arc<AtomicUsize>,
        }
        impl Respond for RunningThenSucceeded {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                let object = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    &self.running
                } else {
                    &self.succeeded
                };
                ResponseTemplate::new(200).set_body_json(object)
            }
        }

        let server = MockServer::start().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = crate::testutil::mock_k8s_client(&server);
        let mut running = build_execution_record(
            "kobe-system",
            "execution-a",
            &lease(),
            &target(),
            &request(),
            &"d".repeat(64),
            recorded_target("workspace"),
        );
        running.metadata.uid = Some("execution-uid".into());
        running.metadata.resource_version = Some("1".into());
        running.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Running,
            started_at: Some("2026-08-20T00:00:00Z".into()),
            ..Default::default()
        });
        let mut succeeded = running.clone();
        succeeded.metadata.resource_version = Some("2".into());
        succeeded.status = Some(crate::crd::SandboxExecutionStatus {
            state: ExecutionState::Succeeded,
            started_at: Some("2026-08-20T00:00:00Z".into()),
            finished_at: Some("2026-08-20T00:00:01Z".into()),
            exit_code: Some(0),
            reason: Some("completed".into()),
            ..Default::default()
        });
        let path_value =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe-system/sandboxexecutions/execution-a";
        Mock::given(method("GET"))
            .and(path(path_value))
            .respond_with(RunningThenSucceeded {
                running: serde_json::to_value(&running).unwrap(),
                succeeded: serde_json::to_value(&succeeded).unwrap(),
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("{path_value}/status")))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "apiVersion":"v1","kind":"Status","status":"Failure",
                "reason":"Conflict","code":409
            })))
            .expect(1)
            .mount(&server)
            .await;

        let durable = persist_terminal(
            &client,
            "kobe-system",
            &running,
            ExecutionState::Unknown,
            None,
            "outcome_unverifiable",
        )
        .await
        .unwrap();
        assert_eq!(
            durable.status.unwrap().state,
            ExecutionState::Succeeded,
            "the first durable terminal CAS is authoritative"
        );
    }
}
