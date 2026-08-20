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
//! # The reservation is a `create`
//!
//! Not a read-then-write. Two concurrent retries of the same request race for
//! one derived object name and the API server picks a winner; the loser reads
//! back what the winner reserved. A read-then-write here is the classic way to
//! produce two spawns from one idempotency key.
//!
//! # A deviation from #82, stated plainly
//!
//! #82 says to reserve the key *in the target*. This reserves it in Kobe's own
//! API instead. The difference would matter if two independent Kobe
//! deployments could drive one Sandbox — they cannot: a lease belongs to one
//! pool in one installation — and reserving in the target would require a
//! writable, durable path inside a container Kobe does not control, which is
//! the runner contract this issue defers. Reserving in Kobe is durable,
//! atomic, and available today.

use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Resource, ResourceExt};

use crate::api::sandbox_access::{SandboxAccessDenied, SandboxTarget};
use crate::crd::{
    ExecutionState, ReuseVerdict, SandboxExecution, SandboxExecutionSpec, SandboxLease,
    execution_name, request_digest, reuse_verdict,
};

/// How long a `Running` execution may go unresolved before it becomes
/// `Unknown`.
///
/// Generous, because the alternative to waiting is guessing. An execution
/// declared `Unknown` too early tells a caller to make a decision they did not
/// need to make; one never declared at all leaves them polling forever.
pub const VERDICT_GRACE: chrono::Duration = chrono::Duration::minutes(5);

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
}

impl ExecutionRequestError {
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::IdempotencyConflict => StatusCode::CONFLICT,
            Self::Invalid { .. } => StatusCode::BAD_REQUEST,
            Self::Denied(denied) => denied.http_status(),
            Self::Backend => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Invalid { .. } => "invalid_request",
            Self::Denied(denied) => denied.reason_code(),
            Self::Backend => "backend_error",
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
}

/// Reserve the idempotency key, atomically, before anything is spawned.
///
/// The name is derived from lease UID and key, so the reservation is a
/// `create` and concurrent retries race for one object. On 409 the existing
/// record decides: same request digest returns it, a different one conflicts.
pub async fn reserve_execution(
    client: &kube::Client,
    namespace: &str,
    lease: &SandboxLease,
    target: &SandboxTarget,
    request: &ExecutionRequest,
) -> Result<Reservation, ExecutionRequestError> {
    validate_request(request)?;

    let digest = request_digest(
        &request.argv,
        request.cwd.as_deref(),
        &request.timeout,
        request.detached,
    );
    let name = execution_name(&target.lease_uid, &request.idempotency_key);
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);

    let owner = lease
        .controller_owner_ref(&())
        .ok_or(ExecutionRequestError::Backend)?;
    let reserved = SandboxExecution {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            // Owner-referenced, so an execution cannot outlive the lease it
            // belongs to. #82 ends history with the Sandbox, and a record that
            // survived would describe a workload nobody can inspect.
            owner_references: Some(vec![owner]),
            labels: Some(
                [(
                    "kobe.kunobi.ninja/sandbox-lease-uid".to_string(),
                    target.lease_uid.clone(),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        },
        spec: SandboxExecutionSpec {
            lease_uid: target.lease_uid.clone(),
            pod_uid: target.pod_uid.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_digest: digest.clone(),
            timeout: request.timeout.clone(),
            detached: request.detached,
        },
        status: None,
    };

    match executions.create(&PostParams::default(), &reserved).await {
        Ok(created) => Ok(Reservation::Reserved(Box::new(created))),
        Err(kube::Error::Api(error)) if error.code == 409 => {
            // Somebody reserved it first — possibly this same caller retrying.
            let existing = executions
                .get(&name)
                .await
                .map_err(|_| ExecutionRequestError::Backend)?;
            match reuse_verdict(&existing.spec, &target.lease_uid, &digest) {
                ReuseVerdict::SameRequest => Ok(Reservation::AlreadyExists(Box::new(existing))),
                ReuseVerdict::Conflict => Err(ExecutionRequestError::IdempotencyConflict),
                // A key belonging to another lease is not this caller's to
                // reuse or to conflict with. Reporting a conflict would confirm
                // the other lease exists.
                ReuseVerdict::Foreign => {
                    Err(ExecutionRequestError::Denied(SandboxAccessDenied::NotFound))
                }
            }
        }
        Err(_) => Err(ExecutionRequestError::Backend),
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

/// Whether a `Running` execution has gone unresolved long enough to be
/// `Unknown`.
///
/// A missing or unreadable deadline resolves to `false`: refusing to declare
/// `Unknown` leaves a caller polling, which is recoverable; declaring it
/// wrongly tells them a completed command may not have run.
pub fn verdict_due(
    status: &crate::crd::SandboxExecutionStatus,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if status.state != ExecutionState::Running {
        return false;
    }
    status
        .verdict_deadline
        .as_deref()
        .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
        .is_some_and(|deadline| now >= deadline)
}

/// The deadline recorded when an execution starts running.
pub fn verdict_deadline(
    started: chrono::DateTime<chrono::Utc>,
    timeout: chrono::Duration,
) -> chrono::DateTime<chrono::Utc> {
    started + timeout + VERDICT_GRACE
}

/// Move a reservation to `Running` and record the deadline its verdict uses.
///
/// Written BEFORE the spawn. After this point nothing may spawn this key
/// again, whatever happens next — including this process disappearing.
pub async fn mark_running(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
    timeout: std::time::Duration,
) -> Result<(), ExecutionRequestError> {
    let started = chrono::Utc::now();
    let deadline = verdict_deadline(
        started,
        chrono::Duration::from_std(timeout).unwrap_or(VERDICT_GRACE),
    );
    mutate_status(client, namespace, execution, |status| {
        crate::crd::transition_execution(status.state, ExecutionState::Running, None)
            .map_err(|_| ExecutionRequestError::Backend)?;
        status.state = ExecutionState::Running;
        status.started_at = Some(started.to_rfc3339());
        status.verdict_deadline = Some(deadline.to_rfc3339());
        Ok(())
    })
    .await
    .map(|_| ())
}

/// Record a settled outcome.
///
/// Best-effort by design, and never propagated: this runs on paths that are
/// already returning an error to the caller, and failing to write the record
/// must not turn one problem into two. A record left `Running` is exactly what
/// the verdict deadline exists to resolve.
pub async fn record_terminal(
    client: &kube::Client,
    namespace: &str,
    execution: &SandboxExecution,
    state: ExecutionState,
    exit_code: Option<i32>,
    reason: &str,
) {
    let finished_at = chrono::Utc::now().to_rfc3339();
    if let Err(error) = mutate_status(client, namespace, execution, |status| {
        crate::crd::transition_execution(status.state, state, exit_code)
            .map_err(|_| ExecutionRequestError::Backend)?;
        status.state = state;
        status.finished_at = Some(finished_at);
        status.exit_code = exit_code;
        status.reason = Some(reason.to_string());
        Ok(())
    })
    .await
    {
        tracing::warn!(
            execution = %execution.name_any(),
            error = %error,
            "could not record the execution outcome; the verdict deadline will resolve it"
        );
    }
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

/// Resolve executions nobody is left to resolve.
///
/// The reserve-then-spawn order guarantees no duplicate spawn, and pays for it
/// with records that can be left `Running` by a process that disappeared. This
/// is what settles them: past its verdict deadline, an execution nobody
/// finished becomes `Unknown`.
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
    interval: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let executions: Api<SandboxExecution> = Api::namespaced(client.clone(), namespace);
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
            let Some(status) = execution.status.as_ref() else {
                continue;
            };
            if !verdict_due(status, now) {
                continue;
            }
            tracing::warn!(
                execution = %execution.name_any(),
                "execution outcome was never recorded; declaring it Unknown"
            );
            record_terminal(
                &client,
                namespace,
                &execution,
                ExecutionState::Unknown,
                None,
                "outcome_unverifiable",
            )
            .await;
        }
    }
    tracing::info!("Sandbox execution reaper shut down");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            argv: vec!["/agent".into(), "run".into()],
            cwd: None,
            timeout: "60s".into(),
            idempotency_key: "key-1".into(),
            detached: false,
        }
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
                lease_uid: "lease".into(),
                pod_uid: "pod".into(),
                idempotency_key: "key".into(),
                request_digest: "d".repeat(64),
                timeout: "60s".into(),
                detached: false,
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

    /// `Unknown` is declared on a deadline, and never guessed.
    ///
    /// Too early tells a caller to make a decision they did not need to make;
    /// never at all leaves them polling forever. A deadline that cannot be read
    /// resolves to "not yet", because polling is recoverable and a wrong
    /// `Unknown` is not.
    #[test]
    fn unknown_is_declared_only_once_its_deadline_passes() {
        let now = chrono::Utc::now();
        let status =
            |state: ExecutionState, deadline: Option<String>| crate::crd::SandboxExecutionStatus {
                state,
                verdict_deadline: deadline,
                ..Default::default()
            };

        let future = (now + chrono::Duration::minutes(1)).to_rfc3339();
        let past = (now - chrono::Duration::seconds(1)).to_rfc3339();

        assert!(!verdict_due(
            &status(ExecutionState::Running, Some(future.clone())),
            now
        ));
        assert!(verdict_due(
            &status(ExecutionState::Running, Some(past.clone())),
            now
        ));

        // A settled execution is never re-judged, however old its deadline.
        for state in [
            ExecutionState::Succeeded,
            ExecutionState::Failed,
            ExecutionState::Cancelled,
            ExecutionState::TimedOut,
            ExecutionState::Unknown,
            ExecutionState::Queued,
        ] {
            assert!(
                !verdict_due(&status(state, Some(past.clone())), now),
                "{state} must not be re-judged"
            );
        }

        // Unreadable deadlines wait rather than guess.
        for unreadable in [None, Some(String::new()), Some("soon".into())] {
            assert!(!verdict_due(
                &status(ExecutionState::Running, unreadable),
                now
            ));
        }
    }

    /// The verdict deadline leaves room for the command itself.
    ///
    /// A deadline shorter than the timeout would declare `Unknown` about
    /// executions that are simply still running, which is the fastest way to
    /// make the state meaningless.
    #[test]
    fn the_verdict_deadline_outlasts_the_command() {
        let started = chrono::Utc::now();
        let timeout = chrono::Duration::minutes(10);
        let deadline = verdict_deadline(started, timeout);

        assert!(deadline > started + timeout);
        assert_eq!(deadline, started + timeout + VERDICT_GRACE);
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
}
