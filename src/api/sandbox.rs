//! HTTP admission for caller-safe [`SandboxLease`](crate::crd::SandboxLease)
//! intent.
//!
//! The routes in this module deliberately stop at admission and lifecycle
//! intent. They never resolve a target cluster, return Kubernetes credentials,
//! or expose upstream Agent Sandbox objects. Placement controllers in #73/#74
//! own those transitions.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use kube::ResourceExt;
use kube::api::{
    Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{error, info, warn};

use super::auth::AuthIdentity;
use super::policy::{clamp_sandbox_ttl, format_duration, is_sandbox_allowed, policy_for};
use super::routes::AppState;
use super::sandbox_rate_limit::RateLimitDecision;
use crate::backend::ClusterBackend;
use crate::crd::{
    ResolvedSandboxPlacement, SandboxCondition, SandboxLease, SandboxLeasePhase, SandboxLeaseSpec,
    SandboxPlacement, SandboxPlacementAuthority, SandboxPool, SandboxPoolReference,
    SandboxPrincipal, SandboxReleaseCause, SandboxTargetProvenance, SandboxVerb,
};
use crate::pool::{is_valid_k8s_name, parse_duration};
use crate::sandbox::{SANDBOX_LEASE_FINALIZER, aggregate_resource_limits, resource_ceiling_allows};

pub(crate) const REQUESTER_HASH_LABEL: &str = "kobe.kunobi.ninja/requester-hash";
const SANDBOX_POOL_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool";
const SANDBOX_ALIAS_LABEL: &str = "kobe.kunobi.ninja/alias";
const SANDBOX_POOL_CRD: &str = "sandboxpools.kobe.kunobi.ninja";
const SANDBOX_LEASE_CRD: &str = "sandboxleases.kobe.kunobi.ninja";
/// Executions are a third CRD, and a staged upgrade can have the lease CRD
/// installed without it. Required explicitly on the execution paths so a
/// missing CRD is one legible error up front, rather than a 503 raised deep in
/// the reservation `create` — which is the failure `require_sandbox_crds`
/// exists to prevent in the first place.
const SANDBOX_EXECUTION_CRD: &str = "sandboxexecutions.kobe.kunobi.ninja";

/// Prefix on every server-minted lease id.
///
/// Shared with the resolver's shape check rather than written at both sites:
/// written twice, they disagreed, and every operation addressed by id fell
/// through to alias resolution and 404'd.
pub(crate) const LEASE_ID_PREFIX: &str = "sandbox-";
pub(crate) const SANDBOX_RESERVATION_TYPE_LABEL: &str = "kobe.kunobi.ninja/sandbox-reservation";
pub(crate) const SANDBOX_RESERVATION_LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-uid";
pub(crate) const SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION: &str =
    "kobe.kunobi.ninja/sandbox-lease-name";
pub(crate) const SANDBOX_RESERVATIONS_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-reservations";
const SANDBOX_RESERVATION_QUOTA: &str = "quota";
const SANDBOX_RESERVATION_ALIAS: &str = "alias";
const MAX_SANDBOX_CONCURRENCY_SLOTS: u32 = 256;
/// Server-owned admission gate. Placement controllers must ignore every lease
/// unless this annotation has the exact `admitted` value.
pub(crate) const SANDBOX_ADMISSION_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-admission";
pub(crate) const SANDBOX_ADMISSION_PENDING: &str = "pending";
pub(crate) const SANDBOX_ADMISSION_ADMITTED: &str = "admitted";
/// Durable loser of the pending-to-admitted arbitration.
///
/// The reaper writes this value with the same UID/resourceVersion/state CAS as
/// admission. Once it lands, an old handler can no longer make the lease
/// placeable, even if that handler was paused when its wall-clock budget ran
/// out and resumes later.
const SANDBOX_ADMISSION_CANCELLED: &str = "cancelled";
/// Server-owned release intent. Controllers own status transitions and observe
/// this annotation with the same object resourceVersion fence.
pub(crate) const SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION: &str =
    "kobe.kunobi.ninja/sandbox-release-requested-at";

/// Build the caller-authenticated Sandbox lease routes.
pub fn routes<B: ClusterBackend + Clone + 'static>() -> Router<AppState<B>> {
    Router::new()
        .route(
            "/v1/sandbox-leases",
            post(create_sandbox_lease::<B>).get(list_sandbox_leases::<B>),
        )
        .route(
            "/v1/sandbox-leases/{id}",
            get(get_sandbox_lease::<B>).delete(release_sandbox_lease::<B>),
        )
        .route("/v1/sandbox-leases/{id}/logs", get(sandbox_logs::<B>))
        .route("/v1/sandbox-leases/{id}/exec", post(sandbox_exec::<B>))
        .route("/v1/sandbox-leases/{id}/attach", get(sandbox_attach::<B>))
        .route(
            "/v1/sandbox-leases/{id}/port-forward",
            get(sandbox_port_forward::<B>),
        )
        .route(
            "/v1/sandbox-leases/{id}/executions",
            post(create_sandbox_execution::<B>),
        )
        .route(
            "/v1/sandbox-leases/{id}/executions/{execution}",
            get(get_sandbox_execution::<B>).delete(cancel_sandbox_execution::<B>),
        )
        .route(
            "/v1/sandbox-leases/{id}/executions/{execution}/logs",
            get(get_sandbox_execution_logs::<B>),
        )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateExecutionRequest {
    command: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    container: Option<String>,
    /// Required. Without it there is no way to tell a retry from a second
    /// command, and every disconnect becomes a potential duplicate.
    idempotency_key: String,
    /// Return once reserved rather than waiting for the result.
    #[serde(default)]
    detach: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionResponse {
    id: String,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Present only in wait mode, and kept distinct — a caller that cannot
    /// separate a tool's diagnostics from its output cannot parse either.
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}

fn execution_response(
    execution: &crate::crd::SandboxExecution,
    output: Option<crate::api::sandbox_access::SandboxExecResponse>,
) -> ExecutionResponse {
    let status = execution.status.clone().unwrap_or_default();
    ExecutionResponse {
        id: execution.name_any(),
        state: status.state.to_string(),
        exit_code: status.exit_code,
        started_at: status.started_at,
        finished_at: status.finished_at,
        reason: status.reason,
        stdout: output.as_ref().map(|output| output.stdout.clone()),
        stderr: output.as_ref().map(|output| output.stderr.clone()),
        truncated: output.is_some_and(|output| output.truncated),
    }
}

/// Whether a reused POST may return its record immediately.
///
/// Detached requests are handle-based and return `202` while active. Legacy
/// raw wait-mode records have no runner output to recover. A current
/// runner-managed wait request returns `None` so the handler resumes polling or
/// reads its retained terminal output instead of silently returning empty
/// streams after a lost HTTP response.
fn reused_execution_response_status(
    execution: &crate::crd::SandboxExecution,
) -> Option<StatusCode> {
    let current = execution
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if execution.spec.detached {
        return Some(if current.is_terminal() {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        });
    }
    (!execution_is_runner_managed(&execution.spec)).then_some(StatusCode::OK)
}

fn execution_denied(
    identity: &AuthIdentity,
    lease: &str,
    error: &crate::api::sandbox_executions::ExecutionRequestError,
) -> Response {
    info!(
        principal = %identity.identity,
        lease = %lease,
        operation = "execution",
        outcome = "denied",
        reason = error.reason_code(),
        "Sandbox access"
    );
    let status = error.http_status();
    if status == StatusCode::NOT_FOUND {
        return StatusCode::NOT_FOUND.into_response();
    }
    sandbox_error(status, error.to_string(), None)
}

/// Reserve and run one durable, idempotent command.
///
/// The reservation happens BEFORE anything is spawned. Spawning first and
/// recording afterwards is the obvious implementation, and it is wrong in the
/// case that matters: a crash between the two leaves no trace that anything
/// ran, so the retry runs it again.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn create_sandbox_execution<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Json(request): Json<CreateExecutionRequest>,
) -> Response {
    use crate::api::sandbox_access as access;
    use crate::api::sandbox_credentials as credentials;
    use crate::api::sandbox_executions as executions;
    use crate::crd::ExecutionState;

    if let Err(response) =
        require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD, SANDBOX_EXECUTION_CRD]).await
    {
        return response;
    }
    if !is_valid_k8s_name(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "execution", denied),
        };
    let container = match target.resolve_container(request.container.as_deref()) {
        Ok(container) => container.to_string(),
        Err(denied) => return access_denied(&identity, &id, "execution", denied),
    };

    let requested = executions::ExecutionRequest {
        argv: request.command,
        cwd: request.cwd,
        timeout: request
            .timeout
            .unwrap_or_else(|| DEFAULT_EXECUTION_TIMEOUT.to_string()),
        idempotency_key: request.idempotency_key,
        detached: request.detach,
    };

    // The runner is the execution contract, not just a detached-mode helper.
    // Raw Kubernetes exec cannot apply `cwd` without a shell, cannot supervise
    // a process group, and does not always expose an exact exit code. Falling
    // back would silently weaken the same API depending on pool image.
    //
    // Checked BEFORE the reservation, so a pool that cannot serve the request
    // does not leave the caller's idempotency key spent on an execution that
    // never existed.
    if target.runner_path.is_none() {
        return sandbox_error(
            StatusCode::NOT_IMPLEMENTED,
            "This Sandbox pool does not provide the Kobe runner",
            Some("Durable execution requires a pool whose template sets runnerPath.".into()),
        );
    }
    if let Err(error) = executions::validate_request(&requested) {
        return execution_denied(&identity, &id, &error);
    }
    let requested_timeout = crate::pool::parse_duration(&requested.timeout)
        .and_then(|timeout| timeout.to_std().ok())
        .expect("validated execution timeout must parse");
    let initial_timeout =
        match executions::effective_timeout(requested_timeout, &lease, chrono::Utc::now()) {
            Ok(timeout) => timeout,
            Err(error) => return execution_denied(&identity, &id, &error),
        };

    // The same encoded-byte ceiling is enforced by the runner. Prove it before
    // registration, capacity CAS, or CR creation so an oversized command cannot
    // spend an idempotency key on something the target must reject.
    let candidate_execution =
        crate::crd::execution_name(&target.lease_uid, &requested.idempotency_key);
    let candidate_start = crate::api::sandbox_runner::start_request(
        &candidate_execution,
        &requested.argv,
        requested.cwd.as_deref(),
        initial_timeout,
    );
    if crate::api::sandbox_runner::start_line(&candidate_start).is_err() {
        return execution_denied(
            &identity,
            &id,
            &executions::ExecutionRequestError::Invalid { what: "command" },
        );
    }

    // Register before reserving capacity or creating the execution object.
    // Release closes this same gate and cannot observe it drained while a
    // CREATE/bind request is still in flight. Registering later would leave a
    // window in which teardown clears the execution manifest, then the delayed
    // request creates a finalised record after absence was already certified.
    let guard = match register_live_stream(&state, &lease, &target).await {
        Ok(guard) => guard,
        Err(denied) => {
            return stream_registration_denied(&identity, &id, "execution", denied);
        }
    };
    let revoked = guard.cancelled();

    let reservation_deadline =
        tokio::time::Instant::now() + executions::EXECUTION_RESERVATION_TIMEOUT;
    let reservation = match executions::reserve_execution(
        &state.client,
        &state.namespace,
        &state.sandbox_reservation_namespace,
        &lease,
        &target,
        &container,
        &requested,
        reservation_deadline,
        &state.shutdown,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => return execution_denied(&identity, &id, &error),
    };

    let (reserved, fresh) = match reservation {
        // Somebody already reserved this exact request. Detached callers keep
        // the handle/poll contract. Wait callers resume observing the same
        // runner record below; they never spawn it again, but a lost response
        // must not turn exact retained output into an empty successful result.
        executions::Reservation::AlreadyExists(existing) => {
            info!(
                principal = %identity.identity,
                lease = %id,
                execution = %existing.name_any(),
                operation = "execution",
                outcome = "deduplicated",
                "Sandbox access"
            );
            if let Some(status) = reused_execution_response_status(&existing) {
                return (status, Json(execution_response(&existing, None))).into_response();
            }
            (existing, false)
        }
        executions::Reservation::Reserved(reserved) => (reserved, true),
        executions::Reservation::Pending(pending) => {
            info!(
                principal = %identity.identity,
                lease = %id,
                execution = %pending.name_any(),
                operation = "execution",
                outcome = "creation_pending",
                "Sandbox access"
            );
            return (
                StatusCode::ACCEPTED,
                Json(execution_response(&pending, None)),
            )
                .into_response();
        }
    };

    // Belt and braces: a reservation that is not fresh must never spawn, even
    // though `Reserved` is fresh by construction. The cost of the check is
    // nothing; the cost of the case it guards is a duplicate `terraform apply`.
    if fresh && !executions::may_spawn(&reserved) {
        return sandbox_error(
            StatusCode::CONFLICT,
            "This execution has already been started",
            None,
        );
    }

    // Registration and its exact lease re-read precede target resolution and
    // every durable mutation as well as TokenRequest. A release event that
    // already passed can therefore never reserve, create, or mint a fresh
    // credential, and an event racing setup cancels the network wait instead
    // of letting it complete under ended authority.
    let scoped = match scoped_client_after_registration(
        &state,
        &lease,
        &target,
        credentials::SandboxOperation::Exec,
        &revoked,
    )
    .await
    {
        Ok(client) => client,
        Err(ScopedSetupDenied::Access(denied)) => {
            if fresh {
                executions::record_terminal(
                    &state.client,
                    &state.namespace,
                    &reserved,
                    ExecutionState::Unknown,
                    None,
                    denied.reason_code(),
                )
                .await;
            }
            return access_denied(&identity, &id, "execution", denied);
        }
        Err(ScopedSetupDenied::Revoked) => {
            if fresh {
                executions::record_terminal(
                    &state.client,
                    &state.namespace,
                    &reserved,
                    ExecutionState::Cancelled,
                    None,
                    "lease_revoked_before_credential",
                )
                .await;
            }
            return stream_registration_denied(
                &identity,
                &id,
                "execution",
                StreamRegistrationDenied::LeaseEnded,
            );
        }
        Err(
            failure @ (ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout),
        ) => {
            if fresh {
                let reason = match failure {
                    ScopedSetupDenied::TargetTimeout => "target_setup_timeout",
                    ScopedSetupDenied::CredentialTimeout => "credential_setup_timeout",
                    _ => unreachable!("matched timeout variants above"),
                };
                executions::record_terminal(
                    &state.client,
                    &state.namespace,
                    &reserved,
                    ExecutionState::Unknown,
                    None,
                    reason,
                )
                .await;
            }
            return stream_registration_denied(
                &identity,
                &id,
                "execution",
                StreamRegistrationDenied::Backend,
            );
        }
    };

    if !fresh {
        return resume_wait_with_runner(
            &state, &identity, &id, &target, &container, &reserved, &scoped, revoked,
        )
        .await;
    }

    // Recompute after credential creation and stream registration. Authority
    // can expire while those network calls run; using the earlier remainder
    // would grant the runner time the lease no longer owns.
    let timeout = match executions::effective_timeout(requested_timeout, &lease, chrono::Utc::now())
    {
        Ok(timeout) => timeout,
        Err(error) => {
            executions::record_terminal(
                &state.client,
                &state.namespace,
                &reserved,
                ExecutionState::TimedOut,
                None,
                "lease_ttl_exhausted",
            )
            .await;
            return execution_denied(&identity, &id, &error);
        }
    };

    // Marked Running before the runner sees the request. From here on nothing
    // may spawn this key again, including after this process disappears.
    if executions::mark_running(&state.client, &state.namespace, &reserved, timeout)
        .await
        .is_err()
    {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Could not record the execution before starting it",
            None,
        );
    }

    run_with_runner(
        &state, &identity, &id, &target, &container, &requested, &reserved, &scoped, timeout,
        revoked,
    )
    .await
}

/// Default bound when a caller does not choose one.
const DEFAULT_EXECUTION_TIMEOUT: &str = "60s";

/// Hand one reserved execution to the runner, then either return its durable
/// handle or wait for the same supervised process.
///
/// Wait mode deliberately uses the same runner as detached mode. A raw exec
/// cannot implement `cwd` without a shell, cannot guarantee process-group
/// cancellation, and does not always expose an exact exit code. One supervisor
/// contract keeps those semantics identical; only the response timing differs.
///
/// * The runner answered — the execution is supervised, and the caller polls.
/// * Anything else — `Unknown`. The command may be running perfectly well
///   inside the container; Kobe simply cannot see it, and `Failed` would tell
///   the caller their retry is safe when it is not.
#[allow(clippy::too_many_arguments)]
async fn run_with_runner<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    requested: &crate::api::sandbox_executions::ExecutionRequest,
    reserved: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
    timeout: std::time::Duration,
    revoked: tokio_util::sync::CancellationToken,
) -> Response {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;
    use crate::crd::ExecutionState;

    let Some(runner_path) = target.runner_path.clone() else {
        // Refused before the reservation; reaching here means the pool changed
        // underneath this request.
        executions::record_terminal(
            &state.client,
            &state.namespace,
            reserved,
            ExecutionState::Unknown,
            None,
            "runner_unavailable",
        )
        .await;
        return sandbox_error(
            StatusCode::CONFLICT,
            "This Sandbox pool stopped providing the Kobe runner",
            None,
        );
    };

    // The execution's own name is the runner's id: derived by Kobe, stable
    // across retries, and — unlike anything the caller sent — safe to put in an
    // exec argument that the target apiserver will audit-log verbatim.
    let request = runner::start_request(
        &reserved.name_any(),
        &requested.argv,
        requested.cwd.as_deref(),
        timeout,
    );

    let started = tokio::select! {
        started = runner::start(
            scoped,
            target,
            container,
            &runner_path,
            &request,
            &state.shutdown,
        ) => started,
        _ = revoked.cancelled() => {
            // The lease stopped permitting access mid-start. Whether the runner
            // received the request is exactly the thing nobody can now say.
            executions::record_terminal(
                &state.client,
                &state.namespace,
                reserved,
                ExecutionState::Unknown,
                None,
                "lease_revoked",
            )
            .await;
            return sandbox_error(
                StatusCode::GONE,
                "Sandbox lease stopped permitting access while the command was starting",
                None,
            );
        }
    };

    let report = match started {
        Ok(report) => report,
        Err(failure) => {
            executions::record_terminal(
                &state.client,
                &state.namespace,
                reserved,
                ExecutionState::Unknown,
                None,
                failure.reason_code(),
            )
            .await;
            info!(
                principal = %identity.identity,
                lease = %id,
                execution = %reserved.name_any(),
                operation = "execution",
                outcome = "unknown",
                reason = failure.reason_code(),
                "Sandbox access"
            );
            return sandbox_error(failure.http_status(), failure.to_string(), None);
        }
    };

    if requested.detached {
        return runner_started_response(state, identity, id, reserved, &report).await;
    }

    complete_wait_mode(
        state,
        identity,
        id,
        target,
        container,
        reserved,
        scoped,
        &runner_path,
        report,
        revoked,
    )
    .await
}

/// Resume a wait-mode request after its first HTTP response was lost.
///
/// The durable record and runner id are reused exactly; this path never calls
/// `start`. A `Running` record resumes polling, while a terminal record reads
/// the retained streams so retrying cannot turn real output into empty output.
#[allow(clippy::too_many_arguments)]
async fn resume_wait_with_runner<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    record: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
    revoked: tokio_util::sync::CancellationToken,
) -> Response {
    use crate::api::sandbox_runner as runner;
    use crate::crd::ExecutionState;

    let current = record
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if current == ExecutionState::Queued {
        // Kobe durably reserved the key but never recorded a spawn. Reusing
        // must not manufacture one: Queued is the exact, retry-safe answer.
        return (StatusCode::OK, Json(execution_response(record, None))).into_response();
    }
    let Some(runner_path) = target.runner_path.clone() else {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "This runner-managed execution can no longer be reached",
            None,
        );
    };
    if current.is_terminal() {
        return wait_output_response(
            state,
            identity,
            id,
            target,
            container,
            record,
            scoped,
            &runner_path,
            revoked,
        )
        .await;
    }

    let polled = complete_before_revocation(
        &revoked,
        runner::poll(
            scoped,
            target,
            container,
            &runner_path,
            &record.name_any(),
            &state.shutdown,
        ),
    )
    .await;
    let report = match polled {
        Some(Ok(report)) => report,
        Some(Err(failure)) => {
            return sandbox_error(failure.http_status(), failure.to_string(), None);
        }
        None => {
            let cancelled = runner::cancel(
                scoped,
                target,
                container,
                &runner_path,
                &record.name_any(),
                &state.shutdown,
            )
            .await;
            record_revoked_outcome(state, record, cancelled).await;
            return sandbox_error(
                StatusCode::GONE,
                "Sandbox lease stopped permitting access; runner cancellation was requested",
                None,
            );
        }
    };

    complete_wait_mode(
        state,
        identity,
        id,
        target,
        container,
        record,
        scoped,
        &runner_path,
        report,
        revoked,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn complete_wait_mode<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    record: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
    runner_path: &str,
    report: kobe_runner::protocol::ExecutionReport,
    revoked: tokio_util::sync::CancellationToken,
) -> Response {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;

    let report = match wait_for_runner(
        scoped,
        target,
        container,
        runner_path,
        &record.name_any(),
        report,
        revoked.clone(),
        &state.shutdown,
    )
    .await
    {
        Ok(report) => report,
        Err(WaitRunnerFailure::Poll(failure)) => {
            // Start was acknowledged, so the command may still be running.
            // Keep `Running`: a later GET can reconcile it, whereas settling
            // Unknown here would discard a recoverable outcome.
            return sandbox_error(failure.http_status(), failure.to_string(), None);
        }
        Err(WaitRunnerFailure::Revoked(cancelled)) => {
            record_revoked_outcome(state, record, cancelled).await;
            return sandbox_error(
                StatusCode::GONE,
                "Sandbox lease stopped permitting access; runner cancellation was requested",
                None,
            );
        }
    };

    let outcome = runner::outcome_from_report(&report);
    let Some(durable) = executions::record_terminal(
        &state.client,
        &state.namespace,
        record,
        outcome.state,
        outcome.exit_code,
        &outcome.reason,
    )
    .await
    else {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "The runner outcome could not be committed",
            None,
        );
    };

    wait_output_response(
        state,
        identity,
        id,
        target,
        container,
        &durable,
        scoped,
        runner_path,
        revoked,
    )
    .await
}

async fn record_revoked_outcome<B: ClusterBackend>(
    state: &AppState<B>,
    record: &crate::crd::SandboxExecution,
    cancelled: Result<
        kobe_runner::protocol::ExecutionReport,
        crate::api::sandbox_runner::RunnerCallFailure,
    >,
) {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;

    let Ok(report) = cancelled else {
        // No terminal claim: teardown remains responsible for proving the
        // process group is gone.
        return;
    };
    let outcome = runner::outcome_from_report(&report);
    if outcome.state.is_terminal() {
        executions::record_terminal(
            &state.client,
            &state.namespace,
            record,
            outcome.state,
            outcome.exit_code,
            &outcome.reason,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_output_response<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    record: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
    runner_path: &str,
    revoked: tokio_util::sync::CancellationToken,
) -> Response {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;

    let output = complete_before_revocation(
        &revoked,
        runner::read_wait_output(
            scoped,
            target,
            container,
            runner_path,
            &record.name_any(),
            &state.shutdown,
        ),
    )
    .await;
    let output = match output {
        Some(Ok(output)) => output,
        Some(Err(failure)) => {
            // The outcome is durable and exact; output retrieval is a separate
            // transport failure and must not rewrite it to Unknown.
            return sandbox_error(failure.http_status(), failure.to_string(), None);
        }
        None => {
            return sandbox_error(
                StatusCode::GONE,
                "Sandbox lease stopped permitting access while execution output was read",
                None,
            );
        }
    };

    let refreshed = executions::refresh(&state.client, &state.namespace, record).await;
    let response_record = refreshed.unwrap_or_else(|| record.clone());
    let status = response_record.status.clone().unwrap_or_default();
    let output = crate::api::sandbox_access::SandboxExecResponse {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: status.state == crate::crd::ExecutionState::Succeeded,
        exit_code: status.exit_code,
        truncated: output.truncated,
    };
    info!(
        principal = %identity.identity,
        lease = %id,
        execution = %response_record.name_any(),
        operation = "execution",
        outcome = "allowed",
        state = %status.state,
        exit_code = ?status.exit_code,
        "Sandbox access"
    );
    (
        StatusCode::OK,
        Json(execution_response(&response_record, Some(output))),
    )
        .into_response()
}

/// Complete one bounded operation only while the lease still permits access.
///
/// Revocation is biased when both branches become ready together. Dropping the
/// operation future aborts an in-flight runner exec and prevents later log
/// chunks from being requested under a lease that has ended.
async fn complete_before_revocation<F>(
    revoked: &tokio_util::sync::CancellationToken,
    operation: F,
) -> Option<F::Output>
where
    F: std::future::Future,
{
    tokio::select! {
        biased;
        _ = revoked.cancelled() => None,
        output = operation => Some(output),
    }
}

async fn runner_started_response<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    reserved: &crate::crd::SandboxExecution,
    report: &kobe_runner::protocol::ExecutionReport,
) -> Response {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;

    let outcome = runner::outcome_from_report(report);
    let durable = if outcome.state.is_terminal() {
        let Some(durable) = executions::record_terminal(
            &state.client,
            &state.namespace,
            reserved,
            outcome.state,
            outcome.exit_code,
            &outcome.reason,
        )
        .await
        else {
            return sandbox_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The runner outcome could not be committed",
                None,
            );
        };
        Some(durable)
    } else {
        let Some(running) = executions::refresh(&state.client, &state.namespace, reserved).await
        else {
            return sandbox_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The running execution could not be re-read",
                None,
            );
        };
        Some(running)
    };
    let record = durable.as_ref().unwrap_or(reserved);
    info!(
        principal = %identity.identity,
        lease = %id,
        execution = %reserved.name_any(),
        operation = "execution",
        outcome = "detached",
        state = %outcome.state,
        "Sandbox access"
    );
    let status = if outcome.state.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    (status, Json(execution_response(record, None))).into_response()
}

enum WaitRunnerFailure {
    Poll(crate::api::sandbox_runner::RunnerCallFailure),
    Revoked(
        Result<
            kobe_runner::protocol::ExecutionReport,
            crate::api::sandbox_runner::RunnerCallFailure,
        >,
    ),
}

/// Wait for the runner without ever respawning the reserved command.
///
/// Lease revocation races every poll and invokes the runner's process-group
/// cancellation. A polling failure leaves the durable record Running so a
/// later GET can recover the answer; it never invents a terminal outcome.
#[allow(clippy::too_many_arguments)]
async fn wait_for_runner(
    scoped: &kube::Client,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    runner_path: &str,
    execution: &str,
    mut report: kobe_runner::protocol::ExecutionReport,
    revoked: tokio_util::sync::CancellationToken,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<kobe_runner::protocol::ExecutionReport, WaitRunnerFailure> {
    use crate::api::sandbox_runner as runner;

    while !report.state.is_terminal() {
        tokio::select! {
            _ = revoked.cancelled() => {
                return Err(WaitRunnerFailure::Revoked(
                    runner::cancel(
                        scoped, target, container, runner_path, execution, shutdown,
                    ).await,
                ));
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
        report = tokio::select! {
            polled = runner::poll(
                scoped, target, container, runner_path, execution, shutdown,
            ) => {
                polled.map_err(WaitRunnerFailure::Poll)?
            }
            _ = revoked.cancelled() => {
                return Err(WaitRunnerFailure::Revoked(
                    runner::cancel(
                        scoped, target, container, runner_path, execution, shutdown,
                    ).await,
                ));
            }
        };
    }
    Ok(report)
}

/// Ask the runner what a supervised execution is doing, and settle it if it is
/// done.
///
/// Returns the record as it now stands. A runner that cannot be reached leaves
/// the record exactly as it was: a transient failure to poll is not evidence
/// about the command, and settling on it would turn a blip into a permanent
/// `Unknown` for a command that finished successfully a second later.
///
/// The one exception is a runner that has *no record* of an execution Kobe
/// reserved. That means the container was replaced under a Pod that kept its
/// identity, and the outcome is genuinely unrecoverable — so it settles as
/// `Unknown` immediately. Wall-clock age alone never settles a running command.
async fn reconcile_runner<B: ClusterBackend>(
    state: &AppState<B>,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    runner_path: &str,
    record: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
) -> crate::crd::SandboxExecution {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;
    use kobe_runner::protocol::RunnerErrorCode;

    let current = record
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if current.is_terminal() {
        return record.clone();
    }
    let polled = runner::poll(
        scoped,
        target,
        container,
        runner_path,
        &record.name_any(),
        &state.shutdown,
    )
    .await;

    let outcome = match polled {
        Ok(report) => runner::outcome_from_report(&report),
        Err(runner::RunnerCallFailure::Refused(RunnerErrorCode::NotFound)) => {
            runner::RunnerOutcome {
                state: crate::crd::ExecutionState::Unknown,
                exit_code: None,
                reason: "runner_forgot_execution".into(),
            }
        }
        // Nothing was learned. The record keeps saying `Running`; wall clock is
        // not evidence that the process group stopped.
        Err(_) => return record.clone(),
    };
    if !outcome.state.is_terminal() {
        return record.clone();
    }

    executions::record_terminal(
        &state.client,
        &state.namespace,
        record,
        outcome.state,
        outcome.exit_code,
        &outcome.reason,
    )
    .await
    .unwrap_or_else(|| record.clone())
}

#[tracing::instrument(skip_all, fields(lease = %id))]
async fn get_sandbox_execution<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path((id, execution)): Path<(String, String)>,
) -> Response {
    use crate::api::sandbox_access as access;

    if let Err(response) =
        require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD, SANDBOX_EXECUTION_CRD]).await
    {
        return response;
    }
    if !is_valid_k8s_name(&id) || !is_valid_k8s_name(&execution) {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Ownership of the LEASE is what authorises reading its executions. An
    // execution name alone must never be enough: they are derived from a caller's
    // own key, so a second caller could otherwise guess one.
    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "execution", denied),
        };

    match crate::api::sandbox_executions::get_owned(
        &state.client,
        &state.namespace,
        &execution,
        &target.lease_uid,
    )
    .await
    {
        Ok(Some(record)) => {
            let runner_address = match crate::api::sandbox_executions::execution_runner_address(
                &record.spec,
                &target,
            ) {
                Ok(address) => address,
                Err("execution_runner_missing") => {
                    return sandbox_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "This runner-managed execution can no longer be reached",
                        None,
                    );
                }
                Err(_) => {
                    return sandbox_error(
                        StatusCode::GONE,
                        "This execution belonged to a replaced Sandbox runner",
                        None,
                    );
                }
            };
            // Current executions are runner-supervised in both modes. Legacy
            // raw wait records are not: polling their id against the runner
            // would turn a valid pre-upgrade Running record into Unknown.
            let record = if execution_is_runner_managed(&record.spec)
                && !record
                    .status
                    .as_ref()
                    .is_some_and(|status| status.state.is_terminal())
            {
                let Some((container, runner_path)) = runner_address.as_ref() else {
                    return sandbox_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "This runner-managed execution can no longer be reached",
                        None,
                    );
                };
                let guard = match register_live_stream(&state, &lease, &target).await {
                    Ok(guard) => guard,
                    Err(denied) => {
                        return stream_registration_denied(&identity, &id, "execution", denied);
                    }
                };
                let revoked = guard.cancelled();
                let scoped = match scoped_client_after_registration(
                    &state,
                    &lease,
                    &target,
                    crate::api::sandbox_credentials::SandboxOperation::Exec,
                    &revoked,
                )
                .await
                {
                    Ok(scoped) => scoped,
                    Err(ScopedSetupDenied::Access(denied)) => {
                        return access_denied(&identity, &id, "execution", denied);
                    }
                    Err(ScopedSetupDenied::Revoked) => {
                        return stream_registration_denied(
                            &identity,
                            &id,
                            "execution",
                            StreamRegistrationDenied::LeaseEnded,
                        );
                    }
                    Err(
                        ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout,
                    ) => {
                        return stream_registration_denied(
                            &identity,
                            &id,
                            "execution",
                            StreamRegistrationDenied::Backend,
                        );
                    }
                };
                match complete_before_revocation(
                    &revoked,
                    reconcile_runner(&state, &target, container, runner_path, &record, &scoped),
                )
                .await
                {
                    Some(record) => record,
                    None => {
                        return stream_registration_denied(
                            &identity,
                            &id,
                            "execution",
                            StreamRegistrationDenied::LeaseEnded,
                        );
                    }
                }
            } else {
                record
            };
            (StatusCode::OK, Json(execution_response(&record, None))).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => execution_denied(&identity, &id, &error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionLogsQuery {
    /// Where to resume each stream. Separate, because the two streams advance
    /// independently — one offset for both would re-read whichever stream was
    /// behind, or skip whichever was ahead.
    #[serde(default)]
    stdout_offset: Option<u64>,
    #[serde(default)]
    stderr_offset: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionStreamWindow {
    data: String,
    /// Where the next read should start. A caller that polls with this value
    /// sees every byte exactly once, which is what makes a detached
    /// execution's output reconnectable after a disconnect.
    next_offset: u64,
    /// Whether bytes are already waiting past `next_offset`.
    more: bool,
    /// Whether the runner dropped output at its retention cap. Unlike `more`,
    /// this is unrecoverable — and a caller parsing a capped stream as
    /// complete is how a bound becomes a wrong answer.
    truncated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionLogsResponse {
    id: String,
    state: String,
    stdout: ExecutionStreamWindow,
    stderr: ExecutionStreamWindow,
}

/// Read one runner-supervised execution's retained output.
///
/// Wait mode returns these bytes inline, but they remain addressable so a
/// client disconnected after completion can recover them without rerunning the
/// command. Detached mode uses the same offset contract for tailing.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn get_sandbox_execution_logs<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path((id, execution)): Path<(String, String)>,
    Query(query): Query<ExecutionLogsQuery>,
) -> Response {
    use crate::api::sandbox_access as access;
    use crate::api::sandbox_runner as runner;
    use kobe_runner::protocol::LogStream;

    if let Err(response) =
        require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD, SANDBOX_EXECUTION_CRD]).await
    {
        return response;
    }
    if !is_valid_k8s_name(&id) || !is_valid_k8s_name(&execution) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "execution-logs", denied),
        };
    let record = match crate::api::sandbox_executions::get_owned(
        &state.client,
        &state.namespace,
        &execution,
        &target.lease_uid,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return execution_denied(&identity, &id, &error),
    };

    if !execution_is_runner_managed(&record.spec) {
        return sandbox_error(
            StatusCode::CONFLICT,
            "Retained output is unavailable for this legacy wait-mode execution",
            None,
        );
    }

    let (container, runner_path) =
        match crate::api::sandbox_executions::execution_runner_address(&record.spec, &target) {
            Ok(Some(address)) => address,
            Ok(None) => {
                return sandbox_error(
                    StatusCode::CONFLICT,
                    "Retained output is unavailable for this legacy execution",
                    None,
                );
            }
            Err("execution_runner_missing") => {
                return sandbox_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "This runner-managed execution can no longer be reached",
                    None,
                );
            }
            Err(_) => {
                return sandbox_error(
                    StatusCode::GONE,
                    "This execution belonged to a replaced Sandbox runner",
                    None,
                );
            }
        };

    // Output reads are live operations too. Holding a guard ensures release,
    // expiry, or quarantine interrupts every runner call below rather than
    // allowing a second stream read under authority that has ended.
    let guard = match register_live_stream(&state, &lease, &target).await {
        Ok(guard) => guard,
        Err(denied) => {
            return stream_registration_denied(&identity, &id, "execution-logs", denied);
        }
    };
    let revoked = guard.cancelled();

    let scoped = match scoped_client_after_registration(
        &state,
        &lease,
        &target,
        crate::api::sandbox_credentials::SandboxOperation::Exec,
        &revoked,
    )
    .await
    {
        Ok(client) => client,
        Err(ScopedSetupDenied::Access(denied)) => {
            return access_denied(&identity, &id, "execution-logs", denied);
        }
        Err(ScopedSetupDenied::Revoked) => {
            return stream_registration_denied(
                &identity,
                &id,
                "execution-logs",
                StreamRegistrationDenied::LeaseEnded,
            );
        }
        Err(ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout) => {
            return stream_registration_denied(
                &identity,
                &id,
                "execution-logs",
                StreamRegistrationDenied::Backend,
            );
        }
    };

    // Polled first, so the state reported alongside the output is the one that
    // was true when the output was read — not the one Kobe last wrote. Legacy
    // raw records were refused above, so this id is always runner-owned.
    let record = match complete_before_revocation(
        &revoked,
        reconcile_runner(&state, &target, &container, &runner_path, &record, &scoped),
    )
    .await
    {
        Some(record) => record,
        None => {
            return runner_output_revoked_response(
                &state,
                &record,
                &scoped,
                &target,
                &container,
                &runner_path,
            )
            .await;
        }
    };

    let mut windows = Vec::new();
    for (stream, offset) in [
        (LogStream::Stdout, query.stdout_offset.unwrap_or(0)),
        (LogStream::Stderr, query.stderr_offset.unwrap_or(0)),
    ] {
        let read = complete_before_revocation(
            &revoked,
            runner::read_output(
                &scoped,
                &target,
                &container,
                &runner_path,
                &record.name_any(),
                stream,
                offset,
                &state.shutdown,
            ),
        )
        .await;
        match read {
            Some(Ok(chunk)) => windows.push(chunk),
            Some(Err(failure)) => {
                info!(
                    principal = %identity.identity,
                    lease = %id,
                    execution = %record.name_any(),
                    operation = "execution-logs",
                    outcome = "denied",
                    reason = failure.reason_code(),
                    "Sandbox access"
                );
                return sandbox_error(failure.http_status(), failure.to_string(), None);
            }
            None => {
                return runner_output_revoked_response(
                    &state,
                    &record,
                    &scoped,
                    &target,
                    &container,
                    &runner_path,
                )
                .await;
            }
        }
    }

    let window = |chunk: &crate::api::sandbox_runner::RunnerLogChunk| {
        ExecutionStreamWindow {
            // Lossy on purpose: a sandboxed command's output is arbitrary
            // bytes, and refusing the window because one of them was not UTF-8
            // would lose all the ones that were.
            data: String::from_utf8_lossy(&chunk.bytes).into_owned(),
            next_offset: chunk.next_offset,
            more: chunk.more,
            truncated: chunk.truncated,
        }
    };
    // Audited by identity and outcome, never by content: the body is the
    // workload's own output and can contain anything.
    info!(
        principal = %identity.identity,
        lease = %id,
        execution = %record.name_any(),
        pod_uid = %target.pod_uid,
        operation = "execution-logs",
        outcome = "allowed",
        "Sandbox access"
    );
    (
        StatusCode::OK,
        Json(ExecutionLogsResponse {
            id: record.name_any(),
            state: record
                .status
                .as_ref()
                .map(|status| status.state)
                .unwrap_or_default()
                .to_string(),
            stdout: window(&windows[0]),
            stderr: window(&windows[1]),
        }),
    )
        .into_response()
}

/// Stop a still-active supervised execution when output access is revoked.
///
/// Terminal executions need no cancellation. For an active one, the only
/// runner call permitted after revocation is the process-group cancellation;
/// its confirmed result is persisted before the caller receives `410 Gone`.
async fn runner_output_revoked_response<B: ClusterBackend>(
    state: &AppState<B>,
    record: &crate::crd::SandboxExecution,
    scoped: &kube::Client,
    target: &crate::api::sandbox_access::SandboxTarget,
    container: &str,
    runner_path: &str,
) -> Response {
    let current = record
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if !current.is_terminal() {
        let cancelled = crate::api::sandbox_runner::cancel(
            scoped,
            target,
            container,
            runner_path,
            &record.name_any(),
            &state.shutdown,
        )
        .await;
        record_revoked_outcome(state, record, cancelled).await;
    }
    sandbox_error(
        StatusCode::GONE,
        "Sandbox lease stopped permitting access while execution output was read",
        None,
    )
}

/// Cancel one execution.
///
/// For every runner-supervised execution this is a real termination: the runner signals the
/// process **group**, so a build script that spawned four compilers and exited
/// does not leave them running on CPU the lease is paying for.
///
/// The record-only fallback exists solely for pre-runner wait-mode records. New
/// wait and detached requests both take the supervised path.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn cancel_sandbox_execution<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path((id, execution)): Path<(String, String)>,
) -> Response {
    use crate::api::sandbox_access as access;

    if let Err(response) =
        require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD, SANDBOX_EXECUTION_CRD]).await
    {
        return response;
    }
    if !is_valid_k8s_name(&id) || !is_valid_k8s_name(&execution) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "execution", denied),
        };

    // Cancellation reaches the same Pod and runner as execution/log reads, so
    // it must enter the same distributed gate. Otherwise it could resolve a
    // Ready lease, race a release that observes an empty gate, and mint a new
    // credential while teardown is already removing the target.
    let guard = match register_live_stream(&state, &lease, &target).await {
        Ok(guard) => guard,
        Err(denied) => {
            return stream_registration_denied(&identity, &id, "execution-cancel", denied);
        }
    };
    let revoked = guard.cancelled();

    match cancel_runner(
        &state, &identity, &id, &lease, &target, &execution, &revoked,
    )
    .await
    {
        RunnerCancellation::NotRunnerManaged => {}
        RunnerCancellation::Handled(response) => return response,
    }

    match crate::api::sandbox_executions::cancel_owned(
        &state.client,
        &state.namespace,
        &execution,
        &target.lease_uid,
    )
    .await
    {
        Ok(Some(record)) => {
            (StatusCode::OK, Json(execution_response(&record, None))).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => execution_denied(&identity, &id, &error),
    }
}

/// Terminate a runner-supervised execution's process group, if this is one.
///
/// Only [`RunnerCancellation::NotRunnerManaged`] lets a legacy wait-mode record
/// fall through to record-only cancellation. Every new execution requires the
/// runner, so missing runner/target/credential proof keeps it Running rather
/// than pretending its process group stopped.
///
/// A runner that cannot be reached does **not** settle the record. Recording
/// `Cancelled` would claim a termination nobody performed, and recording
/// `Unknown` would close a record whose command is very likely still running —
/// leaving it `Running` keeps the caller's retry meaningful, and lease teardown
/// remains the backstop that always ends it.
enum RunnerCancellation {
    NotRunnerManaged,
    Handled(Response),
}

/// Whether cancellation must be confirmed by `kobe-runner`.
///
/// New records state this explicitly because wait and detached mode are both
/// supervised. Legacy records predate that field: detached executions used the
/// runner, while wait-mode executions used raw Kubernetes exec and may use the
/// record-only fallback.
fn execution_is_runner_managed(spec: &crate::crd::SandboxExecutionSpec) -> bool {
    spec.runner_managed.unwrap_or(spec.detached)
}

async fn cancel_runner<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    lease: &SandboxLease,
    target: &crate::api::sandbox_access::SandboxTarget,
    execution: &str,
    revoked: &tokio_util::sync::CancellationToken,
) -> RunnerCancellation {
    use crate::api::sandbox_executions as executions;
    use crate::api::sandbox_runner as runner;

    let record = match executions::get_owned(
        &state.client,
        &state.namespace,
        execution,
        &target.lease_uid,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return RunnerCancellation::Handled(StatusCode::NOT_FOUND.into_response());
        }
        Err(error) => {
            return RunnerCancellation::Handled(execution_denied(identity, id, &error));
        }
    };
    let current = record
        .status
        .as_ref()
        .map(|status| status.state)
        .unwrap_or_default();
    if current.is_terminal() {
        return RunnerCancellation::Handled(
            (StatusCode::OK, Json(execution_response(&record, None))).into_response(),
        );
    }
    let (container, runner_path) = match executions::execution_runner_address(&record.spec, target)
    {
        Ok(Some(address)) => address,
        Ok(None) if !execution_is_runner_managed(&record.spec) => {
            return RunnerCancellation::NotRunnerManaged;
        }
        Ok(None) => {
            return RunnerCancellation::Handled(access_denied_with(
                identity,
                id,
                "execution-cancel",
                "runner_missing",
                StatusCode::SERVICE_UNAVAILABLE,
                "Runner-supervised execution termination could not be confirmed",
            ));
        }
        Err("execution_runner_missing") => {
            return RunnerCancellation::Handled(access_denied_with(
                identity,
                id,
                "execution-cancel",
                "runner_missing",
                StatusCode::SERVICE_UNAVAILABLE,
                "Runner-supervised execution termination could not be confirmed",
            ));
        }
        Err(_) => {
            return RunnerCancellation::Handled(sandbox_error(
                StatusCode::GONE,
                "This execution belonged to a replaced Sandbox runner",
                None,
            ));
        }
    };

    let scoped = match scoped_client_after_registration(
        state,
        lease,
        target,
        crate::api::sandbox_credentials::SandboxOperation::Exec,
        revoked,
    )
    .await
    {
        Ok(scoped) => scoped,
        Err(ScopedSetupDenied::Access(denied)) => {
            return RunnerCancellation::Handled(access_denied(
                identity,
                id,
                "execution-cancel",
                denied,
            ));
        }
        Err(ScopedSetupDenied::Revoked) => {
            return RunnerCancellation::Handled(stream_registration_denied(
                identity,
                id,
                "execution-cancel",
                StreamRegistrationDenied::LeaseEnded,
            ));
        }
        Err(ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout) => {
            return RunnerCancellation::Handled(stream_registration_denied(
                identity,
                id,
                "execution-cancel",
                StreamRegistrationDenied::Backend,
            ));
        }
    };

    let cancelled = complete_before_revocation(
        revoked,
        runner::cancel(
            &scoped,
            target,
            &container,
            &runner_path,
            &record.name_any(),
            &state.shutdown,
        ),
    )
    .await;
    match cancelled {
        None => RunnerCancellation::Handled(stream_registration_denied(
            identity,
            id,
            "execution-cancel",
            StreamRegistrationDenied::LeaseEnded,
        )),
        Some(Ok(report)) => {
            let outcome = runner::outcome_from_report(&report);
            if !outcome.state.is_terminal() {
                // The runner answered without settling it. Saying "cancelled"
                // here would be Kobe's word for something the container did not
                // confirm.
                return RunnerCancellation::Handled(sandbox_error(
                    StatusCode::ACCEPTED,
                    "Cancellation was requested and has not completed yet",
                    None,
                ));
            }
            let Some(response_record) = executions::record_terminal(
                &state.client,
                &state.namespace,
                &record,
                outcome.state,
                outcome.exit_code,
                &outcome.reason,
            )
            .await
            else {
                return RunnerCancellation::Handled(sandbox_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The runner cancellation outcome could not be committed",
                    None,
                ));
            };
            info!(
                principal = %identity.identity,
                lease = %id,
                execution = %record.name_any(),
                operation = "execution-cancel",
                outcome = "allowed",
                state = %outcome.state,
                "Sandbox access"
            );
            RunnerCancellation::Handled(
                (
                    StatusCode::OK,
                    Json(execution_response(&response_record, None)),
                )
                    .into_response(),
            )
        }
        Some(Err(failure)) => {
            info!(
                principal = %identity.identity,
                lease = %id,
                execution = %record.name_any(),
                operation = "execution-cancel",
                outcome = "denied",
                reason = failure.reason_code(),
                "Sandbox access"
            );
            RunnerCancellation::Handled(sandbox_error(
                failure.http_status(),
                failure.to_string(),
                None,
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxAttachQuery {
    /// argv to run. Absent attaches to the container's existing process
    /// instead of starting a new one.
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    container: Option<String>,
    /// Allocate a terminal. Off by default: a TTY merges stderr into stdout
    /// and changes how the workload buffers, so it must be asked for.
    #[serde(default)]
    tty: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxPortForwardQuery {
    /// A pool-declared port name or number. Nothing else resolves.
    port: String,
}

/// Whether the Pod answering to the recorded name is still the recorded Pod.
///
/// Kubernetes permits name reuse, so a name that resolved at placement can
/// point at a different workload by the time a stream opens. Anything that
/// cannot confirm the identity is treated as a mismatch: "I could not check"
/// must not open a terminal.
async fn pod_identity_holds(
    pods: &kube::Api<k8s_openapi::api::core::v1::Pod>,
    target: &crate::api::sandbox_access::SandboxTarget,
) -> bool {
    use kube::ResourceExt;
    matches!(
        pods.get(&target.pod_name).await,
        Ok(pod) if pod.uid().as_deref() == Some(target.pod_uid.as_str())
    )
}

/// Everything an interactive operation needs, resolved before the upgrade.
///
/// Resolution happens *before* the WebSocket handshake completes on purpose:
/// a denial has to be an HTTP status the caller's client understands, not a
/// close frame delivered a moment after a successful-looking upgrade.
struct UpgradeContext {
    target: crate::api::sandbox_access::SandboxTarget,
    container: String,
    scoped: kube::Client,
    /// The registration claimed before the upgrade. Held here so the slot is
    /// never released between being taken and the stream starting.
    guard: crate::api::sandbox_streams::StreamGuard,
}

#[derive(Debug, Clone, Copy)]
enum StreamRegistrationDenied {
    LimitReached,
    LeaseEnded,
    Backend,
}

#[derive(Debug)]
enum ScopedSetupDenied {
    Access(crate::api::sandbox_access::SandboxAccessDenied),
    Revoked,
    TargetTimeout,
    CredentialTimeout,
}

/// Resolve the target cluster and mint the one-operation credential while the
/// caller already holds a confirmed stream registration.
///
/// Keeping the two network calls behind this helper pins their ordering: no
/// endpoint may mint a Pod credential before its lease has been re-read and
/// registered for revocation, and both calls stop if that authority ends.
async fn scoped_client_after_registration<B: ClusterBackend>(
    state: &AppState<B>,
    lease: &SandboxLease,
    target: &crate::api::sandbox_access::SandboxTarget,
    operation: crate::api::sandbox_credentials::SandboxOperation,
    revoked: &tokio_util::sync::CancellationToken,
) -> Result<kube::Client, ScopedSetupDenied> {
    use crate::api::sandbox_transport::{StreamEnd, bounded_setup};

    let cluster = match bounded_setup(
        crate::api::sandbox_access::resolve_target_cluster(
            &state.client,
            &state.namespace,
            lease,
            target,
        ),
        revoked,
    )
    .await
    {
        Ok(Ok(cluster)) => cluster,
        Ok(Err(denied)) => return Err(ScopedSetupDenied::Access(denied)),
        Err(StreamEnd::Revoked) => return Err(ScopedSetupDenied::Revoked),
        Err(_) => return Err(ScopedSetupDenied::TargetTimeout),
    };

    match bounded_setup(
        crate::api::sandbox_credentials::scoped_client(&cluster, target, operation),
        revoked,
    )
    .await
    {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(denied)) => Err(ScopedSetupDenied::Access(denied)),
        Err(StreamEnd::Revoked) => Err(ScopedSetupDenied::Revoked),
        Err(_) => Err(ScopedSetupDenied::CredentialTimeout),
    }
}

/// Claim a replica-local stream slot, then re-read the exact lease.
///
/// This helper is shared by interactive, one-shot, and durable execution so
/// none can register after its deletion/release watch event already passed.
async fn register_live_stream<B: ClusterBackend>(
    state: &AppState<B>,
    lease: &SandboxLease,
    target: &crate::api::sandbox_access::SandboxTarget,
) -> Result<crate::api::sandbox_streams::StreamGuard, StreamRegistrationDenied> {
    let leases: Api<SandboxLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let identity = crate::api::sandbox_streams::StreamIdentity::from_ready_lease(lease)
        .ok_or(StreamRegistrationDenied::LeaseEnded)?;
    let distributed = if let Some(replica) = state.sandbox_serving_replica.as_ref() {
        match crate::sandbox_access_ledger::acquire(
            &state.client,
            &state.sandbox_reservation_namespace,
            lease,
            &identity.principal_key(),
            replica,
        )
        .await
        {
            Ok(crate::sandbox_access_ledger::AccessAcquire::Acquired(guard)) => Some(*guard),
            Ok(crate::sandbox_access_ledger::AccessAcquire::LeaseClosed) => {
                return Err(StreamRegistrationDenied::LeaseEnded);
            }
            Ok(crate::sandbox_access_ledger::AccessAcquire::LimitReached) => {
                return Err(StreamRegistrationDenied::LimitReached);
            }
            Err(error) => {
                tracing::warn!(error = %error, lease = %lease.name_any(), "could not acquire distributed Sandbox access slot");
                return Err(StreamRegistrationDenied::Backend);
            }
        }
    } else {
        #[cfg(not(test))]
        return Err(StreamRegistrationDenied::Backend);
        #[cfg(test)]
        None
    };
    match crate::api::sandbox_streams::register_confirmed(
        crate::api::sandbox_streams::registry(),
        &leases,
        &lease.name_any(),
        &target.lease_uid,
        &identity,
    )
    .await
    {
        Ok(crate::api::sandbox_streams::ConfirmedStreamRegistration::Registered(guard)) => {
            Ok(match distributed {
                Some(distributed) => (*guard).with_distributed(distributed),
                None => *guard,
            })
        }
        Ok(crate::api::sandbox_streams::ConfirmedStreamRegistration::LimitReached) => {
            Err(StreamRegistrationDenied::LimitReached)
        }
        Ok(crate::api::sandbox_streams::ConfirmedStreamRegistration::LeaseEnded) => {
            Err(StreamRegistrationDenied::LeaseEnded)
        }
        Err(_) => Err(StreamRegistrationDenied::Backend),
    }
}

fn stream_registration_denied(
    identity: &AuthIdentity,
    id: &str,
    operation: &'static str,
    denied: StreamRegistrationDenied,
) -> Response {
    match denied {
        StreamRegistrationDenied::LimitReached => access_denied_with(
            identity,
            id,
            operation,
            "concurrency_limit",
            StatusCode::TOO_MANY_REQUESTS,
            "Too many concurrent Sandbox operations",
        ),
        StreamRegistrationDenied::LeaseEnded => access_denied_with(
            identity,
            id,
            operation,
            "lease_ended",
            StatusCode::CONFLICT,
            "Sandbox lease stopped permitting access",
        ),
        StreamRegistrationDenied::Backend => access_denied_with(
            identity,
            id,
            operation,
            "backend_error",
            StatusCode::SERVICE_UNAVAILABLE,
            "Sandbox lease could not be revalidated",
        ),
    }
}

async fn prepare_upgrade<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
    id: &str,
    operation: crate::api::sandbox_credentials::SandboxOperation,
    requested_container: Option<&str>,
) -> Result<UpgradeContext, Response> {
    use crate::api::sandbox_access as access;

    require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await?;
    if !is_valid_k8s_name(id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }

    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, id, identity).await {
            Ok(resolved) => resolved,
            Err(denied) => return Err(access_denied(identity, id, operation.as_str(), denied)),
        };
    let container = match target.resolve_container(requested_container) {
        Ok(container) => container.to_string(),
        Err(denied) => return Err(access_denied(identity, id, operation.as_str(), denied)),
    };
    // Registered here, not merely checked. Asking "am I under the limit?" and
    // registering afterwards lets every concurrent upgrade pass a limit none of
    // them has taken yet. The slot is claimed before the upgrade so a caller
    // over the limit gets a status rather than a socket that closes at once,
    // and the guard travels with the context so the claim cannot be dropped in
    // between.
    let guard = register_live_stream(state, &lease, &target)
        .await
        .map_err(|denied| stream_registration_denied(identity, id, operation.as_str(), denied))?;
    let revoked = guard.cancelled();

    // Both placements go through the same resolution. Child composition
    // changes which cluster the Pod is in; it changes nothing about what the
    // caller may do, which is the equivalence #76 sets out to prove.
    let scoped =
        match scoped_client_after_registration(state, &lease, &target, operation, &revoked).await {
            Ok(client) => client,
            Err(ScopedSetupDenied::Access(denied)) => {
                return Err(access_denied(identity, id, operation.as_str(), denied));
            }
            Err(ScopedSetupDenied::Revoked) => {
                return Err(stream_registration_denied(
                    identity,
                    id,
                    operation.as_str(),
                    StreamRegistrationDenied::LeaseEnded,
                ));
            }
            Err(ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout) => {
                return Err(stream_registration_denied(
                    identity,
                    id,
                    operation.as_str(),
                    StreamRegistrationDenied::Backend,
                ));
            }
        };

    Ok(UpgradeContext {
        target,
        container,
        scoped,
        guard,
    })
}

/// Interactive exec or attach over a bounded WebSocket.
///
/// The caller's socket never reaches the API server: Kobe terminates it,
/// opens a separate connection with a credential scoped to one Pod, and copies
/// bytes. Nothing the caller sends becomes part of a Kubernetes request.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn sandbox_attach<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Query(query): Query<SandboxAttachQuery>,
    upgrade: axum::extract::WebSocketUpgrade,
) -> Response {
    use crate::api::sandbox_credentials::SandboxOperation;
    use crate::api::sandbox_transport as transport;

    if let Some(command) = query.command.as_ref()
        && (command.is_empty() || command.iter().any(String::is_empty))
    {
        return sandbox_error(
            StatusCode::BAD_REQUEST,
            "command must be non-empty argv",
            None,
        );
    }

    // The operation is chosen by which subresource this request will actually
    // call: `pods/exec` with a command, `pods/attach` without. Minting an exec
    // credential and then calling attach was a guaranteed 403 on a socket that
    // had already upgraded cleanly.
    let operation = if query.command.is_some() {
        SandboxOperation::Exec
    } else {
        SandboxOperation::Attach
    };
    let context = match prepare_upgrade(
        &state,
        &identity,
        &id,
        operation,
        query.container.as_deref(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };

    let principal = identity.identity.clone();
    upgrade.on_upgrade(move |mut socket| async move {
        let guard = context.guard;
        let revoked = guard.cancelled();

        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(context.scoped.clone(), &context.target.namespace);

        // The name resolved at placement; the identity must still match. A Pod
        // recycled under the same name is a different workload, and attaching a
        // terminal to it would put a caller's keystrokes into somebody else's
        // container. Logs and exec already recheck; this path did not.
        match transport::bounded_setup(pod_identity_holds(&pods, &context.target), &revoked).await {
            Ok(true) => {}
            Ok(false) | Err(transport::StreamEnd::TargetError) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
                return;
            }
            Err(end) => {
                transport::close_with(&mut socket, end).await;
                return;
            }
        }

        let params = kube::api::AttachParams::default()
            .container(&context.container)
            .stdin(true)
            .stdout(true)
            // A TTY merges stderr into stdout at the kernel level, so asking
            // for both is a contradiction rather than a preference.
            .stderr(!query.tty)
            .tty(query.tty);

        let attached = transport::bounded_setup(
            async {
                match query.command.as_ref() {
                    Some(command) => pods.exec(&context.target.pod_name, command, &params).await,
                    None => pods.attach(&context.target.pod_name, &params).await,
                }
            },
            &revoked,
        )
        .await;
        let mut attached = match attached {
            Ok(Ok(attached)) => attached,
            Ok(Err(_)) | Err(transport::StreamEnd::TargetError) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
                return;
            }
            Err(end) => {
                transport::close_with(&mut socket, end).await;
                return;
            }
        };

        let mut limits = transport::StreamLimits::new(
            transport::IDLE_TIMEOUT,
            transport::MAX_STREAM_DURATION,
            transport::MAX_STREAM_BYTES,
        );
        let end = transport::pump_attached(&mut socket, &mut attached, &mut limits, revoked).await;
        attached.abort();
        transport::close_with(&mut socket, end).await;

        info!(
            principal = %principal,
            lease = %id,
            pod_uid = %context.target.pod_uid,
            operation = "attach",
            outcome = "closed",
            reason = end.code(),
            caller_fault = end.is_caller_fault(),
            "Sandbox stream"
        );
    })
}

/// Forward one pool-declared port over a bounded WebSocket.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn sandbox_port_forward<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Query(query): Query<SandboxPortForwardQuery>,
    upgrade: axum::extract::WebSocketUpgrade,
) -> Response {
    use crate::api::sandbox_credentials::SandboxOperation;
    use crate::api::sandbox_transport as transport;

    let context =
        match prepare_upgrade(&state, &identity, &id, SandboxOperation::PortForward, None).await {
            Ok(context) => context,
            Err(response) => return response,
        };

    // Only what the pool declared. Without this the forward is a general
    // tunnel into the Pod's network namespace, reaching a debug listener or a
    // metrics endpoint the administrator never meant to publish.
    let port = match context.target.resolve_port(&query.port) {
        Ok(port) => port,
        Err(denied) => return access_denied(&identity, &id, "port-forward", denied),
    };

    let principal = identity.identity.clone();
    upgrade.on_upgrade(move |mut socket| async move {
        let guard = context.guard;
        let revoked = guard.cancelled();

        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(context.scoped.clone(), &context.target.namespace);

        // Same fence as attach: a recycled Pod under the recorded name would
        // forward the caller's connection into another tenant's workload.
        match transport::bounded_setup(pod_identity_holds(&pods, &context.target), &revoked).await {
            Ok(true) => {}
            Ok(false) | Err(transport::StreamEnd::TargetError) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
                return;
            }
            Err(end) => {
                transport::close_with(&mut socket, end).await;
                return;
            }
        }

        let mut forwarder = match transport::bounded_setup(
            pods.portforward(&context.target.pod_name, &[port]),
            &revoked,
        )
        .await
        {
            Ok(Ok(forwarder)) => forwarder,
            Ok(Err(_)) | Err(transport::StreamEnd::TargetError) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
                return;
            }
            Err(end) => {
                transport::close_with(&mut socket, end).await;
                return;
            }
        };
        let Some(mut stream) = forwarder.take_stream(port) else {
            transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
            return;
        };

        let mut limits = transport::StreamLimits::new(
            transport::IDLE_TIMEOUT,
            transport::MAX_STREAM_DURATION,
            transport::MAX_STREAM_BYTES,
        );
        let end = transport::pump_duplex(&mut socket, &mut stream, &mut limits, revoked).await;
        transport::close_with(&mut socket, end).await;

        info!(
            principal = %principal,
            lease = %id,
            pod_uid = %context.target.pod_uid,
            operation = "port-forward",
            port,
            outcome = "closed",
            reason = end.code(),
            caller_fault = end.is_caller_fault(),
            "Sandbox stream"
        );
    })
}

/// How long one exec may run before it is abandoned.
///
/// The caller chooses the command, so they choose how long it takes. Without a
/// bound, `sleep infinity` holds an API worker permanently — from inside a
/// sandbox that exists precisely because its occupant is not trusted.
const SANDBOX_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run one command inside a Sandbox and return its bounded output.
///
/// Request/response only: no stdin, no TTY, no shell. Those need a stream
/// protocol with its own revocation story, which is #83, and a shell would make
/// quoting the security boundary.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn sandbox_exec<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Json(request): Json<crate::api::sandbox_access::SandboxExecRequest>,
) -> Response {
    use crate::api::sandbox_access as access;
    use crate::api::sandbox_credentials as credentials;
    use crate::api::sandbox_executions as executions;

    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    if !is_valid_k8s_name(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "exec", denied),
        };
    let container = match target.resolve_container(request.container.as_deref()) {
        Ok(container) => container.to_string(),
        Err(denied) => return access_denied(&identity, &id, "exec", denied),
    };

    // Registered for the duration, so releasing or expiring the lease cancels
    // the command rather than letting it run on inside a workload that is
    // being torn down. The guard deregisters on every exit path, including a
    // panic — a leaked registration would later report cancelling something
    // that ended long ago.
    let guard = match register_live_stream(&state, &lease, &target).await {
        Ok(guard) => guard,
        Err(denied) => return stream_registration_denied(&identity, &id, "exec", denied),
    };
    let revoked = guard.cancelled();

    let scoped = match scoped_client_after_registration(
        &state,
        &lease,
        &target,
        credentials::SandboxOperation::Exec,
        &revoked,
    )
    .await
    {
        Ok(client) => client,
        Err(ScopedSetupDenied::Access(denied)) => {
            return access_denied(&identity, &id, "exec", denied);
        }
        Err(ScopedSetupDenied::Revoked) => {
            return stream_registration_denied(
                &identity,
                &id,
                "exec",
                StreamRegistrationDenied::LeaseEnded,
            );
        }
        Err(ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout) => {
            return stream_registration_denied(
                &identity,
                &id,
                "exec",
                StreamRegistrationDenied::Backend,
            );
        }
    };

    // The fixed endpoint bound is only a ceiling. The exact lease is the
    // authority to execute, so a command may never be granted time beyond its
    // remaining TTL. Compute this immediately before opening the exec stream;
    // credential setup and stream registration may have consumed part of it.
    let timeout =
        match executions::effective_timeout(SANDBOX_EXEC_TIMEOUT, &lease, chrono::Utc::now()) {
            Ok(timeout) => timeout,
            Err(executions::ExecutionRequestError::Denied(denied)) => {
                return access_denied(&identity, &id, "exec", denied);
            }
            Err(error) => {
                return sandbox_error(error.http_status(), error.to_string(), None);
            }
        };

    let result = tokio::select! {
        result = access::exec_in_sandbox(
            &scoped,
            &target,
            &container,
            &request.command,
            timeout,
        ) => result,
        _ = revoked.cancelled() => {
            info!(
                principal = %identity.identity,
                lease = %id,
                operation = "exec",
                outcome = "revoked",
                "Sandbox access"
            );
            return sandbox_error(
                StatusCode::GONE,
                "Sandbox lease stopped permitting access while the command was running",
                None,
            );
        }
    };

    match result {
        Ok(result) => {
            // The command and its output are the caller's own data and are
            // never audited. Identity, target and outcome are.
            info!(
                principal = %identity.identity,
                lease = %id,
                pod_uid = %target.pod_uid,
                operation = "exec",
                outcome = "allowed",
                success = result.success,
                "Sandbox access"
            );
            (StatusCode::OK, Json(result)).into_response()
        }
        Err(denied) => access_denied(&identity, &id, "exec", denied),
    }
}

/// Read a bounded tail of one Sandbox's output.
///
/// The first operation to go through #81's resolver: principal → owned, Ready,
/// unexpired lease → recorded provenance → the exact Pod and container. It
/// selects no default at any step, and the denial vocabulary is deliberately
/// coarse where it faces the caller — an unowned lease answers exactly as an
/// absent one does.
///
/// Management and child placement are not handled separately here. Both
/// resolve through the same interface; only the client differs, and that is
/// Kobe's business rather than the caller's.
#[tracing::instrument(skip_all, fields(lease = %id))]
async fn sandbox_logs<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Query(query): Query<crate::api::sandbox_access::SandboxLogsQuery>,
) -> Response {
    use crate::api::sandbox_access as access;

    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    if !is_valid_k8s_name(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "logs", denied),
        };

    let container = match target.resolve_container(query.container.as_deref()) {
        Ok(container) => container.to_string(),
        Err(denied) => return access_denied(&identity, &id, "logs", denied),
    };

    let guard = match register_live_stream(&state, &lease, &target).await {
        Ok(guard) => guard,
        Err(denied) => return stream_registration_denied(&identity, &id, "logs", denied),
    };
    let revoked = guard.cancelled();

    // The read runs under a credential that cannot name a second Pod, rather
    // than under the operator's own authority. The resolver has already denied
    // everything it should — this is the layer that makes a bug in the request
    // path a 403 instead of a privilege escalation.
    let scoped = match scoped_client_after_registration(
        &state,
        &lease,
        &target,
        crate::api::sandbox_credentials::SandboxOperation::Logs,
        &revoked,
    )
    .await
    {
        Ok(client) => client,
        Err(ScopedSetupDenied::Access(denied)) => {
            return access_denied(&identity, &id, "logs", denied);
        }
        Err(ScopedSetupDenied::Revoked) => {
            return stream_registration_denied(
                &identity,
                &id,
                "logs",
                StreamRegistrationDenied::LeaseEnded,
            );
        }
        Err(ScopedSetupDenied::TargetTimeout | ScopedSetupDenied::CredentialTimeout) => {
            return stream_registration_denied(
                &identity,
                &id,
                "logs",
                StreamRegistrationDenied::Backend,
            );
        }
    };

    let read = crate::api::sandbox_transport::bounded_setup(
        access::read_sandbox_logs(&scoped, &target, &container, access::clamp_tail(query.tail)),
        &revoked,
    )
    .await;
    match read {
        Err(crate::api::sandbox_transport::StreamEnd::Revoked) => {
            return stream_registration_denied(
                &identity,
                &id,
                "logs",
                StreamRegistrationDenied::LeaseEnded,
            );
        }
        Err(_) => {
            return stream_registration_denied(
                &identity,
                &id,
                "logs",
                StreamRegistrationDenied::Backend,
            );
        }
        Ok(Ok(logs)) => {
            // Audited by identity and outcome, never by content: the body is
            // the workload's own output and can contain anything.
            info!(
                principal = %identity.identity,
                lease = %id,
                pod_uid = %target.pod_uid,
                operation = "logs",
                outcome = "allowed",
                "Sandbox access"
            );
            (StatusCode::OK, logs).into_response()
        }
        Ok(Err(denied)) => access_denied(&identity, &id, "logs", denied),
    }
}

/// Record and answer one denied Sandbox operation.
///
/// The audit line carries the principal, lease, operation and a bounded reason
/// code — never a credential, a command, or any of the workload's own output.
/// The reason code is finer-grained than the caller-facing status on purpose:
/// an operator needs to tell "expired" from "never placed" when somebody
/// reports that access stopped working, while the caller must not be able to.
/// Record and answer a denial that is not a resolver outcome.
///
/// Same audit shape as [`access_denied`], for limits enforced after resolution
/// succeeded — the operator needs those countable by cause too.
fn access_denied_with(
    identity: &AuthIdentity,
    lease: &str,
    operation: &'static str,
    reason: &'static str,
    status: StatusCode,
    message: &'static str,
) -> Response {
    info!(
        principal = %identity.identity,
        lease = %lease,
        operation,
        outcome = "denied",
        reason,
        "Sandbox access"
    );
    sandbox_error(status, message, None)
}

fn access_denied(
    identity: &AuthIdentity,
    lease: &str,
    operation: &'static str,
    denied: crate::api::sandbox_access::SandboxAccessDenied,
) -> Response {
    info!(
        principal = %identity.identity,
        lease = %lease,
        operation,
        outcome = "denied",
        reason = denied.reason_code(),
        "Sandbox access"
    );
    let status = denied.http_status();
    if status == StatusCode::NOT_FOUND {
        // No body: a message would distinguish "not yours" from "not there".
        return StatusCode::NOT_FOUND.into_response();
    }
    sandbox_error(status, denied.to_string(), None)
}

/// Caller-safe lease intent. Unknown fields are rejected so a caller cannot
/// smuggle requester identity, target coordinates, runtime settings, or an
/// upstream Pod/Sandbox spec through a future-tolerant JSON object.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSandboxLeaseRequest {
    pool: String,
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    alias: Option<String>,
}

#[derive(Debug, Serialize)]
struct SandboxLeaseResponse {
    id: String,
    phase: String,
    pool: String,
    ttl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_generation: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_deadline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ready_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_cause: Option<SandboxReleaseCause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    placement: Option<ResolvedSandboxPlacement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<SandboxTargetProvenance>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<SandboxCondition>,
}

#[derive(Debug, Serialize)]
struct SandboxLeaseSummary {
    id: String,
    phase: String,
    pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct SandboxErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Stable, non-retry handle returned when this process cannot finish deciding
/// whether the exact durable lease was admitted or cancelled.
///
/// It extends [`SandboxLeaseResponse`] so older clients still retain the ID and
/// poll its `Pending` phase, while `admission_pending` tells current clients
/// that placement was *not* accepted. They must poll `status_url` for this ID
/// and must not repeat the create.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxAdmissionPendingResponse {
    #[serde(flatten)]
    lease: SandboxLeaseResponse,
    status: &'static str,
    retry: bool,
    status_url: String,
}

fn sandbox_error(status: StatusCode, error: impl Into<String>, detail: Option<String>) -> Response {
    (
        status,
        Json(SandboxErrorResponse {
            error: error.into(),
            detail,
        }),
    )
        .into_response()
}

fn sandbox_infra_error(message: &'static str, err: impl std::fmt::Display) -> Response {
    error!(error = %err, "{message}");
    sandbox_error(StatusCode::SERVICE_UNAVAILABLE, message, None)
}

/// Return a lease whose exact admission CAS is known to have committed.
///
/// `phase: Pending` means controller provisioning has not finished; unlike
/// [`sandbox_admission_pending`], admission itself is no longer ambiguous.
fn sandbox_lease_accepted(
    lease_id: String,
    pool: String,
    effective_ttl: String,
    was_clamped: bool,
    alias: Option<String>,
    provisioning_deadline: String,
) -> Response {
    let location = format!("/v1/sandbox-leases/{lease_id}");
    let mut response = (
        StatusCode::ACCEPTED,
        Json(pending_sandbox_lease_response(
            lease_id,
            pool,
            effective_ttl,
            was_clamped,
            alias,
            provisioning_deadline,
        )),
    )
        .into_response();
    if let Ok(location) = axum::http::HeaderValue::from_str(&location) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response
}

/// Return an unresolved admission as a distinct, durable, non-retry handle.
///
/// The caller must not treat this as an admitted/placeable lease. It must poll
/// `Location`: the exact parent may later become admitted or be cancelled by
/// the supervised reaper. Returning a normal accepted lease here would lie;
/// returning 503 would invite a duplicate create after a lost response.
///
/// This protocol does not make a create idempotent across a client disconnect
/// after the final HTTP response. That broader guarantee requires a
/// caller-supplied create idempotency key and remains outside admission #101.
fn sandbox_admission_pending(
    lease_id: String,
    pool: String,
    effective_ttl: String,
    was_clamped: bool,
    alias: Option<String>,
    provisioning_deadline: String,
) -> Response {
    let status_url = format!("/v1/sandbox-leases/{lease_id}");
    let mut response = (
        StatusCode::ACCEPTED,
        Json(SandboxAdmissionPendingResponse {
            lease: pending_sandbox_lease_response(
                lease_id,
                pool,
                effective_ttl,
                was_clamped,
                alias,
                provisioning_deadline,
            ),
            status: "admission_pending",
            retry: false,
            status_url: status_url.clone(),
        }),
    )
        .into_response();
    if let Ok(location) = axum::http::HeaderValue::from_str(&status_url) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response
}

fn pending_sandbox_lease_response(
    lease_id: String,
    pool: String,
    effective_ttl: String,
    was_clamped: bool,
    alias: Option<String>,
    provisioning_deadline: String,
) -> SandboxLeaseResponse {
    SandboxLeaseResponse {
        id: lease_id,
        phase: SandboxLeasePhase::Pending.to_string(),
        pool,
        ttl: effective_ttl.clone(),
        effective_ttl: was_clamped.then_some(effective_ttl),
        alias,
        observed_generation: None,
        provisioning_deadline: Some(provisioning_deadline),
        ready_at: None,
        expires_at: None,
        release_cause: None,
        placement: None,
        target: None,
        conditions: Vec::new(),
    }
}

/// 429 that tells the caller when to come back.
///
/// Without `Retry-After` a throttled client has no signal but "no", and the
/// only strategy left is to poll — which is the load the throttle was raised
/// against. The value is rounded *up* and floored at one second: advertising a
/// wait shorter than the real one converts one rejection into two.
fn sandbox_throttled(error: String, retry_after: std::time::Duration) -> Response {
    let seconds = retry_after.as_secs_f64().ceil().max(1.0) as u64;
    let mut response = sandbox_error(
        StatusCode::TOO_MANY_REQUESTS,
        error,
        Some(format!("Retry in {seconds}s")),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&seconds.to_string()) {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, value);
    }
    response
}

#[tracing::instrument(skip_all)]
async fn create_sandbox_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Json(request): Json<CreateSandboxLeaseRequest>,
) -> Response {
    // Start the budget before any request-owned state can mutate. In
    // particular, the abandoned-admission sweep below is Kubernetes work and
    // must not consume the entire reaper margin before the clock starts.
    let active_admission_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(SANDBOX_ACTIVE_ADMISSION_TIMEOUT_SECS);
    // The admission state machine deliberately retains several exact object
    // snapshots across cancellation branches. Keep that large future off the
    // request task's stack; repeated endpoint calls must not grow a Tokio test
    // or server worker frame enough to overflow it.
    create_sandbox_lease_until(state, identity, request, active_admission_deadline).await
}

/// Run the admission state machine from a heap-backed future.
///
/// The state machine retains exact Kubernetes snapshots across every
/// cancellation branch. Boxing at the constructor boundary keeps those
/// snapshots off both Axum worker stacks and the default-sized Tokio test
/// thread stack, including callers that exercise the deadline helper directly.
fn create_sandbox_lease_until<B: ClusterBackend>(
    state: AppState<B>,
    identity: AuthIdentity,
    request: CreateSandboxLeaseRequest,
    active_admission_deadline: tokio::time::Instant,
) -> impl std::future::Future<Output = Response> {
    Box::pin(create_sandbox_lease_until_inner(
        state,
        identity,
        request,
        active_admission_deadline,
    ))
}

async fn create_sandbox_lease_until_inner<B: ClusterBackend>(
    state: AppState<B>,
    identity: AuthIdentity,
    request: CreateSandboxLeaseRequest,
    active_admission_deadline: tokio::time::Instant,
) -> Response {
    // FIRST statement, deliberately. Everything below — the CRD probe, the pool
    // GET, the lease CREATE, up to `max_concurrent_leases` reservation CREATEs,
    // and the DELETE that undoes them — is apiserver work this handler performs
    // *before* it can decide the answer, and it performs all of it just as
    // eagerly for a request that is going to be refused. So the budget is spent
    // by the attempt, not by its outcome: a caller looping on 429s pays exactly
    // like one looping on 202s, and no exit below can skip the charge because
    // none of them is reachable without passing through here.
    let principal = principal_hash(&identity);
    if let RateLimitDecision::Throttled { retry_after } =
        state.sandbox_admission_limiter.charge(&principal)
    {
        crate::metrics::SANDBOX_ADMISSION_RATE_LIMITED_TOTAL.inc();
        warn!(
            identity = %identity.identity,
            retry_after_secs = retry_after.as_secs_f64(),
            "Sandbox admission throttled for this principal"
        );
        return sandbox_throttled(
            "Sandbox admission rate limit reached for this principal".into(),
            retry_after,
        );
    }

    match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        require_sandbox_crds(&state.client, &[SANDBOX_POOL_CRD, SANDBOX_LEASE_CRD]),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(response)) => return response,
        Err(error) => {
            return sandbox_infra_error("Sandbox lease admission preflight was interrupted", error);
        }
    }
    let policy = policy_for(&identity);

    if !is_valid_k8s_name(&request.pool) {
        return sandbox_error(
            StatusCode::BAD_REQUEST,
            "Invalid SandboxPool name",
            Some(
                "Pool must be a DNS label (lowercase alphanumeric and hyphens, 1-63 characters)"
                    .into(),
            ),
        );
    }
    if !is_sandbox_allowed(&request.pool, SandboxVerb::Lease, &policy) {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox lease is not allowed for this pool",
            None,
        );
    }
    if let Some(alias) = request.alias.as_deref()
        && !is_valid_k8s_name(alias)
    {
        return sandbox_error(
            StatusCode::BAD_REQUEST,
            "Invalid Sandbox lease alias",
            Some(
                "Alias must be a DNS label (lowercase alphanumeric and hyphens, 1-63 characters)"
                    .into(),
            ),
        );
    }

    let pools: Api<SandboxPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let pool = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        pools.get(&request.pool),
    )
    .await
    {
        Ok(Ok(pool)) => pool,
        Ok(Err(kube::Error::Api(error))) if error.code == 404 => {
            return sandbox_error(StatusCode::NOT_FOUND, "SandboxPool not found", None);
        }
        Ok(Err(err)) => return sandbox_infra_error("Unable to load SandboxPool", err),
        Err(error) => {
            return sandbox_infra_error("Sandbox lease admission preflight was interrupted", error);
        }
    };

    if let Err(err) = pool.spec.validate() {
        return sandbox_infra_error("SandboxPool configuration is invalid", err);
    }
    if let Err(err) = crate::sandbox::require_current_sandbox_pool_ready(&pool) {
        warn!(pool = %request.pool, error = %err, "Sandbox admission refused an uncertified pool");
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SandboxPool is not ready for new leases",
            None,
        );
    }
    let pool_reference = match sandbox_pool_reference(&pool) {
        Ok(reference) => reference,
        Err(detail) => {
            return sandbox_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SandboxPool identity is incomplete",
                Some(detail),
            );
        }
    };
    let placement_authority = match sandbox_placement_authority_for_admission(&pool) {
        Ok(authority) => authority,
        Err(detail) => {
            return sandbox_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SandboxPool placement authority is incomplete",
                Some(detail),
            );
        }
    };

    let requested_ttl = request.ttl.as_deref().unwrap_or(&pool.spec.default_ttl);
    let Some(requested_duration) =
        parse_duration(requested_ttl).filter(|duration| *duration > chrono::Duration::zero())
    else {
        if request.ttl.is_none() {
            return sandbox_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SandboxPool default TTL is invalid",
                None,
            );
        }
        return sandbox_error(
            StatusCode::BAD_REQUEST,
            "Invalid Sandbox lease TTL",
            Some("Use a positive duration such as '30m' or '2h'".into()),
        );
    };
    let Some(policy_duration) = clamp_sandbox_ttl(requested_ttl, &policy) else {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox lease TTL is not authorized",
            None,
        );
    };
    let Some(provisioning_timeout) = parse_duration(&pool.spec.provisioning_timeout)
        .filter(|duration| *duration > chrono::Duration::zero())
    else {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SandboxPool provisioning timeout is invalid",
            None,
        );
    };
    let Some(pool_max_ttl) =
        parse_duration(&pool.spec.max_ttl).filter(|duration| *duration > chrono::Duration::zero())
    else {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SandboxPool maximum TTL is invalid",
            None,
        );
    };
    let effective_duration = policy_duration.min(pool_max_ttl);
    let effective_ttl = format_duration(&effective_duration);
    let was_clamped = effective_duration < requested_duration;

    let Some(grant) = policy.sandbox.as_ref() else {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox access is not configured",
            None,
        );
    };
    let totals = match aggregate_resource_limits(&pool.spec.template) {
        Ok(totals) => totals,
        Err(err) => return sandbox_infra_error("SandboxPool resources are invalid", err),
    };
    match resource_ceiling_allows(&grant.resource_ceiling, &totals) {
        Ok(true) => {}
        Ok(false) => {
            return sandbox_error(
                StatusCode::FORBIDDEN,
                "SandboxPool exceeds your resource ceiling",
                None,
            );
        }
        Err(err) => return sandbox_infra_error("Sandbox resource ceiling is invalid", err),
    }

    let leases: Api<SandboxLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let reservations: Api<Lease> =
        Api::namespaced(state.client.clone(), &state.sandbox_reservation_namespace);
    if grant.max_concurrent_leases > MAX_SANDBOX_CONCURRENCY_SLOTS {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sandbox concurrency policy exceeds the supported reservation bound",
            None,
        );
    }
    // Reclaim this principal's own quota stranded by an earlier request that
    // died between reserving and admitting. Runs before admission so a caller
    // locked out by their own crashed request recovers on their next attempt
    // rather than staying 429/409 forever.
    if let Err(error) = await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        cancel_expired_pending_admissions(&leases, &reservations, &identity, chrono::Utc::now()),
    )
    .await
    {
        return sandbox_infra_error(
            "Sandbox lease admission timed out during abandoned-admission recovery",
            error,
        );
    }

    let lease_id = format!(
        "{LEASE_ID_PREFIX}{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );
    let lease = build_sandbox_lease(
        &lease_id,
        &state.namespace,
        pool_reference,
        placement_authority,
        &effective_ttl,
        request.alias.as_deref(),
        &identity,
    );
    // The request-local timer bounds ordinary stalled API work before the
    // controller's ten-minute cancellation boundary. It is intentionally only
    // the availability mechanism; timeout resolution below always commits the
    // durable cancellation CAS because dropping an HTTP future cannot prove
    // that Kubernetes did not accept the request. A CREATE that commits after
    // this future is dropped can leave only an unadmitted parent, which the
    // durable sweep cancels.
    let created = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        leases.create(&PostParams::default(), &lease),
    )
    .await
    {
        Ok(Ok(created)) => created,
        Ok(Err(err)) => return sandbox_infra_error("Failed to create Sandbox lease", err),
        Err(error) => {
            return sandbox_infra_error("Sandbox lease admission was interrupted", error);
        }
    };
    if let Err(err) = validate_lease_shape(&lease, &created, SANDBOX_ADMISSION_PENDING) {
        match delete_exact_pending_lease_until(
            &leases,
            &reservations,
            &created,
            active_admission_deadline,
            &state.shutdown,
        )
        .await
        {
            Ok(()) => {}
            Err(cleanup_err @ SandboxLeaseMutationError::AdmissionDeadlineExceeded)
            | Err(cleanup_err @ SandboxLeaseMutationError::AdmissionShuttingDown) => {
                return sandbox_infra_error(
                    "Malformed Sandbox lease cleanup was interrupted",
                    cleanup_err,
                );
            }
            Err(cleanup_err) => {
                error!(error = %cleanup_err, "Failed to remove malformed Sandbox lease create response");
            }
        }
        return sandbox_infra_error("Sandbox lease create response failed validation", err);
    }

    // Admission snapshots the absolute setup bound before reserving quota or
    // exposing `admitted`. The API-server creation timestamp is authoritative:
    // using a process clock here, or `now()` later in the controller, would
    // erase queue/controller downtime from the bound.
    let provisioning_deadline = match created
        .metadata
        .creation_timestamp
        .as_ref()
        .and_then(|timestamp| {
            chrono::DateTime::parse_from_rfc3339(&timestamp.0.to_string())
                .ok()
                .map(|parsed| parsed.with_timezone(&chrono::Utc))
        })
        .ok_or(SandboxLeaseMutationError::MissingCreationTimestamp)
        .and_then(|accepted_at| {
            crate::sandbox::sandbox_provisioning_deadline(accepted_at, provisioning_timeout)
                .map_err(SandboxLeaseMutationError::Lifecycle)
        }) {
        Ok(deadline) => deadline,
        Err(err) => {
            match delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                Ok(()) => {}
                Err(cleanup_err @ SandboxLeaseMutationError::AdmissionDeadlineExceeded)
                | Err(cleanup_err @ SandboxLeaseMutationError::AdmissionShuttingDown) => {
                    return sandbox_infra_error(
                        "Unbounded Sandbox lease cleanup was interrupted",
                        cleanup_err,
                    );
                }
                Err(cleanup_err) => {
                    error!(error = %cleanup_err, "Failed to remove Sandbox lease without a provisioning deadline");
                }
            }
            return sandbox_infra_error("Failed to bound Sandbox lease provisioning", err);
        }
    };
    let created = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        persist_pending_provisioning_deadline(&leases, &created, &provisioning_deadline),
    )
    .await
    {
        Ok(Ok(created)) => created,
        Ok(Err(err)) => {
            match delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                Ok(()) => {}
                Err(cleanup_err @ SandboxLeaseMutationError::AdmissionDeadlineExceeded)
                | Err(cleanup_err @ SandboxLeaseMutationError::AdmissionShuttingDown) => {
                    return sandbox_infra_error(
                        "Sandbox deadline checkpoint cleanup was interrupted",
                        cleanup_err,
                    );
                }
                Err(cleanup_err) => {
                    error!(error = %cleanup_err, "Failed to remove Sandbox lease after deadline checkpoint failure");
                }
            }
            return sandbox_infra_error("Failed to checkpoint Sandbox provisioning deadline", err);
        }
        Err(bound) => {
            match resolve_timed_out_admission(
                &leases,
                &reservations,
                &created,
                &provisioning_deadline,
                None,
                None,
                &state.shutdown,
            )
            .await
            {
                AdmissionResolution::Admitted => {
                    warn!(
                        lease_id = %lease_id,
                        "Sandbox admission completed while its deadline cancellation was in flight; reporting success"
                    );
                    return sandbox_lease_accepted(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
                AdmissionResolution::Cancelled => {
                    return sandbox_infra_error("Sandbox lease admission was interrupted", bound);
                }
                AdmissionResolution::HandedOff => {
                    warn!(
                        lease_id = %lease_id,
                        "Sandbox admission resolution handed off durably; returning its non-retry handle"
                    );
                    return sandbox_admission_pending(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
            }
        }
    };

    // Every admitted lease owns its distributed access gate before capacity is
    // reserved. Lazy creation in a handler would leave a no-operation lease
    // unable to enter teardown when the protected ledger quota is full, while
    // lazy creation in teardown would make cleanup depend on allocating the
    // very resource whose exhaustion cleanup must relieve.
    let access_gate = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        crate::sandbox_access_ledger::prepare_open_gate(
            &state.client,
            &state.sandbox_reservation_namespace,
            &created,
        ),
    )
    .await
    {
        Ok(Ok(reference)) => reference,
        Ok(Err(err)) => {
            if let Err(cleanup_err) = delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                error!(error = %cleanup_err, "Failed to remove Sandbox lease after access-gate preparation failure");
                if matches!(
                    cleanup_err,
                    SandboxLeaseMutationError::AdmissionDeadlineExceeded
                        | SandboxLeaseMutationError::AdmissionShuttingDown
                ) {
                    return sandbox_admission_pending(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
            }
            return sandbox_infra_error("Failed to prepare Sandbox access gate", err);
        }
        Err(bound) => {
            match resolve_timed_out_admission(
                &leases,
                &reservations,
                &created,
                &provisioning_deadline,
                None,
                None,
                &state.shutdown,
            )
            .await
            {
                AdmissionResolution::Cancelled => {
                    return sandbox_infra_error(
                        "Sandbox access-gate preparation was interrupted",
                        bound,
                    );
                }
                AdmissionResolution::Admitted | AdmissionResolution::HandedOff => {
                    return sandbox_admission_pending(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
            }
        }
    };

    // Quota and alias admission use atomic, per-principal Kubernetes Lease
    // reservations. Advisory LIST checks above improve error latency, but only
    // these CREATE operations are authoritative across API replicas.
    // The exact names and UIDs returned by CREATE are committed atomically with
    // the `admitted` marker below. Cleanup uses those persisted handles rather
    // than granting deletion authority to a label selector.
    let admission_reservations = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        acquire_admission_reservations(
            &leases,
            &reservations,
            &created,
            &identity,
            request.alias.as_deref(),
            grant.max_concurrent_leases,
        ),
    )
    .await
    {
        Ok(Ok(reservations)) => reservations,
        Ok(Err(AdmissionReservationError::QuotaExhausted)) => {
            if let Err(error) = delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                return sandbox_infra_error(
                    "Sandbox quota reservation cleanup failed; lease remains unadmitted",
                    error,
                );
            }
            return sandbox_error(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Concurrent Sandbox lease limit ({}) reached",
                    grant.max_concurrent_leases
                ),
                None,
            );
        }
        Ok(Err(AdmissionReservationError::AliasTaken)) => {
            if let Err(error) = delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                return sandbox_infra_error(
                    "Sandbox alias reservation cleanup failed; lease remains unadmitted",
                    error,
                );
            }
            return sandbox_error(
                StatusCode::CONFLICT,
                format!(
                    "Sandbox lease alias '{}' is already active",
                    request.alias.as_deref().unwrap_or_default()
                ),
                None,
            );
        }
        Ok(Err(err)) => {
            if let Err(cleanup_err) = delete_exact_pending_lease_until(
                &leases,
                &reservations,
                &created,
                active_admission_deadline,
                &state.shutdown,
            )
            .await
            {
                error!(error = %cleanup_err, "Failed to remove Sandbox lease after reservation error");
            }
            return sandbox_infra_error("Failed to reserve Sandbox admission", err);
        }
        Err(bound) => {
            match resolve_timed_out_admission(
                &leases,
                &reservations,
                &created,
                &provisioning_deadline,
                None,
                Some(&access_gate),
                &state.shutdown,
            )
            .await
            {
                AdmissionResolution::Admitted => {
                    warn!(
                        lease_id = %lease_id,
                        "Sandbox admission completed while reservation timeout cancellation was in flight; reporting success"
                    );
                    return sandbox_lease_accepted(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
                AdmissionResolution::Cancelled => {
                    return sandbox_infra_error("Sandbox lease admission was interrupted", bound);
                }
                AdmissionResolution::HandedOff => {
                    warn!(
                        lease_id = %lease_id,
                        "Sandbox reservation-timeout resolution handed off durably; returning its non-retry handle"
                    );
                    return sandbox_admission_pending(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
            }
        }
    };

    let mut admission_handoff_requires_quarantine = false;
    let admission_result = match await_admission_stage_until(
        active_admission_deadline,
        &state.shutdown,
        admit_sandbox_lease(
            &leases,
            &reservations,
            &created,
            &admission_reservations,
            &access_gate,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(bound) => {
            match resolve_timed_out_admission(
                &leases,
                &reservations,
                &created,
                &provisioning_deadline,
                Some(&admission_reservations),
                Some(&access_gate),
                &state.shutdown,
            )
            .await
            {
                AdmissionResolution::Admitted => {
                    warn!(
                        lease_id = %lease_id,
                        "Sandbox admission committed while timeout cancellation was in flight; reporting success"
                    );
                    Ok(())
                }
                AdmissionResolution::Cancelled => {
                    return sandbox_infra_error("Sandbox lease admission was interrupted", bound);
                }
                AdmissionResolution::HandedOff => {
                    warn!(
                        lease_id = %lease_id,
                        "Timed-out Sandbox admission handed off durably; returning its non-retry handle"
                    );
                    return sandbox_admission_pending(
                        lease_id,
                        request.pool,
                        effective_ttl,
                        was_clamped,
                        request.alias,
                        provisioning_deadline,
                    );
                }
            }
        }
    };

    if let Err(err) = admission_result {
        match err {
            // Provably NOT admitted. Remove the lease, which releases its own
            // reservations afterwards.
            //
            // Deliberately does not release reservations first. Doing so would
            // free the quota slot while the lease might still be live — if the
            // "not committed" classification were ever wrong, another request
            // could take that slot against an admitted lease and over-admit.
            // Deleting the lease under its UID fence is what makes the release
            // safe, so it has to come first.
            SandboxLeaseMutationError::AdmissionNotCommitted => {
                if let Err(cleanup_err) = delete_exact_pending_lease_until(
                    &leases,
                    &reservations,
                    &created,
                    active_admission_deadline,
                    &state.shutdown,
                )
                .await
                {
                    error!(error = %cleanup_err, "Failed to remove Sandbox lease after admission failure");
                }
                return sandbox_infra_error("Failed to finalize Sandbox lease admission", err);
            }
            // Anything else is ambiguous after reservation: a lost response,
            // transport failure, or cleanup that lost its race with the admit
            // PATCH. A one-off GET is not enough — it can still read `pending`
            // immediately before admission lands. Route the entire tail back
            // through the UID/RV/state arbiter so only a durable winner decides
            // whether failure is retryable.
            other => {
                match resolve_timed_out_admission(
                    &leases,
                    &reservations,
                    &created,
                    &provisioning_deadline,
                    Some(&admission_reservations),
                    Some(&access_gate),
                    &state.shutdown,
                )
                .await
                {
                    AdmissionResolution::Admitted => {
                        if leases.get(&lease_id).await.is_ok_and(|current| {
                            !crate::sandbox_access_ledger::persisted_gate_reference(&current)
                                .is_ok_and(|actual| actual == access_gate)
                        }) {
                            // Admission itself is durable, so a 503 would invite
                            // a duplicate create. Preserve the handle; placement
                            // independently proves the exact open gate and
                            // quarantines the lease if that provenance drifted.
                            admission_handoff_requires_quarantine = true;
                            error!(
                                lease_id = %lease_id,
                                error = %other,
                                "admission committed without the expected access gate; \
                                 preserving the durable handle for quarantine"
                            );
                        } else {
                            warn!(
                                lease_id = %lease_id,
                                error = %other,
                                "Ambiguous admission tail resolved as admitted; reporting the existing handle"
                            );
                        }
                    }
                    AdmissionResolution::Cancelled => {
                        return sandbox_infra_error(
                            "Failed to finalize Sandbox lease admission",
                            other,
                        );
                    }
                    AdmissionResolution::HandedOff => {
                        warn!(
                            lease_id = %lease_id,
                            error = %other,
                            "Ambiguous admission tail handed off durably; returning its non-retry handle"
                        );
                        return sandbox_admission_pending(
                            lease_id,
                            request.pool,
                            effective_ttl,
                            was_clamped,
                            request.alias,
                            provisioning_deadline,
                        );
                    }
                }
            }
        }
    }

    if admission_handoff_requires_quarantine {
        warn!(
            lease_id = %lease_id,
            pool = %request.pool,
            identity = %identity.identity,
            "Sandbox lease admitted but not authorized for placement; returning its durable handle"
        );
    } else {
        info!(
            lease_id = %lease_id,
            pool = %request.pool,
            identity = %identity.identity,
            "Sandbox lease accepted for placement"
        );
    }

    sandbox_lease_accepted(
        lease_id,
        request.pool,
        effective_ttl,
        was_clamped,
        request.alias,
        provisioning_deadline,
    )
}

#[tracing::instrument(skip_all)]
async fn list_sandbox_leases<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
) -> Response {
    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    let policy = policy_for(&identity);
    let Some(grant) = policy.sandbox.as_ref() else {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox access is not configured",
            None,
        );
    };
    if !grant.verbs.contains(&SandboxVerb::Lease) {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox lease read is not allowed",
            None,
        );
    }

    let leases: Api<SandboxLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let params = requester_list_params(&identity);
    match leases.list(&params).await {
        Ok(items) => {
            let response: Vec<_> = items
                .iter()
                .filter(|lease| principal_matches(&lease.spec.requester, &identity))
                .filter(|lease| {
                    is_sandbox_allowed(&lease.spec.pool_ref.name, SandboxVerb::Lease, &policy)
                })
                .map(|lease| {
                    let status = lease.status.clone().unwrap_or_default();
                    SandboxLeaseSummary {
                        id: lease.name_any(),
                        phase: status.phase.to_string(),
                        pool: lease.spec.pool_ref.name.clone(),
                        alias: lease.spec.alias.clone(),
                        expires_at: status.expires_at,
                    }
                })
                .collect();
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => sandbox_infra_error("Failed to list Sandbox leases", err),
    }
}

#[tracing::instrument(skip_all)]
async fn get_sandbox_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    let leases: Api<SandboxLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let lease = match owned_sandbox_lease(&leases, &id, &identity).await {
        Ok(Some(lease)) => lease,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return sandbox_infra_error("Failed to get Sandbox lease", err),
    };
    let policy = policy_for(&identity);
    if !is_sandbox_allowed(&lease.spec.pool_ref.name, SandboxVerb::Lease, &policy) {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox lease read is not allowed",
            None,
        );
    }

    (StatusCode::OK, Json(sandbox_lease_response(lease, None))).into_response()
}

#[tracing::instrument(skip_all)]
async fn release_sandbox_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    let leases: Api<SandboxLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let lease = match owned_sandbox_lease(&leases, &id, &identity).await {
        Ok(Some(lease)) => lease,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return sandbox_infra_error("Failed to get Sandbox lease", err),
    };
    let policy = policy_for(&identity);
    if !is_sandbox_allowed(&lease.spec.pool_ref.name, SandboxVerb::Release, &policy) {
        return sandbox_error(
            StatusCode::FORBIDDEN,
            "Sandbox release is not allowed",
            None,
        );
    }

    let phase = lease
        .status
        .as_ref()
        .map(|status| status.phase)
        .unwrap_or_default();
    if phase == SandboxLeasePhase::Quarantined {
        return sandbox_error(
            StatusCode::CONFLICT,
            "Sandbox cleanup is quarantined",
            Some("Cleanup remains uncertain; capacity has not been released".into()),
        );
    }
    if matches!(
        phase,
        SandboxLeasePhase::Released | SandboxLeasePhase::Expired
    ) {
        return StatusCode::NO_CONTENT.into_response();
    }

    if lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        != Some(SANDBOX_ADMISSION_ADMITTED)
    {
        let reservations: Api<Lease> =
            Api::namespaced(state.client.clone(), &state.sandbox_reservation_namespace);
        if pristine_pending_lease(&lease).is_ok() {
            let admission = lease
                .annotations()
                .get(SANDBOX_ADMISSION_ANNOTATION)
                .map(String::as_str);
            if !matches!(
                admission,
                Some(SANDBOX_ADMISSION_PENDING) | Some(SANDBOX_ADMISSION_CANCELLED)
            ) {
                match pristine_parent_has_no_live_reservations(&reservations, &lease).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return sandbox_error(
                            StatusCode::CONFLICT,
                            "Sandbox admission state is ambiguous",
                            Some(
                                "Lease retained because live admission reservations still exist"
                                    .into(),
                            ),
                        );
                    }
                    Err(err) => {
                        return sandbox_infra_error(
                            "Failed to prove unadmitted Sandbox reservations absent",
                            err,
                        );
                    }
                }
            }
            return match delete_exact_pending_lease(&leases, &reservations, &lease).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(err) => sandbox_infra_error("Failed to remove unadmitted Sandbox lease", err),
            };
        }

        let persisted = match proven_active_release_shape(&lease, &state.namespace) {
            Ok(persisted) => persisted,
            Err(_) => {
                return sandbox_error(
                    StatusCode::CONFLICT,
                    "Sandbox admission state is ambiguous",
                    Some(
                        "Lease retained; active or corrupt state requires verified teardown".into(),
                    ),
                );
            }
        };
        return match repair_admitted_release_intent(&leases, &reservations, &lease, &persisted)
            .await
        {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(err) => sandbox_infra_error(
                "Failed to repair Sandbox admission for verified teardown",
                err,
            ),
        };
    }
    if phase == SandboxLeasePhase::Releasing {
        return StatusCode::NO_CONTENT.into_response();
    }
    if lease
        .annotations()
        .contains_key(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
    {
        return StatusCode::NO_CONTENT.into_response();
    }

    let Some(resource_version) = lease.resource_version() else {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sandbox lease has no resourceVersion",
            None,
        );
    };
    let patch = serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION: chrono::Utc::now().to_rfc3339()
            }
        }
    });
    match leases
        .patch(&id, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => sandbox_infra_error("Failed to request Sandbox release", err),
    }
}

/// Prove that damaged admission metadata does not hide a committed token set.
///
/// Exact `pending`/`cancelled` markers are themselves CAS state and use the
/// normal fenced cancellation path. A missing or unrecognised marker has no
/// such authority: before direct parent deletion Kobe must scan the full
/// ledger and prove that no deterministic token name for this principal could
/// belong to the parent. A UID-label selector is insufficient because the
/// label is mutable and can hide a live token. Any candidate makes the object
/// indistinguishable from an admitted Pending lease whose annotations were
/// stripped, so it is retained unchanged.
async fn pristine_parent_has_no_live_reservations(
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<bool, SandboxLeaseMutationError> {
    lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let principal = principal_hash_for(&lease.spec.requester);
    let alias_name = lease
        .spec
        .alias
        .as_deref()
        .map(|alias| alias_reservation_name(&principal, alias));
    let listed = reservations.list(&ListParams::default()).await?;

    // With damaged parent admission metadata, mutable token labels and
    // annotations cannot prove which same-principal parent owns a slot. Names
    // are immutable and derived from the principal, so conservatively retain
    // the parent if any of its possible quota names (or exact alias name) is
    // live. This path is recovery from corruption, where refusing deletion is
    // safer than freeing quota underneath a hidden admitted Sandbox.
    Ok(!listed.items.into_iter().any(|reservation| {
        let name = reservation.name_any();
        quota_reservation_slot(&name, &principal).is_some()
            || alias_name.as_deref() == Some(name.as_str())
    }))
}

/// Prove that a non-admitted lease already owns an active Sandbox lifecycle.
///
/// A phase alone is not authority to resurrect admission: corrupt status could
/// otherwise turn an unreserved object into controller work. Recovery requires
/// the cleanup fence, both placement checkpoints, and canonical exact
/// reservation provenance. The live ledger is verified separately immediately
/// before the repair CAS.
fn proven_active_release_shape(
    lease: &SandboxLease,
    management_namespace: &str,
) -> Result<Vec<AdmissionReservation>, SandboxLeaseMutationError> {
    let status = lease
        .status
        .as_ref()
        .ok_or(SandboxLeaseMutationError::LeaseShapeChanged)?;
    let target =
        crate::sandbox::require_release_safe_target_provenance(status, management_namespace)?;
    let target_has_identity = target.child_cluster_lease.is_some()
        || target.child_cluster_instance.is_some()
        || target.sandbox_template.is_some()
        || target.sandbox_warm_pool.is_some()
        || target.sandbox_claim.is_some()
        || target.sandbox.is_some()
        || target.pod.is_some()
        || target.service.is_some();
    if !matches!(
        status.phase,
        SandboxLeasePhase::Provisioning | SandboxLeasePhase::Ready | SandboxLeasePhase::Releasing
    ) || !target_has_identity
        || !normalized_finalizers(lease)
            .iter()
            .any(|finalizer| finalizer == SANDBOX_LEASE_FINALIZER)
    {
        return Err(SandboxLeaseMutationError::LeaseShapeChanged);
    }
    lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    lease
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    persisted_reservation_provenance(lease)
}

/// Repair a proven active lease and request teardown in one exact CAS.
///
/// Both annotations are written by the same UID/resourceVersion-fenced JSON
/// Patch. Therefore no controller can observe a repaired `admitted` object
/// without its release intent. Before that patch Kobe proves that every
/// persisted reservation is still the exact live token admission committed;
/// mismatch or API uncertainty fails closed without touching the parent or the
/// ledger. A lost PATCH response is successful only when a re-read proves both
/// annotations on the same UID.
async fn repair_admitted_release_intent(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    persisted: &[AdmissionReservation],
) -> Result<(), SandboxLeaseMutationError> {
    let uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let resource_version = lease
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    verified_reservations_for_lease(reservations, lease, &uid, Some(persisted), true).await?;

    let requested_at = lease
        .annotations()
        .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
        .filter(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
        .cloned()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        {
            "op": "add",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
            "value": SANDBOX_ADMISSION_ADMITTED
        },
        {
            "op": "add",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-release-requested-at",
            "value": requested_at
        }
    ]));
    match leases
        .patch(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(repaired) => validate_repaired_release(lease, &repaired, persisted, &requested_at),
        Err(patch_error) => match leases.get(&lease.name_any()).await {
            Ok(current) => validate_repaired_release(lease, &current, persisted, &requested_at)
                .map_err(|_| SandboxLeaseMutationError::Kubernetes(patch_error)),
            Err(_) => Err(SandboxLeaseMutationError::Kubernetes(patch_error)),
        },
    }
}

fn validate_repaired_release(
    expected: &SandboxLease,
    actual: &SandboxLease,
    persisted: &[AdmissionReservation],
    requested_at: &str,
) -> Result<(), SandboxLeaseMutationError> {
    if actual.name_any() != expected.name_any()
        || actual.namespace() != expected.namespace()
        || actual.uid() != expected.uid()
        || actual.spec != expected.spec
        || actual
            .annotations()
            .get(SANDBOX_ADMISSION_ANNOTATION)
            .map(String::as_str)
            != Some(SANDBOX_ADMISSION_ADMITTED)
        || actual
            .annotations()
            .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
            .map(String::as_str)
            != Some(requested_at)
        || persisted_reservation_provenance(actual)? != persisted
    {
        return Err(SandboxLeaseMutationError::LeaseShapeChanged);
    }
    Ok(())
}

async fn require_sandbox_crds(client: &kube::Client, names: &[&str]) -> Result<(), Response> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for name in names {
        match crds.get(name).await {
            Ok(crd)
                if crd
                    .status
                    .as_ref()
                    .and_then(|status| status.conditions.as_ref())
                    .is_some_and(|conditions| {
                        conditions.iter().any(|condition| {
                            condition.type_ == "Established" && condition.status == "True"
                        })
                    }) =>
            {
                continue;
            }
            Ok(_) | Err(kube::Error::Api(_)) => {
                return Err(sandbox_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Sandbox API is not installed or established",
                    None,
                ));
            }
            Err(err) => return Err(sandbox_infra_error("Unable to discover Sandbox API", err)),
        }
    }
    Ok(())
}

async fn owned_sandbox_lease(
    leases: &Api<SandboxLease>,
    id: &str,
    identity: &AuthIdentity,
) -> Result<Option<SandboxLease>, kube::Error> {
    match leases.get(id).await {
        Ok(lease) if principal_matches(&lease.spec.requester, identity) => Ok(Some(lease)),
        Ok(_) => Ok(None),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(None),
        Err(err) => Err(err),
    }
}

fn sandbox_lease_response(
    lease: SandboxLease,
    effective_ttl: Option<String>,
) -> SandboxLeaseResponse {
    let id = lease.name_any();
    let status = lease.status.unwrap_or_default();
    SandboxLeaseResponse {
        id,
        phase: status.phase.to_string(),
        pool: lease.spec.pool_ref.name,
        ttl: lease.spec.ttl,
        effective_ttl,
        alias: lease.spec.alias,
        observed_generation: status.observed_generation,
        provisioning_deadline: status.provisioning_deadline,
        ready_at: status.ready_at,
        expires_at: status.expires_at,
        release_cause: status.release_cause,
        placement: status.placement,
        target: status.target.map(caller_visible_provenance),
        conditions: status.conditions,
    }
}

/// Strip the internal composition from provenance before it reaches a caller.
///
/// `SandboxTargetProvenance` is the controller's restart-safe record of exactly
/// what it built, and for a child-placement lease that includes the internal
/// `ClusterLease` and `ClusterInstance` Kobe acquired to host the Sandbox.
///
/// The caller asked for a Sandbox. The cluster underneath it is Kobe's
/// implementation of the pool, not a capability they hold — they cannot
/// connect to it, extend it or release it, and #74 requires that they cannot
/// *discover* it either. Returning its name and UID would hand them the exact
/// identifiers every cluster-lease endpoint is keyed on, turning "no
/// authority" into "no authority, but knows precisely what to ask for".
///
/// Stripped at the response boundary rather than never recorded: teardown must
/// be able to prove that exact instance UID gone, and evidence a controller
/// cannot see is evidence that does not exist.
fn caller_visible_provenance(target: SandboxTargetProvenance) -> SandboxTargetProvenance {
    SandboxTargetProvenance {
        child_cluster_lease: None,
        child_cluster_instance: None,
        child_cluster_kubeconfig_secret: None,
        child_cluster_kubeconfig_sha256: None,
        ..target
    }
}

fn build_sandbox_lease(
    id: &str,
    namespace: &str,
    pool_ref: SandboxPoolReference,
    placement_authority: Option<SandboxPlacementAuthority>,
    ttl: &str,
    alias: Option<&str>,
    identity: &AuthIdentity,
) -> SandboxLease {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(SANDBOX_POOL_LABEL.into(), pool_ref.name.clone());
    labels.insert(REQUESTER_HASH_LABEL.into(), principal_hash(identity));
    if let Some(alias) = alias {
        labels.insert(SANDBOX_ALIAS_LABEL.into(), alias.into());
    }
    let annotations = std::collections::BTreeMap::from([(
        SANDBOX_ADMISSION_ANNOTATION.to_string(),
        SANDBOX_ADMISSION_PENDING.to_string(),
    )]);
    SandboxLease {
        metadata: ObjectMeta {
            name: Some(id.into()),
            namespace: Some(namespace.into()),
            labels: Some(labels),
            annotations: Some(annotations),
            // The finalizer belongs on the admission CREATE, before the
            // provisioning deadline, reservations, or `admitted` marker. A
            // controller-added finalizer would leave a deletion race in that
            // interval where the durable lease could disappear first.
            finalizers: Some(vec![SANDBOX_LEASE_FINALIZER.to_string()]),
            ..Default::default()
        },
        spec: SandboxLeaseSpec {
            pool_ref,
            placement_authority,
            ttl: ttl.into(),
            alias: alias.map(str::to_owned),
            requester: SandboxPrincipal {
                provider: identity.provider.clone(),
                requester_type: identity.requester_type.clone(),
                issuer: identity.issuer.clone(),
                identity: identity.identity.clone(),
            },
        },
        status: None,
    }
}

/// Live lease ids carrying one alias, for this caller only.
///
/// The label selector is a prefilter, not the authorisation: the requester
/// hash narrows the list, and each candidate is then re-checked against the
/// complete principal tuple. A hash collision would otherwise be enough to
/// reach another tenant's lease, and the hash is over caller-influenced
/// values.
///
/// Terminal leases are excluded. An alias names something a caller can still
/// use, and a released lease would otherwise shadow the live one they just
/// created under the same name.
pub(crate) async fn leases_with_alias(
    client: &kube::Client,
    namespace: &str,
    alias: &str,
    identity: &AuthIdentity,
) -> Result<Vec<String>, kube::Error> {
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    let params = ListParams::default().labels(&format!(
        "{REQUESTER_HASH_LABEL}={},{SANDBOX_ALIAS_LABEL}={alias}",
        principal_hash(identity)
    ));
    Ok(leases
        .list(&params)
        .await?
        .into_iter()
        .filter(|lease| principal_matches(&lease.spec.requester, identity))
        .filter(|lease| lease.spec.alias.as_deref() == Some(alias))
        .filter(|lease| {
            !matches!(
                lease
                    .status
                    .as_ref()
                    .map(|status| status.phase)
                    .unwrap_or_default(),
                SandboxLeasePhase::Released
                    | SandboxLeasePhase::Expired
                    | SandboxLeasePhase::Quarantined
            )
        })
        .map(|lease| lease.name_any())
        .collect())
}

fn requester_list_params(identity: &AuthIdentity) -> ListParams {
    ListParams::default().labels(&format!(
        "{REQUESTER_HASH_LABEL}={}",
        principal_hash(identity)
    ))
}

/// Stable, non-reversible identifier for one principal.
///
/// This is **not** merely a lookup prefilter, which is why it must be
/// collision-resistant. It names the reservation objects
/// (`sbx-quota-{hash}-{slot}`, `sbx-alias-{hash}-{alias}`), so two principals
/// sharing a hash share one quota namespace and one alias namespace — and
/// unlike the list paths, the reservation path has no exact-identity recheck to
/// fall back on. A caller able to steer their own identity string toward a
/// victim's hash could then occupy every one of that victim's slots or squat
/// their aliases: targeted denial of service.
///
/// An earlier version used FNV-1a-64 and documented collisions as harmless.
/// That was true of visibility (which does recheck exact identity) and false of
/// the ledger. SHA-256 truncated to 128 bits is collision-resistant here and
/// still a valid DNS label component.
///
/// Components are length-prefixed so `("ab", "c")` and `("a", "bc")` cannot
/// produce the same digest.
///
/// # Changing this function is a migration
///
/// The output names the reservation objects AND the label selector used to find
/// them, so changing it renames every quota slot and alias at once. Objects
/// created under the previous scheme become invisible: they still occupy
/// backend resources, but the new selector cannot see them, so a principal
/// could acquire their full limit again in the new namespace and re-take an
/// alias someone still holds — a quota and alias bypass.
///
/// That was safe to ignore for the FNV-to-SHA-256 change only because
/// `SandboxLease` had never shipped: it is absent from `main`, from `v0.38.0`,
/// and from the released chart, so no object could exist under the old scheme.
/// Once this ships, any further change needs a versioned migration that keeps
/// enforcing against legacy reservations until they are drained.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
enum SandboxReservationKind {
    Quota,
    Alias,
}

/// Derive the only reservation identities this persisted lease may own.
///
/// A quota slot must be the canonical decimal spelling of an index inside the
/// hard admission bound. An alias reservation must name the exact alias stored
/// on the lease; merely having the right principal prefix is not authority.
fn expected_reservation_kind(
    name: &str,
    principal: &str,
    alias: Option<&str>,
) -> Option<SandboxReservationKind> {
    if quota_reservation_slot(name, principal).is_some() {
        return Some(SandboxReservationKind::Quota);
    }

    let alias = alias?;
    (alias_reservation_name(principal, alias) == name).then_some(SandboxReservationKind::Alias)
}

fn quota_reservation_slot(name: &str, principal: &str) -> Option<u32> {
    let (encoded_principal, slot) = parsed_quota_reservation_name(name)?;
    (encoded_principal == principal).then_some(slot)
}

/// Split one canonical quota-token name without trusting its mutable labels.
fn parsed_quota_reservation_name(name: &str) -> Option<(&str, u32)> {
    let raw = name
        .strip_prefix("sbx-")?
        .strip_prefix(SANDBOX_RESERVATION_QUOTA)?
        .strip_prefix('-')?;
    let (principal, raw_slot) = raw.rsplit_once('-')?;
    let slot = raw_slot.parse::<u32>().ok()?;
    (slot < MAX_SANDBOX_CONCURRENCY_SLOTS && quota_reservation_name(principal, slot) == name)
        .then_some((principal, slot))
}

fn counts_toward_advisory_quota(
    reservation: &Lease,
    principal: &str,
    max_concurrent_leases: u32,
) -> bool {
    quota_reservation_slot(&reservation.name_any(), principal)
        .is_some_and(|slot| slot < max_concurrent_leases)
        && reservation
            .labels()
            .get(SANDBOX_RESERVATION_TYPE_LABEL)
            .is_some_and(|value| value == SANDBOX_RESERVATION_QUOTA)
        && reservation
            .labels()
            .get(REQUESTER_HASH_LABEL)
            .is_some_and(|value| value == principal)
        && reservation
            .labels()
            .get(SANDBOX_RESERVATION_LEASE_UID_LABEL)
            .is_some_and(|value| !value.is_empty())
}

/// The same digest as [`principal_hash`], over a stored principal rather than a
/// live authenticated identity. Cleanup runs from the persisted object, not
/// from a request, so it needs this form.
pub(crate) fn principal_hash_for(requester: &SandboxPrincipal) -> String {
    let mut hasher = Sha256::new();
    for component in [
        requester.provider.as_bytes(),
        requester.issuer.as_bytes(),
        requester.identity.as_bytes(),
    ] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component);
    }
    hasher
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn principal_hash(identity: &AuthIdentity) -> String {
    let mut hasher = Sha256::new();
    for component in [
        identity.provider.as_bytes(),
        identity.issuer.as_bytes(),
        identity.identity.as_bytes(),
    ] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component);
    }
    hasher
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The request handler's active budget after its `SandboxLease` CREATE.
///
/// This is deliberately shorter than the controller deadline below. The local
/// timeout stops ordinary slow/stalled work early, but is not trusted as the
/// safety proof: dropped HTTP futures can still leave an API request in
/// flight. The durable cancelled checkpoint and orphan-ledger sweep close that
/// race.
const SANDBOX_ACTIVE_ADMISSION_TIMEOUT_SECS: u64 = 480;

/// Maximum extra time an HTTP request owns ambiguous admission arbitration.
///
/// The durable parent and supervised reaper make handoff safe, so an API
/// outage must not retain the request forever after its active budget elapsed.
/// Thirty seconds still permits several exact-state retries while remaining
/// comfortably inside the two-minute margin before reaper eligibility.
const SANDBOX_ADMISSION_RESOLUTION_TIMEOUT_SECS: u64 = 30;

/// Poll one active-admission operation only while the request owns its budget.
///
/// The absolute deadline is shared by every Kubernetes await, including
/// preflight and cleanup, so moving work between stages cannot silently extend
/// the HTTP lifetime. Shutdown has the same bound: before parent creation it
/// is a safe retryable refusal; after creation callers must use the durable
/// admission arbiter and return a non-retry handoff when classification cannot
/// finish. The erased, heap-backed future is also an intentional stack bound:
/// recovery, reservation and exact-cleanup stages each retain several object
/// snapshots and must not form one deeply nested poll chain on an Axum worker.
fn await_admission_stage_until<'a, T, F>(
    deadline: tokio::time::Instant,
    shutdown: &'a tokio_util::sync::CancellationToken,
    future: F,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, SandboxLeaseMutationError>> + Send + 'a>,
>
where
    T: Send + 'a,
    F: std::future::Future<Output = T> + Send + 'a,
{
    Box::pin(async move {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Err(SandboxLeaseMutationError::AdmissionShuttingDown),
            _ = tokio::time::sleep_until(deadline) => {
                Err(SandboxLeaseMutationError::AdmissionDeadlineExceeded)
            }
            output = future => Ok(output),
        }
    })
}

/// Bound best-effort deletion by the same absolute request envelope.
async fn delete_exact_pending_lease_until(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    deadline: tokio::time::Instant,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<(), SandboxLeaseMutationError> {
    await_admission_stage_until(
        deadline,
        shutdown,
        delete_exact_pending_lease(leases, reservations, lease),
    )
    .await?
}

/// Maximum wall-clock budget before the durable admission arbiter may cancel a
/// still-pending attempt.
///
/// Age is deliberately **not** treated as proof that the handler died. At this
/// boundary the reaper first writes [`SANDBOX_ADMISSION_CANCELLED`] with the
/// same UID/resourceVersion/state CAS used by admission. That write actively
/// revokes the handler's right to commit; only the winning state transition is
/// proof. Deletion and reservation release happen after that checkpoint.
const SANDBOX_PENDING_CANCEL_DEADLINE_SECS: i64 = 600;

/// Whether a pending admission has reached the point where it may be cancelled.
///
/// Pure so the boundary is testable without a clock: `now` is supplied. This
/// authorizes a cancellation attempt, never deletion by itself.
fn pending_admission_cancellation_due(
    created_at: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(created_at) = created_at else {
        // No API-server timestamp means we cannot enforce the advertised
        // budget. Fail closed instead of guessing that cancellation is due.
        return false;
    };
    let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    (now - created_at.with_timezone(&chrono::Utc)).num_seconds()
        >= SANDBOX_PENDING_CANCEL_DEADLINE_SECS
}

#[derive(Debug)]
enum PendingAdmissionCancellation {
    /// This caller won the pending -> cancelled CAS.
    Cancelled(SandboxLease),
    /// Admission won the same CAS; the lease must remain placeable.
    AdmissionWon(SandboxLease),
    /// The exact lease is already absent. Its detached ledger entries may
    /// still need the orphan sweep below.
    Gone,
}

#[derive(Debug)]
enum AdmissionResolution {
    /// The exact lease is durably admitted; report the existing handle.
    Admitted,
    /// Cancellation/absence won, so a retry cannot duplicate a Sandbox.
    Cancelled,
    /// Resolution could not finish before process shutdown or an invariant
    /// failure. The durable parent is the supervised reaper's handoff; return
    /// its distinct `admission_pending` handle so the caller polls rather than
    /// treating it as placeable or submitting again.
    HandedOff,
}

/// Atomically revoke a pending admission before any reap is attempted.
///
/// Both this function and [`admit_sandbox_lease`] test the exact UID,
/// resourceVersion, and `pending` marker in one JSON Patch. Therefore exactly
/// one can win: cancellation makes every paused or delayed admission patch
/// stale, while a committed admission makes cancellation observe `admitted`
/// and leave the lease alone. A retry after a lost PATCH response resolves the
/// winner by re-reading the exact object. The immediately preceding read must
/// also remain a pristine pre-placement shape; a lifecycle that drifted to
/// Provisioning/Ready while retaining `pending` is never cancelled.
async fn cancel_pending_admission(
    leases: &Api<SandboxLease>,
    expected: &SandboxLease,
) -> Result<PendingAdmissionCancellation, SandboxLeaseMutationError> {
    let name = expected.name_any();
    let expected_uid = expected
        .uid()
        .ok_or(SandboxLeaseMutationError::MissingUid)?;
    let mut last_patch_error = None;

    // One retry resolves a committed-but-lost response. A second concurrent
    // writer can still race that read; leave it for the next durable sweep
    // rather than spinning against the API server.
    for _ in 0..2 {
        let current = match leases.get(&name).await {
            Ok(current) => current,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Ok(PendingAdmissionCancellation::Gone);
            }
            Err(error) => return Err(error.into()),
        };
        if current.uid().as_deref() != Some(expected_uid.as_str()) {
            return Err(SandboxLeaseMutationError::UidChanged);
        }
        match current
            .annotations()
            .get(SANDBOX_ADMISSION_ANNOTATION)
            .map(String::as_str)
        {
            Some(SANDBOX_ADMISSION_ADMITTED) => {
                validate_lease_shape(expected, &current, SANDBOX_ADMISSION_ADMITTED)?;
                return Ok(PendingAdmissionCancellation::AdmissionWon(current));
            }
            Some(SANDBOX_ADMISSION_CANCELLED) => {
                validate_lease_shape_unadmitted(expected, &current)?;
                return Ok(PendingAdmissionCancellation::Cancelled(current));
            }
            Some(SANDBOX_ADMISSION_PENDING) => {
                validate_lease_shape_unadmitted(expected, &current)?;
            }
            _ => return Err(SandboxLeaseMutationError::UnexpectedAdmissionState),
        }

        let resource_version = current
            .resource_version()
            .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
        let patch = crate::controllers::lease::json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": expected_uid },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            {
                "op": "test",
                "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
                "value": SANDBOX_ADMISSION_PENDING
            },
            {
                "op": "replace",
                "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
                "value": SANDBOX_ADMISSION_CANCELLED
            }
        ]));
        match leases
            .patch(&name, &PatchParams::default(), &Patch::Json::<()>(patch))
            .await
        {
            Ok(cancelled) => {
                validate_lease_shape(&current, &cancelled, SANDBOX_ADMISSION_CANCELLED)?;
                return Ok(PendingAdmissionCancellation::Cancelled(cancelled));
            }
            Err(error) => last_patch_error = Some(error),
        }
    }

    Err(SandboxLeaseMutationError::Kubernetes(
        last_patch_error.expect("a bounded cancellation retry always records its PATCH error"),
    ))
}

/// Cancel one attempt and only then remove its lease and reservations.
///
/// `AdmissionWon` is returned to the caller instead of being converted to a
/// failure: doing otherwise would invite a retry while an admitted Sandbox is
/// already placeable.
async fn cancel_and_reap_pending_admission(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<PendingAdmissionCancellation, SandboxLeaseMutationError> {
    match cancel_pending_admission(leases, lease).await? {
        PendingAdmissionCancellation::Cancelled(cancelled) => {
            delete_exact_pending_lease(leases, reservations, &cancelled).await?;
            Ok(PendingAdmissionCancellation::Cancelled(cancelled))
        }
        PendingAdmissionCancellation::Gone => {
            let uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
            release_reservations_for_lease(reservations, lease, &uid).await?;
            Ok(PendingAdmissionCancellation::Gone)
        }
        admitted @ PendingAdmissionCancellation::AdmissionWon(_) => Ok(admitted),
    }
}

/// Resolve an elapsed handler budget through the durable state machine.
///
/// Tokio's timeout only stops this task from polling the request future; it
/// cannot prove that an HTTP request was not already committed by Kubernetes.
/// This function supplies that proof by racing the exact cancellation CAS
/// against admission, then reporting success if admission actually won. A
/// cancelled/absent parent is safe failure, and the independent orphan sweep
/// recovers any reservation POST that becomes visible afterwards.
///
/// The resolver may briefly outlive the active deadline during an API outage,
/// but it is bounded by both process shutdown and a separate handoff deadline.
/// On either bound (or an invariant failure that prevents safe classification)
/// it returns [`AdmissionResolution::HandedOff`]. The caller then emits the
/// distinct `admission_pending` 202+handle contract instead of either a normal
/// accepted lease or an ambiguous 503; the durable parent is left for the
/// supervised admission reaper. This keeps HTTP lifetime bounded without
/// inviting a duplicate.
async fn resolve_timed_out_admission(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    expected_provisioning_deadline: &str,
    expected_reservations: Option<&[AdmissionReservation]>,
    expected_access_gate: Option<&crate::sandbox_access_ledger::AccessGateReference>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> AdmissionResolution {
    let resolution_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(SANDBOX_ADMISSION_RESOLUTION_TIMEOUT_SECS);
    resolve_timed_out_admission_until(
        leases,
        reservations,
        lease,
        expected_provisioning_deadline,
        expected_reservations,
        expected_access_gate,
        shutdown,
        resolution_deadline,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_timed_out_admission_until(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    expected_provisioning_deadline: &str,
    expected_reservations: Option<&[AdmissionReservation]>,
    expected_access_gate: Option<&crate::sandbox_access_ledger::AccessGateReference>,
    shutdown: &tokio_util::sync::CancellationToken,
    resolution_deadline: tokio::time::Instant,
) -> AdmissionResolution {
    let mut retry_delay = std::time::Duration::from_millis(50);
    let outcome = loop {
        let attempt = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return AdmissionResolution::HandedOff,
            _ = tokio::time::sleep_until(resolution_deadline) => {
                warn!(
                    lease_id = %lease.name_any(),
                    "Sandbox admission arbitration exceeded its handoff budget"
                );
                return AdmissionResolution::HandedOff;
            }
            attempt = cancel_and_reap_pending_admission(leases, reservations, lease) => attempt,
        };
        match attempt {
            Ok(outcome) => break outcome,
            // An API/transport error can be a lost response to either side of
            // the arbitration. Returning 503 here would revive the duplicate
            // admission bug: the caller could retry while the original admit
            // PATCH was merely late. Keep this resolver alive (the admission
            // future itself is already gone) until a durable state is visible
            // or the bounded handoff deadline expires. The controller reaper
            // races on the same CAS independently.
            Err(SandboxLeaseMutationError::Kubernetes(error)) => {
                warn!(
                    lease_id = %lease.name_any(),
                    error = %error,
                    "Sandbox admission arbitration is unresolved; retrying exact cancellation"
                );
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return AdmissionResolution::HandedOff,
                    _ = tokio::time::sleep_until(resolution_deadline) => {
                        return AdmissionResolution::HandedOff;
                    }
                    _ = tokio::time::sleep(retry_delay) => {}
                }
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_secs(2));
            }
            Err(error) => {
                warn!(
                    lease_id = %lease.name_any(),
                    %error,
                    "Sandbox admission could not be classified; handing its durable handle to the reaper"
                );
                return AdmissionResolution::HandedOff;
            }
        }
    };

    match outcome {
        PendingAdmissionCancellation::Cancelled(_) | PendingAdmissionCancellation::Gone => {
            AdmissionResolution::Cancelled
        }
        PendingAdmissionCancellation::AdmissionWon(admitted) => {
            let validation = require_provisioning_deadline(
                &admitted,
                expected_provisioning_deadline,
            )
            .and_then(|()| {
                let persisted = persisted_reservation_provenance(&admitted)?;
                if let Some(expected_reservations) = expected_reservations
                    && persisted != canonical_reservation_provenance(lease, expected_reservations)?
                {
                    return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                        "timed-out admission committed different reservation provenance".into(),
                    ));
                }
                if let Some(expected_access_gate) = expected_access_gate
                    && crate::sandbox_access_ledger::persisted_gate_reference(&admitted)?
                        != *expected_access_gate
                {
                    return Err(SandboxLeaseMutationError::AccessGateProvenanceChanged);
                }
                Ok(())
            });
            if let Err(error) = validation {
                warn!(
                    lease_id = %lease.name_any(),
                    %error,
                    "Admitted Sandbox could not be validated; returning its durable handle without inviting a retry"
                );
                return AdmissionResolution::HandedOff;
            }
            AdmissionResolution::Admitted
        }
    }
}

#[derive(Debug)]
enum AdmissionSweepResolution {
    Reaped,
    AdmissionWon(String),
    ReleaseRequested,
}

/// Classify one stale admission before attempting its cancellation CAS.
///
/// Only a pristine admission parent may transition `pending -> cancelled`.
/// Provisioning/Ready/Releasing status is evidence that controller work may
/// already exist even when the marker drifted backwards. Such an object is
/// atomically repaired to `admitted` plus release intent only after exact live
/// reservation proof; incomplete or corrupt proof returns an error without a
/// parent or ledger mutation. [`cancel_pending_admission`] repeats the pristine
/// check on its fresh GET, closing the race between LIST classification and CAS.
async fn reconcile_expired_admission_candidate(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AdmissionSweepResolution>, SandboxLeaseMutationError> {
    let admission = lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str);
    let should_cancel = admission == Some(SANDBOX_ADMISSION_PENDING)
        && pending_admission_cancellation_due(
            lease
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|timestamp| timestamp.0.to_string())
                .as_deref(),
            now,
        );
    let should_finish_cancel = admission == Some(SANDBOX_ADMISSION_CANCELLED);
    if !should_cancel && !should_finish_cancel {
        return Ok(None);
    }

    if pristine_pending_lease(lease).is_ok() {
        let outcome = if should_cancel {
            cancel_and_reap_pending_admission(leases, reservations, lease).await?
        } else {
            delete_exact_pending_lease(leases, reservations, lease).await?;
            PendingAdmissionCancellation::Cancelled(lease.clone())
        };
        return Ok(Some(match outcome {
            PendingAdmissionCancellation::Cancelled(_) | PendingAdmissionCancellation::Gone => {
                AdmissionSweepResolution::Reaped
            }
            PendingAdmissionCancellation::AdmissionWon(admitted) => {
                AdmissionSweepResolution::AdmissionWon(admitted.name_any())
            }
        }));
    }

    let management_namespace = leases
        .namespace()
        .ok_or(SandboxLeaseMutationError::LeaseShapeChanged)?;
    let persisted = proven_active_release_shape(lease, management_namespace)?;
    repair_admitted_release_intent(leases, reservations, lease, &persisted).await?;
    Ok(Some(AdmissionSweepResolution::ReleaseRequested))
}

/// Run one replica-wide admission pass.
///
/// Split from the interval loop so lifecycle classification and its mutation
/// ordering can be tested without a clock-driven background task.
async fn reap_expired_pending_admissions_once(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let all = match leases.list(&ListParams::default()).await {
        Ok(all) => all,
        Err(error) => {
            warn!(error = %error, "Sandbox admission reaper could not list leases");
            return;
        }
    };
    for lease in all.items {
        match reconcile_expired_admission_candidate(leases, reservations, &lease, now).await {
            Ok(None) => {}
            Ok(Some(AdmissionSweepResolution::Reaped)) => info!(
                lease_id = %lease.name_any(),
                "Cancelled and reaped an expired Sandbox admission"
            ),
            Ok(Some(AdmissionSweepResolution::AdmissionWon(admitted_name))) => info!(
                lease_id = %admitted_name,
                "Sandbox admission won the cancellation CAS; leaving it placeable"
            ),
            Ok(Some(AdmissionSweepResolution::ReleaseRequested)) => warn!(
                lease_id = %lease.name_any(),
                "Repaired drifted Sandbox admission and requested verified teardown"
            ),
            Err(error) => warn!(
                lease_id = %lease.name_any(),
                error = %error,
                "Expired Sandbox admission is ambiguous; retained unchanged"
            ),
        }
    }
}

/// Background sweep that reclaims abandoned admission state for every principal.
///
/// The create-path sweep only helps a caller who comes back. A principal whose
/// request died mid-admission and who never calls create again keeps their
/// quota slot and alias consumed indefinitely — and an operator has no way to
/// see it, because the lease looks like an ordinary `pending` object that no
/// controller will ever touch (placement ignores anything not `admitted`).
///
/// This runs on the operator, so recovery no longer depends on the victim
/// retrying. The wall-clock deadline authorizes an exact pending-to-cancelled
/// CAS; it is the committed cancellation, not age, that authorizes deletion.
/// Detached reservations are also swept against the parent name+UID, so a
/// reservation CREATE that commits after cancellation/deletion is eventually
/// reclaimed rather than becoming a permanent quota leak.
///
/// Pristine cancellation does not depend on placement. If an active lifecycle
/// has drifted back to `pending`, however, this reaper only repairs admission
/// plus release intent; the placement controller remains responsible for the
/// resulting verified teardown. Missing lifecycle proof fails closed.
pub async fn run_sandbox_admission_reaper(
    client: kube::Client,
    lease_namespace: &str,
    reservation_namespace: &str,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), lease_namespace);
    let reservations: Api<Lease> = Api::namespaced(client, reservation_namespace);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.cancelled() => {
                info!("Sandbox admission reaper shutting down");
                return;
            },
        }

        reap_expired_pending_admissions_once(&leases, &reservations, chrono::Utc::now()).await;

        // Independent of the parent LIST: a late reservation POST can commit
        // after the parent was already cancelled and deleted. Its exact
        // parent name+UID is still carried on the ledger object, so this sweep
        // remains able to recover it on every later pass.
        reap_orphaned_admission_reservations(&leases, &reservations).await;
    }
}

/// Release quota and aliases stranded by a request that died mid-admission.
///
/// Reservations are created before the lease is admitted and deliberately have
/// no owner reference: garbage collection must not be able to release quota
/// before Kobe proves the tenant footprint absent. If the process dies (or a
/// cleanup path itself fails) between acquiring reservations and committing
/// admission, the lease stays `pending` forever, no placement controller touches
/// it, and its slot plus alias remain consumed. The caller then gets 429 or 409
/// on every retry with no way out but this exact-fenced cleanup.
///
/// This sweep is the recovery path. It runs on the caller's own next create, so
/// the principal who was locked out is exactly the one who unlocks themselves.
///
/// Scope, stated narrowly: this create-path optimization reclaims only **this
/// principal's** abandoned pending leases. The replica-wide admission reaper
/// provides the equivalent recovery when the principal never calls create
/// again.
async fn cancel_expired_pending_admissions(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    identity: &AuthIdentity,
    now: chrono::DateTime<chrono::Utc>,
) {
    let stale = match leases.list(&requester_list_params(identity)).await {
        Ok(list) => list,
        // Best-effort: a failed sweep must not fail the create. The caller
        // simply keeps whatever quota they already had.
        Err(error) => {
            warn!(error = %error, "Sandbox abandoned-lease sweep failed to list");
            return;
        }
    };

    for lease in stale.items {
        // The label prefilter is a hash, so it can group two principals.
        // Recheck exact identity before deleting anything: without this, a hash
        // collision would let one principal reap another's leases.
        if !principal_matches(&lease.spec.requester, identity) {
            continue;
        }
        match reconcile_expired_admission_candidate(leases, reservations, &lease, now).await {
            Ok(None) => {}
            Ok(Some(AdmissionSweepResolution::Reaped)) => info!(
                lease_id = %lease.name_any(),
                "Cancelled and reclaimed an expired Sandbox admission"
            ),
            Ok(Some(AdmissionSweepResolution::AdmissionWon(admitted_name))) => info!(
                lease_id = %admitted_name,
                "Sandbox admission won the caller-side cancellation CAS"
            ),
            Ok(Some(AdmissionSweepResolution::ReleaseRequested)) => warn!(
                lease_id = %lease.name_any(),
                "Caller sweep repaired drifted admission and requested verified teardown"
            ),
            Err(error) => warn!(
                lease_id = %lease.name_any(),
                error = %error,
                "Caller sweep found ambiguous Sandbox admission; retained unchanged"
            ),
        }
    }
}

/// How long a lease that reached a clean terminal phase is kept before the
/// record itself is retired. Seven days, expressed in the units
/// [`parse_duration`] understands.
///
/// The number is a policy call, and the unit is the part that matters. A
/// terminal lease is the audit record of who held what, for how long, and
/// whether cleanup was proven — the thing an operator reads *after* somebody
/// notices something went wrong. A window measured in hours would routinely
/// have the evidence gone before the question was asked; one measured in months
/// grows `etcd` without bound holding records nobody will ever read. A week
/// spans a weekend plus the working day it takes to notice, which is the
/// shortest window that still answers the question the record exists to answer.
const DEFAULT_SANDBOX_LEASE_RETENTION: &str = "168h";

/// Floor on the configured retention window.
///
/// Not a guard against an operator wanting a short window — it is a guard
/// against a mistyped one. `7s` parses perfectly and would delete every
/// terminal lease almost as fast as it was written, destroying the audit trail
/// with no error anywhere to explain it. An hour is far below any retention
/// worth configuring and far above the time it takes to read a record that just
/// appeared, so clamping here can only ever rescue a typo.
const MIN_SANDBOX_LEASE_RETENTION_SECS: i64 = 3600;

/// Environment variable carrying the retention window override.
pub(crate) const ENV_SANDBOX_LEASE_RETENTION: &str = "KOBE_SANDBOX_LEASE_RETENTION";

/// Resolve the terminal-lease retention window from operator configuration.
///
/// Takes the configured string rather than reading the environment itself, so
/// the parsing and clamping rules are assertable without mutating process-wide
/// state that no two tests can own at the same time.
///
/// Every rejection falls back to the default rather than to zero or to
/// "sweep nothing". Zero would delete records on a typo; disabling the sweep
/// silently would reintroduce the unbounded growth this exists to stop, and an
/// operator who mistyped a duration has said nothing about wanting either.
pub(crate) fn sandbox_lease_retention(configured: Option<&str>) -> chrono::Duration {
    let default = parse_duration(DEFAULT_SANDBOX_LEASE_RETENTION)
        .expect("the default Sandbox lease retention window parses");
    let Some(configured) = configured
        .map(str::trim)
        .filter(|configured| !configured.is_empty())
    else {
        return default;
    };
    // `parse_duration` also refuses anything past a year, which is the same
    // answer as unparseable here: a value that far out is not a retention
    // policy, it is a mistake.
    let Some(parsed) = parse_duration(configured) else {
        warn!(
            env = ENV_SANDBOX_LEASE_RETENTION,
            value = %configured,
            default = DEFAULT_SANDBOX_LEASE_RETENTION,
            "Ignoring an unusable Sandbox lease retention window; using the default"
        );
        return default;
    };
    let floor = chrono::Duration::seconds(MIN_SANDBOX_LEASE_RETENTION_SECS);
    if parsed < floor {
        warn!(
            env = ENV_SANDBOX_LEASE_RETENTION,
            value = %configured,
            floor = %format_duration(&floor),
            "Sandbox lease retention window is below the floor; clamping"
        );
        return floor;
    }
    parsed
}

/// When the lease reached a terminal phase, as recorded on the object itself.
///
/// `CleanupVerified` is the only durable record of that moment. The phase
/// carries no timestamp, and `creationTimestamp` dates the lease's birth rather
/// than its end — sweeping on that would retire a lease that ran for a
/// fortnight the instant it was released, which is precisely when its record is
/// most likely to be wanted.
///
/// Only the `True` form counts. The `False` form is written by
/// [`quarantine_lease`](crate::controllers::sandbox) and dates the moment
/// teardown became *unprovable*, so reading it as a terminal timestamp would
/// hand the sweep exactly the objects it must never touch.
fn terminal_lease_recorded_at(status: &crate::crd::SandboxLeaseStatus) -> Option<&str> {
    status
        .conditions
        .iter()
        .find(|condition| {
            condition.condition_type == crate::controllers::sandbox::CLEANUP_VERIFIED_CONDITION
                && condition.status == crate::crd::SandboxConditionStatus::True
        })
        .and_then(|condition| condition.last_transition_time.as_deref())
}

/// Whether a lease's record has outlived its retention window and may be
/// retired.
///
/// Pure so the rules are assertable without a cluster or a clock: `now` and the
/// window are supplied.
///
/// The phase test is an exhaustive `match` with no wildcard arm, deliberately.
/// A wildcard would let a phase added later be swept — or spared — by whichever
/// side of the pattern it happened to land on, with nobody forced to decide. As
/// written, a new phase is a compile error at the one place the decision
/// belongs.
fn terminal_lease_is_retired(
    phase: SandboxLeasePhase,
    terminal_since: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    retention: chrono::Duration,
) -> bool {
    match phase {
        // The clean terminal phases. Cleanup was proven before either was
        // written, and their reservations were released at that same moment, so
        // retiring the record cannot release capacity — it only removes a row.
        SandboxLeasePhase::Released | SandboxLeasePhase::Expired => {}
        // Quarantined is terminal, and is the one terminal phase that must
        // never be swept. It still consumes capacity, on purpose: it is what
        // withholds a slot whose teardown nobody could prove. Deleting the
        // object would hand that slot back on no evidence at all and take the
        // record of the unproven teardown with it — the exact double-booking
        // the quarantine exists to prevent, now with nothing left to show for
        // it. It leaves only by being cleared to `Released`/`Expired`, after
        // which the window starts from that transition.
        SandboxLeasePhase::Quarantined => return false,
        // Not terminal at all: these leases may still be running.
        SandboxLeasePhase::Pending
        | SandboxLeasePhase::Provisioning
        | SandboxLeasePhase::Ready
        | SandboxLeasePhase::Releasing => return false,
    }

    let Some(terminal_since) = terminal_since else {
        // No proof of when it ended is no proof that it ended long enough ago.
        // Keeping an undated record costs one row; deleting it may destroy the
        // audit trail of a lease that ended a minute ago.
        return false;
    };
    let Ok(terminal_since) = chrono::DateTime::parse_from_rfc3339(terminal_since) else {
        return false;
    };
    now - terminal_since.with_timezone(&chrono::Utc) >= retention
}

/// Retire terminal Sandbox lease records once they are past their retention
/// window.
///
/// `Released` and `Expired` leases stop consuming capacity the moment they are
/// written, so this is not a capacity reclaim and never was — the objects
/// simply accumulate, one per Sandbox ever leased, forever. This bounds that at
/// the cost of the audit record, which is why the window is generous and why
/// `Quarantined` is excluded outright.
///
/// Before a clean terminal phase is written, reconciliation has explicitly
/// verified the management footprint absent or consumed the exact child
/// teardown proof, then released every admission reservation. Claim, allocation
/// fence, and child-handle tombstones are not GC dependents of this record. A
/// sweep always considers them before the outer record, and their own reaper
/// still requires the exact outer UID to be absent on a later pass.
///
/// Runs on every replica rather than under leader election. Each delete is
/// fenced on the exact UID and resourceVersion, so replicas racing on the same
/// object produce one delete and a 404/409 for the loser, which is the same
/// outcome as running alone.
pub async fn run_sandbox_lease_reaper(
    client: kube::Client,
    namespace: &str,
    interval: std::time::Duration,
    retention: chrono::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    info!(
        retention = %format_duration(&retention),
        "Starting Sandbox lease retention sweep"
    );
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }
        let now = chrono::Utc::now();
        crate::controllers::sandbox::sweep_sandbox_allocation_tombstones(&client, namespace, now)
            .await;
        sweep_retired_leases(&leases, retention, now).await;
    }
    info!("Sandbox lease retention sweep shut down");
}

/// One pass of the retention sweep.
///
/// Split from the timer loop so a test can run exactly one tick and assert what
/// it did, rather than racing a sleep.
async fn sweep_retired_leases(
    leases: &Api<SandboxLease>,
    retention: chrono::Duration,
    now: chrono::DateTime<chrono::Utc>,
) {
    let listed = match leases.list(&ListParams::default()).await {
        Ok(listed) => listed,
        // Best-effort by design: a window this long has no deadline a single
        // missed tick could threaten.
        Err(error) => {
            warn!(error = %error, "Sandbox lease retention sweep failed to list");
            return;
        }
    };

    for lease in listed {
        let Some(status) = lease.status.as_ref() else {
            continue;
        };
        if !terminal_lease_is_retired(
            status.phase,
            terminal_lease_recorded_at(status),
            now,
            retention,
        ) {
            continue;
        }
        match delete_retired_lease(leases, &lease, retention, now).await {
            Ok(true) => info!(
                lease_id = %lease.name_any(),
                phase = %status.phase,
                "Retired a terminal Sandbox lease past its retention window"
            ),
            // Gone already, or no longer eligible on re-read. Both are the
            // sweep declining to act, not a failure.
            Ok(false) => {}
            Err(error) => warn!(
                lease_id = %lease.name_any(),
                error = %error,
                "Could not retire a terminal Sandbox lease"
            ),
        }
    }
}

/// Delete one retired lease, fenced on the object the decision was made about.
///
/// Returns whether this call is what removed it.
///
/// The eligibility test is re-run against the *re-read* object, not the listed
/// one. A lease can be quarantined between the list and the delete — teardown
/// verification is asynchronous and a controller may reopen the question — and
/// acting on the stale copy would delete the one kind of record that must never
/// be deleted. The resourceVersion precondition catches the same race at the
/// API server; this catches it before the request is even sent, and says why.
async fn delete_retired_lease(
    leases: &Api<SandboxLease>,
    lease: &SandboxLease,
    retention: chrono::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, SandboxLeaseMutationError> {
    let expected_uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let current = match leases.get(&lease.name_any()).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    // A same-named lease created since the list is a different tenant's record
    // that has not been terminal for a second, let alone a week.
    if current.uid().as_deref() != Some(expected_uid.as_str()) {
        return Err(SandboxLeaseMutationError::UidChanged);
    }
    let Some(status) = current.status.as_ref() else {
        return Ok(false);
    };
    if !terminal_lease_is_retired(
        status.phase,
        terminal_lease_recorded_at(status),
        now,
        retention,
    ) {
        return Ok(false);
    }

    let resource_version = current
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(expected_uid),
            resource_version: Some(resource_version),
        }),
        ..Default::default()
    };
    match leases.delete(&current.name_any(), &params).await {
        Ok(_) => Ok(true),
        // 404: somebody else retired it. 409: it changed between the re-read
        // and the delete, so the decision was made about a version that no
        // longer exists. Neither is an error, and both mean "not by us".
        Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Whether this principal owns the lease, by the complete identity tuple.
///
/// Exposed for #81's resolver so ownership is decided in exactly one place: a
/// second implementation is a second chance to compare on identity alone and
/// let one provider's `alice` reach another's.
pub(crate) fn principal_owns_lease(lease: &SandboxLease, identity: &AuthIdentity) -> bool {
    principal_matches(&lease.spec.requester, identity)
}

fn principal_matches(requester: &SandboxPrincipal, identity: &AuthIdentity) -> bool {
    requester.provider == identity.provider
        && requester.issuer == identity.issuer
        && requester.identity == identity.identity
}

fn sandbox_pool_reference(pool: &SandboxPool) -> Result<SandboxPoolReference, String> {
    pool.namespace()
        .ok_or_else(|| "SandboxPool has no namespace".to_string())?;
    let uid = pool
        .uid()
        .ok_or_else(|| "SandboxPool has no UID".to_string())?;
    let generation = pool
        .metadata
        .generation
        .ok_or_else(|| "SandboxPool has no generation".to_string())?;
    Ok(SandboxPoolReference {
        name: pool.name_any(),
        uid,
        generation,
    })
}

/// Copy only controller-certified child placement identity into a new lease.
/// Management leases retain their existing wire shape.
fn sandbox_placement_authority_for_admission(
    pool: &SandboxPool,
) -> Result<Option<SandboxPlacementAuthority>, String> {
    let recorded = pool
        .status
        .as_ref()
        .and_then(|status| status.placement_authority.as_ref());
    match &pool.spec.placement {
        SandboxPlacement::Management {} => {
            if recorded.is_some() {
                return Err(
                    "management SandboxPool unexpectedly records placementAuthority".into(),
                );
            }
            Ok(None)
        }
        SandboxPlacement::ChildCluster { cluster_pool_ref } => {
            let status = pool
                .status
                .as_ref()
                .ok_or_else(|| "child SandboxPool has no status".to_string())?;
            let authority = recorded.ok_or_else(|| {
                "child SandboxPool has no certified placementAuthority".to_string()
            })?;
            let namespace = pool
                .namespace()
                .ok_or_else(|| "SandboxPool has no namespace".to_string())?;
            if authority.api_version != "kobe.kunobi.ninja/v1alpha1"
                || authority.kind != "ClusterPool"
                || authority.namespace != namespace
                || authority.name != *cluster_pool_ref
                || authority.uid.is_empty()
                || authority.generation < 1
            {
                return Err(
                    "child SandboxPool placementAuthority does not match its exact ClusterPool"
                        .into(),
                );
            }
            let composition_eligible = status.conditions.iter().any(|condition| {
                condition.condition_type == "Ready"
                    && condition.status == crate::crd::SandboxConditionStatus::False
                    && condition.reason == "CompositionEligible"
                    && condition.observed_generation == pool.metadata.generation
            });
            if !composition_eligible {
                return Err(
                    "child SandboxPool placementAuthority lacks current CompositionEligible status"
                        .into(),
                );
            }
            Ok(Some(authority.clone()))
        }
    }
}

/// Persist the admission-time setup bound before quota can be committed.
///
/// The UID/resourceVersion tests make the checkpoint belong to the exact
/// object returned by CREATE. A lost response is resolved by re-reading that
/// object and accepting only the exact deadline; no reservation exists yet, so
/// every failure remains safely removable as an unadmitted lease.
async fn persist_pending_provisioning_deadline(
    leases: &Api<SandboxLease>,
    lease: &SandboxLease,
    deadline: &str,
) -> Result<SandboxLease, SandboxLeaseMutationError> {
    let uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let resource_version = lease
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    let mut status = lease.status.clone().unwrap_or_default();
    if status.phase != SandboxLeasePhase::Pending {
        return Err(SandboxLeaseMutationError::UnexpectedAdmissionState);
    }
    status.provisioning_deadline = Some(deadline.to_string());
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "add", "path": "/status", "value": status }
    ]));

    match leases
        .patch_status(
            &lease.name_any(),
            &PatchParams::default(),
            &Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(stamped) => {
            validate_lease_shape(lease, &stamped, SANDBOX_ADMISSION_PENDING)?;
            require_provisioning_deadline(&stamped, deadline)?;
            Ok(stamped)
        }
        Err(_patch_error) => {
            let current = leases.get(&lease.name_any()).await?;
            validate_lease_shape(lease, &current, SANDBOX_ADMISSION_PENDING)?;
            require_provisioning_deadline(&current, deadline)?;
            Ok(current)
        }
    }
}

fn require_provisioning_deadline(
    lease: &SandboxLease,
    expected: &str,
) -> Result<(), SandboxLeaseMutationError> {
    if lease
        .status
        .as_ref()
        .and_then(|status| status.provisioning_deadline.as_deref())
        == Some(expected)
    {
        Ok(())
    } else {
        Err(SandboxLeaseMutationError::ProvisioningDeadlineNotCommitted)
    }
}

async fn admit_sandbox_lease(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    admission_reservations: &[AdmissionReservation],
    access_gate: &crate::sandbox_access_ledger::AccessGateReference,
) -> Result<(), SandboxLeaseMutationError> {
    let name = lease.name_any();
    let uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let resource_version = lease
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    let reservation_provenance = encoded_reservation_provenance(lease, admission_reservations)?;
    let access_gate_provenance = crate::sandbox_access_ledger::encode_gate_reference(access_gate)?;
    // Admission and expiry cancellation are the two sides of one arbitration.
    // Testing UID, resourceVersion, and the pending marker in this same API
    // transaction means neither a stale handler nor a same-named replacement
    // can become admitted after the reaper commits `cancelled`.
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        {
            "op": "test",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
            "value": SANDBOX_ADMISSION_PENDING
        },
        {
            "op": "replace",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
            "value": SANDBOX_ADMISSION_ADMITTED
        },
        {
            "op": "add",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-reservations",
            "value": reservation_provenance
        },
        {
            "op": "add",
            "path": "/metadata/annotations/kobe.kunobi.ninja~1sandbox-access-gate",
            "value": access_gate_provenance
        }
    ]));
    match leases
        .patch(&name, &PatchParams::default(), &Patch::Json::<()>(patch))
        .await
    {
        Ok(admitted) => {
            validate_lease_shape(lease, &admitted, SANDBOX_ADMISSION_ADMITTED)?;
            if persisted_reservation_provenance(&admitted)?
                != canonical_reservation_provenance(lease, admission_reservations)?
            {
                return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                    "admission response changed the persisted reservation set".into(),
                ));
            }
            if !crate::sandbox_access_ledger::persisted_gate_reference(&admitted)
                .is_ok_and(|actual| actual == *access_gate)
            {
                return Err(SandboxLeaseMutationError::AccessGateProvenanceChanged);
            }
            Ok(())
        }
        Err(patch_error) => {
            // The API server may have committed the patch before the response
            // was lost. Resolve that ambiguity from the exact UID: an admitted
            // object is success; a still-pending object is removed with its
            // current resourceVersion so a failed POST cannot later be placed.
            let current = match leases.get(&name).await {
                Ok(current) => current,
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    return Err(SandboxLeaseMutationError::Kubernetes(patch_error));
                }
                Err(error) => return Err(SandboxLeaseMutationError::Kubernetes(error)),
            };
            match current
                .annotations()
                .get(SANDBOX_ADMISSION_ANNOTATION)
                .map(String::as_str)
            {
                Some(SANDBOX_ADMISSION_ADMITTED) => {
                    validate_lease_shape(lease, &current, SANDBOX_ADMISSION_ADMITTED)?;
                    if persisted_reservation_provenance(&current)?
                        != canonical_reservation_provenance(lease, admission_reservations)?
                    {
                        return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                            "lost admission response contains different reservation provenance"
                                .into(),
                        ));
                    }
                    if !crate::sandbox_access_ledger::persisted_gate_reference(&current)
                        .is_ok_and(|actual| actual == *access_gate)
                    {
                        return Err(SandboxLeaseMutationError::AccessGateProvenanceChanged);
                    }
                    Ok(())
                }
                Some(SANDBOX_ADMISSION_PENDING) => {
                    // The safety property is "never delete an ADMITTED lease by this path",
                    // not "the annotation must read exactly `pending`". Demanding the latter
                    // bricked any lease whose annotation went missing or corrupt: the release
                    // handler routes everything not-admitted here, and this then refused it
                    // forever, so the object could not be removed through the API at all.
                    validate_lease_shape_unadmitted(lease, &current)?;
                    delete_exact_pending_lease(leases, reservations, &current).await?;
                    Err(SandboxLeaseMutationError::AdmissionNotCommitted)
                }
                _ => Err(SandboxLeaseMutationError::UnexpectedAdmissionState),
            }
        }
    }
}

/// One reservation this request actually created, recorded so it can be
/// released by exact identity. The UID matters: releasing by name alone could
/// delete a *replacement* reservation another request created after ours was
/// already gone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionReservation {
    kind: SandboxReservationKind,
    name: String,
    uid: String,
}

/// Canonicalize and validate the exact reservation set committed at admission.
///
/// The annotation produced from this set is the durable authority for cleanup:
/// a selector may discover candidates, but it can never invent another name or
/// UID Kobe is allowed to delete.
fn canonical_reservation_provenance(
    lease: &SandboxLease,
    reservations: &[AdmissionReservation],
) -> Result<Vec<AdmissionReservation>, SandboxLeaseMutationError> {
    let principal = principal_hash_for(&lease.spec.requester);
    let expected_len = 1 + usize::from(lease.spec.alias.is_some());
    if reservations.len() != expected_len {
        return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
            "reservation count does not match quota plus optional alias".into(),
        ));
    }

    let mut quota = 0usize;
    let mut alias = 0usize;
    let mut names = std::collections::BTreeSet::new();
    let mut uids = std::collections::BTreeSet::new();
    for reservation in reservations {
        if reservation.uid.is_empty()
            || !names.insert(reservation.name.clone())
            || !uids.insert(reservation.uid.clone())
        {
            return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                "reservation name and UID must be non-empty and unique".into(),
            ));
        }
        let derived =
            expected_reservation_kind(&reservation.name, &principal, lease.spec.alias.as_deref())
                .ok_or_else(|| {
                SandboxLeaseMutationError::ReservationProvenanceChanged(format!(
                    "reservation {} is not derived from the admitted lease",
                    reservation.name
                ))
            })?;
        if derived != reservation.kind {
            return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                format!("reservation {} kind changed", reservation.name),
            ));
        }
        match reservation.kind {
            SandboxReservationKind::Quota => quota += 1,
            SandboxReservationKind::Alias => alias += 1,
        }
    }
    if quota != 1 || alias != usize::from(lease.spec.alias.is_some()) {
        return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
            "reservation kinds do not match quota plus optional alias".into(),
        ));
    }

    let mut canonical = reservations.to_vec();
    canonical.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.uid.cmp(&right.uid))
    });
    Ok(canonical)
}

fn encoded_reservation_provenance(
    lease: &SandboxLease,
    reservations: &[AdmissionReservation],
) -> Result<String, SandboxLeaseMutationError> {
    serde_json::to_string(&canonical_reservation_provenance(lease, reservations)?)
        .map_err(|err| SandboxLeaseMutationError::ReservationProvenanceChanged(err.to_string()))
}

fn persisted_reservation_provenance(
    lease: &SandboxLease,
) -> Result<Vec<AdmissionReservation>, SandboxLeaseMutationError> {
    let encoded = lease
        .annotations()
        .get(SANDBOX_RESERVATIONS_ANNOTATION)
        .ok_or_else(|| {
            SandboxLeaseMutationError::ReservationProvenanceChanged(
                "admitted lease has no persisted reservation set".into(),
            )
        })?;
    let reservations: Vec<AdmissionReservation> = serde_json::from_str(encoded)
        .map_err(|err| SandboxLeaseMutationError::ReservationProvenanceChanged(err.to_string()))?;
    canonical_reservation_provenance(lease, &reservations)
}

/// Whether an admitted lease carries the complete exact reservation set.
///
/// The placement controller uses this when certifying the narrow
/// admission-only cancellation shape. Keeping the parser here prevents that
/// proof from accepting a merely present or caller-crafted annotation.
pub(crate) fn admitted_reservation_provenance_is_valid(lease: &SandboxLease) -> bool {
    lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .is_some_and(|value| value == SANDBOX_ADMISSION_ADMITTED)
        && persisted_reservation_provenance(lease).is_ok()
}

/// Why admission could not reserve its slot. Both refusals are ordinary,
/// caller-visible outcomes rather than faults — the caller is over quota, or
/// picked an alias someone else is already using.
#[derive(Debug, Error)]
enum AdmissionReservationError {
    #[error("concurrent Sandbox lease quota is exhausted")]
    QuotaExhausted,
    #[error("Sandbox lease alias is already active")]
    AliasTaken,
    #[error("SandboxLease has no UID to fence its reservations against")]
    MissingLeaseUid,
    #[error("Sandbox reservation API is not scoped to the dedicated ledger namespace")]
    MissingReservationNamespace,
    #[error("Sandbox reservation DELETE was accepted but object absence was not confirmed")]
    DeletionNotConfirmed,
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

/// Quota slots are named per principal and per slot index, so acquiring one is
/// a race for a *specific* name. `CREATE` is the atomic primitive: two API
/// replicas contending for the last slot cannot both succeed, because the
/// second gets 409 from the API server.
pub(crate) fn quota_reservation_name(principal: &str, slot: u32) -> String {
    format!("sbx-quota-{principal}-{slot}")
}

/// Aliases are validated DNS labels (<=63 chars) before we get here, so they can
/// be embedded directly rather than hashed — which keeps the reservation name
/// legible to an operator debugging a stuck alias.
fn alias_reservation_name(principal: &str, alias: &str) -> String {
    format!("sbx-alias-{principal}-{alias}")
}

/// Build a coordination `Lease` used purely as a compare-and-swap token.
///
/// Reservations deliberately have no owner reference to the `SandboxLease`.
/// A foreground delete may garbage-collect dependants before Kobe has proved
/// the tenant footprint absent; letting GC remove these capacity tokens would
/// admit a replacement while the old Sandbox could still be running. The
/// pending-admission reaper and verified release path perform exact UID-fenced
/// cleanup instead.
fn build_admission_reservation(
    name: String,
    reservation_type: &str,
    lease: &SandboxLease,
    principal: &str,
    reservation_namespace: &str,
) -> Result<Lease, AdmissionReservationError> {
    let lease_uid = lease
        .uid()
        .ok_or(AdmissionReservationError::MissingLeaseUid)?;
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        SANDBOX_RESERVATION_TYPE_LABEL.to_string(),
        reservation_type.to_string(),
    );
    labels.insert(
        SANDBOX_RESERVATION_LEASE_UID_LABEL.to_string(),
        lease_uid.clone(),
    );
    labels.insert(REQUESTER_HASH_LABEL.to_string(), principal.to_string());
    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert(
        SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION.to_string(),
        lease.name_any(),
    );

    Ok(Lease {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(reservation_namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        // The token carries no lease semantics; existence *is* the claim.
        spec: Some(LeaseSpec::default()),
    })
}

/// Reserve this lease's admission atomically across every API replica.
///
/// Advisory `LIST` checks earlier in the request improve error latency, but
/// they cannot be authoritative: two replicas can both read "one slot free" and
/// both admit. Only the `CREATE` calls below decide, because the API server
/// serializes them on object name.
///
/// Alias is reserved first. A taken alias is a deterministic, user-fixable
/// conflict, so failing on it before consuming a quota slot avoids a pointless
/// acquire-then-release round trip against the shared quota namespace.
async fn acquire_admission_reservations(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    identity: &AuthIdentity,
    alias: Option<&str>,
    max_concurrent_leases: u32,
) -> Result<Vec<AdmissionReservation>, AdmissionReservationError> {
    let principal = principal_hash(identity);
    let reservation_namespace = reservations
        .namespace()
        .ok_or(AdmissionReservationError::MissingReservationNamespace)?;
    let mut acquired: Vec<AdmissionReservation> = Vec::new();

    if let Some(alias) = alias {
        let reservation = build_admission_reservation(
            alias_reservation_name(&principal, alias),
            SANDBOX_RESERVATION_ALIAS,
            lease,
            &principal,
            reservation_namespace,
        )?;
        match reservations
            .create(&PostParams::default(), &reservation)
            .await
        {
            Ok(created) => {
                // An empty UID would make every later release fail its
                // precondition with 409, which the release path treats as
                // "ours is already gone" — silently stranding the slot.
                // Refuse rather than acquire something we can never release.
                let Some(uid) = created.uid() else {
                    rollback_partial_reservations(leases, reservations, lease).await;
                    return Err(AdmissionReservationError::MissingLeaseUid);
                };
                acquired.push(AdmissionReservation {
                    kind: SandboxReservationKind::Alias,
                    name: created.name_any(),
                    uid,
                });
            }
            Err(kube::Error::Api(error)) if error.code == 409 => {
                return Err(AdmissionReservationError::AliasTaken);
            }
            Err(error) => return Err(error.into()),
        }
    }

    // Advisory short-circuit. Scanning for a free slot costs one CREATE per
    // taken slot, so a caller at a 256-slot limit would otherwise pay 256 round
    // trips just to be told they are over quota. One LIST answers the common
    // case. It is deliberately NOT authoritative — a slot can free or fill
    // between this read and the CREATE below, which is exactly why the CREATE
    // still decides. The selector is also not trusted: only canonical slots
    // inside THIS policy bound with all three identity labels count. An
    // arbitrary object carrying the two advisory labels must not manufacture a
    // cheap 429 for another principal.
    match reservations
        .list(&ListParams::default().labels(&format!(
            "{SANDBOX_RESERVATION_TYPE_LABEL}={SANDBOX_RESERVATION_QUOTA},{REQUESTER_HASH_LABEL}={principal}"
        )))
        .await
    {
        Ok(existing)
            if existing
                .items
                .iter()
                .filter(|reservation| {
                    counts_toward_advisory_quota(
                        reservation,
                        &principal,
                        max_concurrent_leases,
                    )
                })
                .count() as u32
                >= max_concurrent_leases =>
        {
            rollback_partial_reservations(leases, reservations, lease).await;
            return Err(AdmissionReservationError::QuotaExhausted);
        }
        Ok(_) => {}
        // A failed advisory read must not fail the request: fall through to the
        // authoritative scan, which is correct on its own.
        Err(error) => {
            error!(error = %error, "Advisory Sandbox quota read failed; falling back to slot scan");
        }
    }

    // First free index wins. Slots are dense and bounded by policy, and
    // `max_concurrent_leases` is capped at MAX_SANDBOX_CONCURRENCY_SLOTS by the
    // caller, so this loop is bounded regardless of what a policy asks for.
    let mut slot_taken = false;
    for slot in 0..max_concurrent_leases {
        let reservation = build_admission_reservation(
            quota_reservation_name(&principal, slot),
            SANDBOX_RESERVATION_QUOTA,
            lease,
            &principal,
            reservation_namespace,
        )?;
        match reservations
            .create(&PostParams::default(), &reservation)
            .await
        {
            Ok(created) => {
                // Same reasoning as the alias arm: a reservation we cannot
                // name by UID is one we can never release.
                let Some(uid) = created.uid() else {
                    rollback_partial_reservations(leases, reservations, lease).await;
                    return Err(AdmissionReservationError::MissingLeaseUid);
                };
                acquired.push(AdmissionReservation {
                    kind: SandboxReservationKind::Quota,
                    name: created.name_any(),
                    uid,
                });
                slot_taken = true;
                break;
            }
            // This slot belongs to another live lease; try the next one.
            Err(kube::Error::Api(error)) if error.code == 409 => continue,
            Err(error) => {
                rollback_partial_reservations(leases, reservations, lease).await;
                return Err(error.into());
            }
        }
    }

    if !slot_taken {
        rollback_partial_reservations(leases, reservations, lease).await;
        return Err(AdmissionReservationError::QuotaExhausted);
    }

    Ok(acquired)
}

/// Best-effort unwind of reservations taken earlier in a failed acquire.
///
/// The durable lease is deleted and confirmed absent before any slot is freed.
/// This is intentionally the same cleanup path the caller will retry: directly
/// deleting a partially acquired reservation first would create a quota hole
/// if admission raced with the acquire failure.
async fn rollback_partial_reservations(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) {
    if let Err(error) = delete_exact_pending_lease(leases, reservations, lease).await {
        error!(error = %error, "Failed to remove pending Sandbox lease after partial reservation acquire");
    }
}

/// Release exactly the reservations we hold. A UID precondition means a
/// reservation that was already reaped and recreated by a different request is
/// left alone rather than stolen from its new owner.
async fn release_admission_reservations(
    reservations: &Api<Lease>,
    acquired: &[AdmissionReservation],
) -> Result<(), AdmissionReservationError> {
    for reservation in acquired {
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(reservation.uid.clone()),
                resource_version: None,
            }),
            ..Default::default()
        };
        match reservations.delete(&reservation.name, &params).await {
            Ok(_) => {}
            // 404: already gone. 409: either the name now holds somebody
            // else's reservation or the precondition raced; the exact GET
            // below distinguishes those outcomes.
            Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
            Err(error) => return Err(error.into()),
        }
        match reservations.get(&reservation.name).await {
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Ok(current) if current.uid().as_deref() != Some(reservation.uid.as_str()) => {
                // Our exact object is gone. A replacement must survive.
            }
            Ok(_) => return Err(AdmissionReservationError::DeletionNotConfirmed),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct OrphanReservationIdentity {
    name: String,
    uid: String,
    resource_version: String,
    lease_name: String,
    lease_uid: String,
    principal: String,
}

/// Validate the self-contained identity carried by a detached ledger token.
///
/// A late reservation POST can surface only after its `SandboxLease` has been
/// cancelled and deleted, so cleanup cannot rely on the parent object to
/// reconstruct the expected token. The ledger namespace is operator-only, but
/// this still validates every authority-bearing field before using the token
/// as deletion authority: exact labels/annotation, deterministic name, empty
/// spec, no finalizers/owners, and server-assigned UID/resourceVersion.
fn orphan_reservation_identity(
    reservation: &Lease,
    expected_namespace: &str,
) -> Result<OrphanReservationIdentity, String> {
    if reservation.namespace().as_deref() != Some(expected_namespace) {
        return Err("namespace changed".into());
    }
    if !reservation
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Err("ownerReferences must be empty".into());
    }
    if !reservation
        .metadata
        .finalizers
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Err("finalizers must be empty".into());
    }
    if reservation.spec.as_ref() != Some(&LeaseSpec::default()) {
        return Err("Lease spec changed".into());
    }

    let name = reservation.name_any();
    let uid = reservation
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "UID is missing".to_string())?;
    let resource_version = reservation
        .resource_version()
        .filter(|resource_version| !resource_version.is_empty())
        .ok_or_else(|| "resourceVersion is missing".to_string())?;
    let labels = reservation.labels();
    if labels.len() != 3 {
        return Err("labels changed".into());
    }
    let principal = labels
        .get(REQUESTER_HASH_LABEL)
        .filter(|principal| {
            principal.len() == 32
                && principal
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .cloned()
        .ok_or_else(|| "requester hash is malformed".to_string())?;
    let lease_uid = labels
        .get(SANDBOX_RESERVATION_LEASE_UID_LABEL)
        .filter(|uid| !uid.is_empty())
        .cloned()
        .ok_or_else(|| "SandboxLease UID label is missing".to_string())?;
    let reservation_type = labels
        .get(SANDBOX_RESERVATION_TYPE_LABEL)
        .map(String::as_str)
        .ok_or_else(|| "reservation type is missing".to_string())?;
    let name_matches = match reservation_type {
        SANDBOX_RESERVATION_QUOTA => quota_reservation_slot(&name, &principal).is_some(),
        SANDBOX_RESERVATION_ALIAS => {
            let prefix = format!("sbx-{SANDBOX_RESERVATION_ALIAS}-{principal}-");
            name.strip_prefix(&prefix).is_some_and(|alias| {
                is_valid_k8s_name(alias) && alias_reservation_name(&principal, alias) == name
            })
        }
        _ => false,
    };
    if !name_matches {
        return Err("name is not derived from its reservation type and principal".into());
    }

    let annotations = reservation.annotations();
    if annotations.len() != 1 {
        return Err("annotations changed".into());
    }
    let lease_name = annotations
        .get(SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION)
        .filter(|name| name.starts_with(LEASE_ID_PREFIX) && is_valid_k8s_name(name))
        .cloned()
        .ok_or_else(|| "SandboxLease name annotation is malformed".to_string())?;

    Ok(OrphanReservationIdentity {
        name,
        uid,
        resource_version,
        lease_name,
        lease_uid,
        principal,
    })
}

/// Reclaim reservation POSTs that became visible after their parent vanished.
///
/// Cancellation and admission are fenced on the parent, but Kubernetes cannot
/// atomically couple that CRD mutation to a coordination-Lease CREATE. A POST
/// already in flight when cancellation wins can therefore commit after the
/// parent cleanup's selector read. Every token carries the parent name+UID, so
/// repeated sweeps make that finite race recoverable without trusting age or a
/// caller retry. Deletion itself is fenced by the token's UID and
/// resourceVersion; a same-named replacement always survives.
///
/// Exact parent absence is sufficient because the parent is created with
/// Kobe's finalizer before any reservation POST. An admitted parent cannot
/// disappear through Kobe until verified teardown has already released its
/// ledger; an unadmitted parent disappears only after the cancellation CAS.
/// Thus a token whose exact parent UID is absent is either late unadmitted work
/// or an idempotent cleanup tail, never authority for a live Sandbox.
async fn reap_orphaned_admission_reservations(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
) {
    let Some(expected_namespace) = reservations.namespace() else {
        warn!("Sandbox orphan-reservation sweep has no ledger namespace");
        return;
    };
    // List the ledger first and parents second. Any token in this ledger
    // snapshot must have been created after its parent, so the later parent
    // snapshot cannot miss a newly admitted owner. A stale parent can only
    // defer orphan cleanup for one sweep, which is the safe direction.
    let listed = match reservations.list(&ListParams::default()).await {
        Ok(listed) => listed,
        Err(error) => {
            warn!(error = %error, "Sandbox orphan-reservation sweep could not list the ledger");
            return;
        }
    };
    let live_parents: std::collections::BTreeMap<String, SandboxLease> = match leases
        .list(&ListParams::default())
        .await
    {
        Ok(listed) => listed
            .items
            .into_iter()
            .map(|lease| (lease.name_any(), lease))
            .collect(),
        Err(error) => {
            warn!(error = %error, "Sandbox orphan-reservation sweep could not list parent leases");
            return;
        }
    };

    // Token-carried parent fields are mutable discovery hints, not deletion
    // authority. The admitted parent persists the exact token name+UID; honor
    // that authority even when the token's lease-name annotation or lease-UID
    // label was changed to point somewhere else.
    let live_persisted_tokens: std::collections::BTreeSet<(String, String)> = live_parents
        .values()
        .filter_map(|parent| persisted_reservation_provenance(parent).ok())
        .flatten()
        .map(|reservation| (reservation.name, reservation.uid))
        .collect();
    let live_principals: std::collections::BTreeSet<String> = live_parents
        .values()
        .filter(|parent| {
            parent
                .status
                .as_ref()
                .is_none_or(|status| status.phase.consumes_capacity())
                && persisted_reservation_provenance(parent).is_err()
        })
        .map(|parent| principal_hash_for(&parent.spec.requester))
        .collect();
    let live_alias_tokens: std::collections::BTreeSet<String> = live_parents
        .values()
        .filter(|parent| {
            parent
                .status
                .as_ref()
                .is_none_or(|status| status.phase.consumes_capacity())
                && persisted_reservation_provenance(parent).is_err()
        })
        .filter_map(|parent| {
            parent.spec.alias.as_deref().map(|alias| {
                alias_reservation_name(&principal_hash_for(&parent.spec.requester), alias)
            })
        })
        .collect();

    for reservation in listed.items {
        let reservation_name = reservation.name_any();
        // Admission cannot atomically couple a coordination-Lease CREATE to the
        // parent PATCH that persists its exact token set. Between those writes,
        // the parent is live and Pending while the token has no parent-side
        // provenance yet. Token-carried labels and annotations are mutable, so
        // they cannot authorize orphan deletion during that window: a changed
        // parent hint could make the token look detached, let this sweep delete
        // it, and then allow the already-in-flight admission CAS to commit.
        //
        // The token name is immutable and encodes the principal (plus alias,
        // when applicable). Conservatively retain any deterministic name that
        // could belong to a capacity-owning parent which has not yet persisted
        // exact provenance. Parents with valid provenance are covered by the
        // exact name+UID set above, so an unrelated live lease does not delay
        // safe orphan cleanup. Once the ambiguous parent is absent or terminal,
        // the normal exact-name+UID cleanup below remains available.
        if parsed_quota_reservation_name(&reservation_name)
            .is_some_and(|(principal, _)| live_principals.contains(principal))
            || live_alias_tokens.contains(&reservation_name)
        {
            continue;
        }
        let identity = match orphan_reservation_identity(&reservation, expected_namespace) {
            Ok(identity) => identity,
            Err(reason) => {
                warn!(
                    reservation = %reservation.name_any(),
                    %reason,
                    "Ignoring malformed Sandbox admission reservation"
                );
                continue;
            }
        };
        if live_persisted_tokens.contains(&(identity.name.clone(), identity.uid.clone())) {
            continue;
        }
        let live_parent = live_parents
            .get(&identity.lease_name)
            .filter(|parent| parent.uid().as_deref() == Some(identity.lease_uid.as_str()));
        let orphaned = if let Some(parent) = live_parent {
            if principal_hash_for(&parent.spec.requester) != identity.principal {
                warn!(
                    reservation = %identity.name,
                    lease = %identity.lease_name,
                    "Sandbox reservation principal does not match its live parent"
                );
            }
            false
        } else {
            match leases.get(&identity.lease_name).await {
                Ok(parent) if parent.uid().as_deref() == Some(identity.lease_uid.as_str()) => {
                    if principal_hash_for(&parent.spec.requester) != identity.principal {
                        warn!(
                            reservation = %identity.name,
                            lease = %identity.lease_name,
                            "Sandbox reservation principal does not match its live parent"
                        );
                    }
                    false
                }
                Ok(_) => true,
                Err(kube::Error::Api(error)) if error.code == 404 => true,
                Err(error) => {
                    warn!(
                        reservation = %identity.name,
                        error = %error,
                        "Could not verify Sandbox reservation parent; leaving it held"
                    );
                    false
                }
            }
        };
        if !orphaned {
            continue;
        }

        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(identity.uid.clone()),
                resource_version: Some(identity.resource_version.clone()),
            }),
            ..Default::default()
        };
        let delete_result = reservations.delete(&identity.name, &params).await;
        match reservations.get(&identity.name).await {
            Err(kube::Error::Api(error)) if error.code == 404 => info!(
                reservation = %identity.name,
                lease = %identity.lease_name,
                "Reaped an orphaned Sandbox admission reservation"
            ),
            Ok(current) if current.uid().as_deref() != Some(identity.uid.as_str()) => {
                // Our exact token is gone. Preserve the replacement.
            }
            Ok(_) => match delete_result {
                Err(error) => warn!(
                    reservation = %identity.name,
                    error = %error,
                    "Could not reap an orphaned Sandbox reservation; will retry"
                ),
                Ok(_) => warn!(
                    reservation = %identity.name,
                    "Sandbox reservation DELETE was accepted but absence was not confirmed"
                ),
            },
            Err(error) => warn!(
                reservation = %identity.name,
                error = %error,
                "Could not confirm orphaned Sandbox reservation deletion"
            ),
        }
    }
}

/// Release every reservation carried by one exact lease UID.
///
/// Used on the cleanup path, where we hold the lease rather than the list of
/// reservations we created. Selecting on the UID label (not the name) is what
/// keeps a recreated same-named lease from dropping its predecessor's slots.
pub(crate) async fn release_reservations_for_lease(
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    lease_uid: &str,
) -> Result<(), SandboxLeaseMutationError> {
    if lease.uid().as_deref() != Some(lease_uid) {
        return Err(SandboxLeaseMutationError::UidChanged);
    }
    let admission = lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str);
    let persisted = match admission {
        Some(SANDBOX_ADMISSION_ADMITTED) => Some(persisted_reservation_provenance(lease)?),
        _ => {
            pristine_pending_lease(lease)?;
            None
        }
    };
    let held = verified_reservations_for_lease(
        reservations,
        lease,
        lease_uid,
        persisted.as_deref(),
        false,
    )
    .await?;
    if let Err(error) = release_admission_reservations(reservations, &held).await {
        return match error {
            AdmissionReservationError::Kubernetes(error) => Err(error.into()),
            other => {
                error!(error = %other, "Unexpected Sandbox reservation release failure");
                Err(SandboxLeaseMutationError::ReservationDeletionNotConfirmed)
            }
        };
    }
    Ok(())
}

/// Validate the complete reservation selector result before any mutation.
///
/// A label selector narrows discovery but grants no deletion authority. Every
/// object must match Kobe's deterministic full shape, and admitted provenance
/// must match exact name, kind, and UID. Cleanup permits an expected token to
/// be already absent after an earlier partial release. Admission repair passes
/// `require_complete = true`: all exact tokens must still be live, otherwise
/// the parent remains untouched and ambiguous.
async fn verified_reservations_for_lease(
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    lease_uid: &str,
    persisted: Option<&[AdmissionReservation]>,
    require_complete: bool,
) -> Result<Vec<AdmissionReservation>, SandboxLeaseMutationError> {
    if lease.uid().as_deref() != Some(lease_uid) {
        return Err(SandboxLeaseMutationError::UidChanged);
    }
    let persisted_by_name: std::collections::BTreeMap<&str, &AdmissionReservation> = persisted
        .unwrap_or_default()
        .iter()
        .map(|reservation| (reservation.name.as_str(), reservation))
        .collect();
    let params = ListParams::default().labels(&format!(
        "{SANDBOX_RESERVATION_LEASE_UID_LABEL}={lease_uid}"
    ));
    let owned = reservations.list(&params).await?;

    // A label is caller-supplied data, not an integrity check. Validate the
    // ENTIRE result before the first delete/repair, or a malformed object found
    // after a valid token could make the operation partially authoritative.
    let principal = principal_hash_for(&lease.spec.requester);
    let expected_namespace = reservations
        .namespace()
        .ok_or(SandboxLeaseMutationError::MissingReservationNamespace)?;
    let mut quota_seen = false;
    let mut alias_seen = false;
    let mut held = Vec::with_capacity(owned.items.len());
    for reservation in owned {
        let name = reservation.name_any();
        let kind = validate_reservation_shape(
            &reservation,
            lease,
            lease_uid,
            expected_namespace,
            &principal,
        )?;
        if let Some(expected) = persisted_by_name.get(name.as_str()) {
            if expected.kind != kind || reservation.uid().as_deref() != Some(expected.uid.as_str())
            {
                return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                    format!("reservation {name} no longer matches its admitted UID and kind"),
                ));
            }
        } else if persisted.is_some() {
            return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                format!("reservation {name} was not committed at admission"),
            ));
        }
        let duplicate = match kind {
            SandboxReservationKind::Quota => std::mem::replace(&mut quota_seen, true),
            SandboxReservationKind::Alias => std::mem::replace(&mut alias_seen, true),
        };
        if duplicate {
            return Err(SandboxLeaseMutationError::ReservationShapeChanged {
                name,
                reason: format!("more than one {kind:?} reservation carries this lease UID"),
            });
        }
        held.push(AdmissionReservation {
            kind,
            name,
            uid: reservation.uid().expect("shape validation requires a UID"),
        });
    }

    // GET every expected name omitted by the UID selector. The same UID hidden
    // behind malformed labels is corruption. A missing/replaced exact token is
    // acceptable only to idempotent cleanup, never as proof for admission
    // repair.
    for expected in persisted.unwrap_or_default() {
        if held.iter().any(|current| current.name == expected.name) {
            continue;
        }
        match reservations.get(&expected.name).await {
            Err(kube::Error::Api(error)) if error.code == 404 && !require_complete => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                    format!("reservation {} is no longer live", expected.name),
                ));
            }
            Ok(current)
                if current.uid().as_deref() != Some(expected.uid.as_str()) && !require_complete =>
            {
                // A later admission may legitimately reuse the deterministic
                // name after cleanup removed this exact UID. Preserve it.
            }
            Ok(current) if current.uid().as_deref() != Some(expected.uid.as_str()) => {
                return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                    format!("reservation {} was replaced", expected.name),
                ));
            }
            Ok(current) => {
                let kind = validate_reservation_shape(
                    &current,
                    lease,
                    lease_uid,
                    expected_namespace,
                    &principal,
                )?;
                if kind != expected.kind || current.uid().as_deref() != Some(expected.uid.as_str())
                {
                    return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                        format!("reservation {} was replaced", expected.name),
                    ));
                }
                return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
                    format!(
                        "reservation {} disappeared from an exact UID list",
                        expected.name
                    ),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if require_complete && held.len() != persisted.unwrap_or_default().len() {
        return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
            "live reservation set is incomplete".into(),
        ));
    }
    Ok(held)
}

/// Prove that one selector result is exactly an admission token Kobe created.
///
/// Server-assigned metadata (UID/resourceVersion/timestamps) may vary. Every
/// authority-bearing field does not: namespace, deterministic name, labels,
/// lease-name annotation, empty Lease spec, and the deliberate absence of
/// owner references/finalizers. The latter is important: reservations are
/// released explicitly only after footprint proof, never early by Kubernetes
/// garbage collection.
fn validate_reservation_shape(
    reservation: &Lease,
    lease: &SandboxLease,
    lease_uid: &str,
    expected_namespace: &str,
    principal: &str,
) -> Result<SandboxReservationKind, SandboxLeaseMutationError> {
    let name = reservation.name_any();
    let fail = |reason: &str| SandboxLeaseMutationError::ReservationShapeChanged {
        name: name.clone(),
        reason: reason.to_string(),
    };
    let kind = expected_reservation_kind(&name, principal, lease.spec.alias.as_deref())
        .ok_or_else(|| fail("name is not an exact reservation derived from this lease"))?;
    if reservation.namespace().as_deref() != Some(expected_namespace) {
        return Err(fail("namespace changed"));
    }
    if reservation.uid().as_deref().is_none_or(str::is_empty) {
        return Err(fail("UID is missing"));
    }
    if !reservation
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Err(fail("ownerReferences must be empty"));
    }
    if !reservation
        .metadata
        .finalizers
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Err(fail("finalizers must be empty"));
    }

    let expected_type = match kind {
        SandboxReservationKind::Quota => SANDBOX_RESERVATION_QUOTA,
        SandboxReservationKind::Alias => SANDBOX_RESERVATION_ALIAS,
    };
    let expected_labels = std::collections::BTreeMap::from([
        (
            SANDBOX_RESERVATION_TYPE_LABEL.to_string(),
            expected_type.to_string(),
        ),
        (
            SANDBOX_RESERVATION_LEASE_UID_LABEL.to_string(),
            lease_uid.to_string(),
        ),
        (REQUESTER_HASH_LABEL.to_string(), principal.to_string()),
    ]);
    if reservation.labels() != &expected_labels {
        return Err(fail("labels changed"));
    }
    let expected_annotations = std::collections::BTreeMap::from([(
        SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION.to_string(),
        lease.name_any(),
    )]);
    if reservation.annotations() != &expected_annotations {
        return Err(fail("lease-name annotation changed"));
    }
    if reservation.spec.as_ref() != Some(&LeaseSpec::default()) {
        return Err(fail("Lease spec changed"));
    }
    Ok(kind)
}

/// Remove a still-unadmitted lease and free whatever it reserved.
///
/// Cleanup is deliberately three checkpoints: remove only Kobe's finalizer,
/// issue an exact UID/resourceVersion-fenced DELETE, and prove a subsequent
/// GET is 404. Reservations are released only after that absence proof. An
/// accepted DELETE is not proof when a foreign finalizer can keep the lease
/// present, and freeing quota in that state could over-admit.
async fn delete_exact_pending_lease(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    // Validate the caller's snapshot before even accepting a 404 as absence
    // proof. Otherwise an active/corrupt snapshot could authorize reservation
    // release without a live parent to reclassify.
    pristine_pending_lease(lease)?;
    let expected_uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let mut current = match leases.get(&lease.name_any()).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            // This GET is the required absence proof. The lease is already
            // gone, but reservations may still be awaiting explicit cleanup.
            return finish_pending_ledger_cleanup(reservations, lease, &expected_uid).await;
        }
        Err(error) => return Err(error.into()),
    };
    if current.uid().as_deref() != Some(expected_uid.as_str()) {
        return Err(SandboxLeaseMutationError::UidChanged);
    }

    // A previous attempt may have committed finalizer removal and lost its
    // response. Accept exactly that one shape change so a retry can finish the
    // DELETE; every foreign finalizer must otherwise be preserved byte-for-byte.
    let expected_without_finalizer = without_sandbox_cleanup_finalizer(lease);
    if validate_lease_shape_unadmitted(lease, &current).is_err() {
        validate_lease_shape_unadmitted(&expected_without_finalizer, &current)?;
    }

    if normalized_finalizers(&current)
        .iter()
        .any(|finalizer| finalizer == SANDBOX_LEASE_FINALIZER)
    {
        let resource_version = current
            .resource_version()
            .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
        let expected_after_patch = without_sandbox_cleanup_finalizer(&current);
        let patch = crate::controllers::lease::json_patch(serde_json::json!([
            { "op": "test", "path": "/metadata/uid", "value": expected_uid.clone() },
            { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
            {
                "op": "add",
                "path": "/metadata/finalizers",
                "value": normalized_finalizers(&expected_after_patch)
            }
        ]));
        current = match leases
            .patch(
                &current.name_any(),
                &PatchParams::default(),
                &Patch::Json::<()>(patch),
            )
            .await
        {
            Ok(patched) => {
                validate_lease_shape_unadmitted(&expected_after_patch, &patched)?;
                patched
            }
            Err(patch_error) => {
                // JSON Patch may have committed before its response was lost.
                // Only the exact post-removal object lets cleanup continue.
                match leases.get(&current.name_any()).await {
                    Ok(reread) => {
                        validate_lease_shape_unadmitted(&expected_after_patch, &reread)?;
                        reread
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => {
                        return finish_pending_ledger_cleanup(reservations, lease, &expected_uid)
                            .await;
                    }
                    Err(_) => return Err(patch_error.into()),
                }
            }
        };
    }

    let resource_version = current
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(expected_uid.clone()),
            resource_version: Some(resource_version),
        }),
        ..Default::default()
    };
    let delete_result = leases.delete(&current.name_any(), &params).await;

    // DELETE success only means deletion was accepted. A foreign finalizer can
    // keep this exact lease present, so an explicit 404 is the release fence.
    match leases.get(&current.name_any()).await {
        Err(kube::Error::Api(error)) if error.code == 404 => {
            finish_pending_ledger_cleanup(reservations, lease, &expected_uid).await
        }
        Ok(remaining) if remaining.uid().as_deref() != Some(expected_uid.as_str()) => {
            Err(SandboxLeaseMutationError::UidChanged)
        }
        Ok(_) => match delete_result {
            Err(error) => Err(error.into()),
            Ok(_) => Err(SandboxLeaseMutationError::DeletionNotConfirmed),
        },
        Err(error) => Err(error.into()),
    }
}

async fn finish_pending_ledger_cleanup(
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    expected_uid: &str,
) -> Result<(), SandboxLeaseMutationError> {
    release_reservations_for_lease(reservations, lease, expected_uid).await?;
    crate::sandbox_access_ledger::remove_pre_admission_gate(reservations, lease).await?;
    Ok(())
}

fn without_sandbox_cleanup_finalizer(lease: &SandboxLease) -> SandboxLease {
    let mut lease = lease.clone();
    let remaining: Vec<String> = normalized_finalizers(&lease)
        .iter()
        .filter(|finalizer| finalizer.as_str() != SANDBOX_LEASE_FINALIZER)
        .cloned()
        .collect();
    lease.metadata.finalizers = (!remaining.is_empty()).then_some(remaining);
    lease
}

/// Prove that direct deletion cannot discard an active Sandbox lifecycle.
///
/// Missing or corrupt admission is safe to delete only while the object is
/// still the pristine admission parent: Pending/default status, no controller
/// progress, no target/placement, no release intent, and no committed
/// reservation provenance. Anything else is ambiguous and must be repaired
/// into verified teardown or retained for operator review.
fn pristine_pending_lease(lease: &SandboxLease) -> Result<(), SandboxLeaseMutationError> {
    if lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        == Some(SANDBOX_ADMISSION_ADMITTED)
    {
        return Err(SandboxLeaseMutationError::UnexpectedAdmissionState);
    }
    if lease
        .annotations()
        .contains_key(SANDBOX_RESERVATIONS_ANNOTATION)
        || lease
            .annotations()
            .contains_key(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
    {
        return Err(SandboxLeaseMutationError::ReservationProvenanceChanged(
            "unadmitted lease carries active lifecycle provenance".into(),
        ));
    }
    if let Some(status) = lease.status.as_ref()
        && (status.phase != SandboxLeasePhase::Pending
            || status.observed_generation.is_some()
            || status.ready_at.is_some()
            || status.expires_at.is_some()
            || status.release_cause.is_some()
            || status.placement.is_some()
            || status.target.is_some()
            || !status.conditions.is_empty())
    {
        return Err(SandboxLeaseMutationError::LeaseShapeChanged);
    }
    Ok(())
}

/// Validate an exact pristine-parent retry while allowing admission marker
/// damage (`pending`, `cancelled`, absent, or unrecognised).
fn validate_lease_shape_unadmitted(
    expected: &SandboxLease,
    actual: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    pristine_pending_lease(expected)?;
    pristine_pending_lease(actual)?;
    validate_lease_shape_base(expected, actual)
}

fn validate_lease_shape(
    expected: &SandboxLease,
    actual: &SandboxLease,
    admission: &str,
) -> Result<(), SandboxLeaseMutationError> {
    validate_lease_shape_base(expected, actual)?;
    if actual
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        != Some(admission)
    {
        return Err(SandboxLeaseMutationError::UnexpectedAdmissionState);
    }
    Ok(())
}

fn validate_lease_shape_base(
    expected: &SandboxLease,
    actual: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    if actual.name_any() != expected.name_any()
        || actual.namespace() != expected.namespace()
        || actual.spec != expected.spec
        || normalized_finalizers(actual) != normalized_finalizers(expected)
    {
        return Err(SandboxLeaseMutationError::LeaseShapeChanged);
    }
    if let Some(expected_uid) = expected.uid()
        && actual.uid().as_deref() != Some(expected_uid.as_str())
    {
        return Err(SandboxLeaseMutationError::UidChanged);
    }
    if actual.uid().is_none() {
        return Err(SandboxLeaseMutationError::MissingUid);
    }
    if actual.resource_version().is_none() {
        return Err(SandboxLeaseMutationError::MissingResourceVersion);
    }
    for (key, expected_value) in expected.labels() {
        if actual.labels().get(key) != Some(expected_value) {
            return Err(SandboxLeaseMutationError::LeaseShapeChanged);
        }
    }
    if let Some(expected_deadline) = expected
        .status
        .as_ref()
        .and_then(|status| status.provisioning_deadline.as_deref())
    {
        require_provisioning_deadline(actual, expected_deadline)?;
    }
    Ok(())
}

fn normalized_finalizers(lease: &SandboxLease) -> &[String] {
    lease.metadata.finalizers.as_deref().unwrap_or_default()
}

#[derive(Debug, Error)]
pub(crate) enum SandboxLeaseMutationError {
    #[error("SandboxLease has no UID")]
    MissingUid,
    #[error("SandboxLease has no resourceVersion")]
    MissingResourceVersion,
    #[error("SandboxLease has no API-server creation timestamp")]
    MissingCreationTimestamp,
    #[error("SandboxLease provisioning deadline checkpoint did not commit")]
    ProvisioningDeadlineNotCommitted,
    #[error("SandboxLease admission exceeded its active handler deadline")]
    AdmissionDeadlineExceeded,
    #[error("SandboxLease admission was interrupted by process shutdown")]
    AdmissionShuttingDown,
    #[error("SandboxLease identity or server-owned admission fields changed")]
    LeaseShapeChanged,
    #[error("SandboxLease UID changed")]
    UidChanged,
    #[error("SandboxLease has an unexpected admission state")]
    UnexpectedAdmissionState,
    #[error("SandboxLease admission patch did not commit; the pending object was removed")]
    AdmissionNotCommitted,
    #[error("SandboxLease DELETE was accepted but object absence was not confirmed")]
    DeletionNotConfirmed,
    #[error("Sandbox reservation DELETE was accepted but object absence was not confirmed")]
    ReservationDeletionNotConfirmed,
    #[error("Sandbox reservation API is not scoped to the dedicated ledger namespace")]
    MissingReservationNamespace,
    #[error("Sandbox reservation {name} does not match its durable admission shape: {reason}")]
    ReservationShapeChanged { name: String, reason: String },
    #[error("Sandbox reservation provenance changed: {0}")]
    ReservationProvenanceChanged(String),
    #[error("Sandbox access-gate provenance changed")]
    AccessGateProvenanceChanged,
    #[error(transparent)]
    AccessLedger(#[from] crate::sandbox_access_ledger::AccessLedgerError),
    #[error(transparent)]
    Lifecycle(#[from] crate::sandbox::SandboxLifecycleError),
    #[error(transparent)]
    Provenance(#[from] crate::sandbox::SandboxProvenanceError),
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::api::policy::{Policy, SandboxPolicy};
    use crate::crd::{SandboxLeaseStatus, SandboxResourceCeiling};
    use axum::body;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_LEDGER_NAMESPACE: &str = "sandbox-ledger";

    fn identity() -> AuthIdentity {
        AuthIdentity {
            provider: "developer-oidc".into(),
            requester_type: "oidc:developer".into(),
            identity: "alice@example.com".into(),
            issuer: "https://issuer.example".into(),
            policy: Policy {
                allowed_pools: vec!["cluster-*".into()],
                max_ttl: chrono::Duration::hours(8),
                max_concurrent_leases: 2,
                default_priority: 50,
                max_extensions: 2,
                sandbox: Some(SandboxPolicy {
                    allowed_pools: vec!["agent-*".into()],
                    verbs: vec![SandboxVerb::Lease, SandboxVerb::Release],
                    max_ttl: chrono::Duration::hours(2),
                    max_concurrent_leases: 2,
                    resource_ceiling: SandboxResourceCeiling {
                        max_cpu: "2".into(),
                        max_memory: "4Gi".into(),
                    },
                }),
            },
        }
    }

    fn test_state(server: &MockServer) -> AppState<crate::testutil::MockBackend> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        AppState {
            client: crate::testutil::mock_k8s_client(server),
            authenticator: std::sync::Arc::new(super::super::auth::JwtAuthenticator::new(
                "test".into(),
            )),
            namespace: "test-ns".into(),
            sandbox_reservation_namespace: TEST_LEDGER_NAMESPACE.into(),
            sandbox_serving_replica: None,
            backend: crate::testutil::MockBackend::new(),
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        }
    }

    fn pool_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxPool",
            "metadata": {
                "name": "agent-small",
                "namespace": "test-ns",
                "uid": "pool-uid",
                "generation": 1
            },
            "spec": {
                "warmCapacity": 1,
                "defaultTtl": "1h",
                "maxTtl": "4h",
                "provisioningTimeout": "10m",
                "placement": { "type": "management" },
                "template": {
                    "defaultContainer": "agent",
                    "containers": [{
                        "name": "agent",
                        "image": "example.invalid/agent@sha256:abc",
                        "resources": {
                            "requests": {
                                "cpu": "500m",
                                "memory": "512Mi",
                                "ephemeralStorage": "512Mi"
                            },
                            "limits": {
                                "cpu": "1",
                                "memory": "1Gi",
                                "ephemeralStorage": "1Gi"
                            }
                        }
                    }],
                    "exposedPorts": [{ "name": "http", "container": "agent", "port": 3000 }]
                },
                "isolation": { "tier": "trusted-runc" },
                "readiness": { "canary": { "argv": ["/bin/true"], "timeout": "30s" } }
            },
            "status": {
                "observedGeneration": 1,
                "ready": 1,
                "allocated": 0,
                "quarantined": 0,
                "certification": {
                    "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "observedGeneration": 1,
                    "phase": "certified",
                    "sandboxTemplate": {
                        "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxTemplate",
                        "namespace": "test-ns",
                        "name": "kobe-agent-small",
                        "uid": "template-uid",
                        "generation": 1
                    },
                    "sandboxWarmPool": {
                        "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxWarmPool",
                        "namespace": "test-ns",
                        "name": "kobe-agent-small",
                        "uid": "warm-pool-uid",
                        "generation": 3
                    },
                    "sandboxClaim": {
                        "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxClaim",
                        "namespace": "test-ns",
                        "name": "kobe-cert",
                        "uid": "cert-claim-uid"
                    },
                    "sandbox": {
                        "apiVersion": "agents.x-k8s.io/v1beta1",
                        "kind": "Sandbox",
                        "namespace": "test-ns",
                        "name": "cert-sandbox",
                        "uid": "cert-sandbox-uid"
                    },
                    "pod": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "namespace": "test-ns",
                        "name": "cert-pod",
                        "uid": "cert-pod-uid"
                    },
                    "teardownFence": {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "namespace": "test-ns",
                        "name": "retired-cert-fence",
                        "uid": "cert-fence-uid"
                    },
                    "drainGeneration": 2,
                    "replenishGeneration": 3,
                    "canaryPassedAt": "2026-08-20T00:00:00Z",
                    "certifiedAt": "2026-08-20T00:01:00Z"
                },
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "Certified",
                    "message": "test fixture represents a fully certified pool",
                    "observedGeneration": 1,
                    "lastTransitionTime": "2026-08-20T00:00:00Z"
                }]
            }
        })
    }

    fn pool_reference() -> SandboxPoolReference {
        SandboxPoolReference {
            name: "agent-small".into(),
            uid: "pool-uid".into(),
            generation: 1,
        }
    }

    fn crd_json(name: &str, plural: &str, kind: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": name },
            "spec": {
                "group": "kobe.kunobi.ninja",
                "names": { "kind": kind, "plural": plural },
                "scope": "Namespaced",
                "versions": [{
                    "name": "v1alpha1",
                    "served": true,
                    "storage": true,
                    "schema": { "openAPIV3Schema": { "type": "object" } }
                }]
            },
            "status": {
                "conditions": [{
                    "type": "Established",
                    "status": "True",
                    "reason": "InitialNamesAccepted",
                    "message": "accepted",
                    "lastTransitionTime": "2026-08-10T00:00:00Z"
                }]
            }
        })
    }

    async fn mount_sandbox_crds(server: &MockServer) {
        for (name, plural, kind) in [
            (SANDBOX_POOL_CRD, "sandboxpools", "SandboxPool"),
            (SANDBOX_LEASE_CRD, "sandboxleases", "SandboxLease"),
            (
                SANDBOX_EXECUTION_CRD,
                "sandboxexecutions",
                "SandboxExecution",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}"
                )))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(crd_json(name, plural, kind)),
                )
                .mount(server)
                .await;
        }
    }

    fn lease_json(name: &str, requester: &str, phase: &str) -> serde_json::Value {
        let principal = principal_hash_for(&SandboxPrincipal {
            provider: "developer-oidc".into(),
            requester_type: "oidc:developer".into(),
            issuer: "https://issuer.example".into(),
            identity: requester.into(),
        });
        let quota_name = quota_reservation_name(&principal, 0);
        let provenance = serde_json::to_string(&vec![AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            uid: format!("{quota_name}-uid"),
            name: quota_name,
        }])
        .unwrap();
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxLease",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
                "resourceVersion": "1",
                "creationTimestamp": "2026-08-10T00:00:00Z"
                ,"labels": {
                    SANDBOX_POOL_LABEL: "agent-small",
                    REQUESTER_HASH_LABEL: principal_hash(&identity())
                },
                "annotations": {
                    SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_ADMITTED,
                    SANDBOX_RESERVATIONS_ANNOTATION: provenance
                }
            },
            "spec": {
                "poolRef": {
                    "name": "agent-small",
                    "uid": "pool-uid",
                    "generation": 1
                },
                "ttl": "1h",
                "requester": {
                    "provider": "developer-oidc",
                    "type": "oidc:developer",
                    "issuer": "https://issuer.example",
                    "identity": requester
                }
            },
            "status": { "phase": phase, "observedGeneration": 1 }
        })
    }

    fn pristine_pending_json(name: &str, admission: Option<&str>) -> serde_json::Value {
        let mut lease = lease_json(name, "alice@example.com", "Pending");
        lease["metadata"]["annotations"] = admission.map_or_else(
            || serde_json::json!({}),
            |admission| serde_json::json!({ SANDBOX_ADMISSION_ANNOTATION: admission }),
        );
        lease["metadata"]["finalizers"] = serde_json::json!([SANDBOX_LEASE_FINALIZER]);
        lease["status"] = serde_json::json!({
            "phase": "Pending",
            "provisioningDeadline": "2026-08-10T00:10:00Z"
        });
        lease
    }

    fn active_release_json(name: &str, admission: Option<&str>) -> serde_json::Value {
        let mut lease = lease_json(name, "alice@example.com", "Ready");
        if let Some(admission) = admission {
            lease["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                serde_json::json!(admission);
        } else {
            lease["metadata"]["annotations"]
                .as_object_mut()
                .unwrap()
                .remove(SANDBOX_ADMISSION_ANNOTATION);
        }
        lease["metadata"]["finalizers"] = serde_json::json!([SANDBOX_LEASE_FINALIZER]);
        lease["status"] = serde_json::json!({
            "phase": "Ready",
            "observedGeneration": 1,
            "readyAt": "2026-08-10T00:02:00Z",
            "expiresAt": "2026-08-10T01:02:00Z",
            "placement": { "type": "management" },
            "target": {
                "namespace": "test-ns",
                "sandboxClaim": {
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim", "namespace": "test-ns",
                    "name": "claim", "uid": "claim-uid"
                },
                "sandbox": {
                    "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                    "namespace": "test-ns", "name": "sbx", "uid": "sandbox-uid"
                },
                "pod": {
                    "apiVersion": "v1", "kind": "Pod",
                    "namespace": "test-ns", "name": "sbx-0", "uid": "pod-uid"
                }
            }
        });
        lease
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Mock the coordination-Lease API with the semantics the CAS ledger
    /// depends on:
    ///
    /// - `CREATE` succeeds on a free name and returns 409 on a taken one,
    ///   exactly as the API server serializes competing writers;
    /// - `LIST` honours `labelSelector`. This matters: the release path selects
    ///   on the lease-UID label, so a mock that ignored selectors would let one
    ///   lease's cleanup delete another lease's reservations and hide a real
    ///   fencing bug.
    ///
    /// `preheld` simulates reservations another lease already owns, which is how
    /// quota exhaustion and alias conflicts are provoked deterministically
    /// without running concurrent requests. They are labelled with a foreign
    /// lease UID, so correct code must leave them alone.
    ///
    /// Returns the live ledger so a test can assert what was acquired and,
    /// crucially, what was released again.
    async fn mount_reservation_api(
        server: &MockServer,
        preheld: &[String],
    ) -> Arc<Mutex<std::collections::BTreeMap<String, serde_json::Value>>> {
        mount_reservation_api_owned(
            server,
            &preheld
                .iter()
                .map(|name| (name.clone(), FOREIGN_LEASE_UID.to_string()))
                .collect::<Vec<_>>(),
        )
        .await
    }

    const FOREIGN_LEASE_UID: &str = "preheld-foreign-lease-uid";

    /// Like `mount_reservation_api`, but each pre-held reservation names the
    /// SandboxLease UID that owns it — so a test can model reservations
    /// stranded by a *specific* lease and watch them actually be released.
    async fn mount_reservation_api_owned(
        server: &MockServer,
        preheld: &[(String, String)],
    ) -> Arc<Mutex<std::collections::BTreeMap<String, serde_json::Value>>> {
        const RESERVATIONS: &str = "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases";

        // Reconstruct the labels a real reservation would carry from its name
        // (`sbx-<type>-<principal>-<suffix>`), so selector filtering behaves.
        let seeded: std::collections::BTreeMap<String, serde_json::Value> = preheld
            .iter()
            .map(|(name, owner_uid)| {
                let parts: Vec<&str> = name.splitn(4, '-').collect();
                let reservation_type = parts.get(1).copied().unwrap_or_default();
                let principal = parts.get(2).copied().unwrap_or_default();
                let lease_name = owner_uid.strip_suffix("-uid").unwrap_or(owner_uid);
                (
                    name.clone(),
                    serde_json::json!({
                        "apiVersion": "coordination.k8s.io/v1",
                        "kind": "Lease",
                        "metadata": {
                            "name": name,
                            "namespace": TEST_LEDGER_NAMESPACE,
                            "uid": format!("{name}-uid"),
                            "resourceVersion": "1",
                            "labels": {
                                SANDBOX_RESERVATION_TYPE_LABEL: reservation_type,
                                SANDBOX_RESERVATION_LEASE_UID_LABEL: owner_uid,
                                REQUESTER_HASH_LABEL: principal,
                            },
                            "annotations": {
                                SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION: lease_name,
                            }
                        },
                        "spec": {}
                    }),
                )
            })
            .collect();
        let held = Arc::new(Mutex::new(seeded));

        let create_state = Arc::clone(&held);
        Mock::given(method("POST"))
            .and(path(RESERVATIONS))
            .respond_with(move |request: &wiremock::Request| {
                let mut object: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let name = object["metadata"]["name"].as_str().unwrap().to_string();
                let mut state = create_state.lock().unwrap();
                if state.contains_key(&name) {
                    return ResponseTemplate::new(409).set_body_json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "reason": "AlreadyExists",
                        "message": format!("leases.coordination.k8s.io \"{name}\" already exists"),
                        "code": 409
                    }));
                }
                object["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
                object["metadata"]["resourceVersion"] = serde_json::json!("1");
                state.insert(name, object.clone());
                ResponseTemplate::new(201).set_body_json(object)
            })
            .mount(server)
            .await;

        let delete_state = Arc::clone(&held);
        Mock::given(method("DELETE"))
            .and(path_regex(
                r"^/apis/coordination\.k8s\.io/v1/namespaces/sandbox-ledger/leases/.+$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let name = request
                    .url
                    .path()
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                // Honour the UID precondition, exactly as the API server does.
                // Without this the mock deletes by bare name, and the UID
                // fencing the release path depends on goes untested — a
                // regression that stole another lease's reservation would pass.
                let precondition_uid = serde_json::from_slice::<serde_json::Value>(&request.body)
                    .ok()
                    .and_then(|body| {
                        body["preconditions"]["uid"]
                            .as_str()
                            .map(|uid| uid.to_string())
                    });
                let mut state = delete_state.lock().unwrap();
                let actual_uid = state
                    .get(&name)
                    .and_then(|object| object["metadata"]["uid"].as_str().map(|s| s.to_string()));
                match (actual_uid, precondition_uid) {
                    (None, _) => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    })),
                    (Some(actual), Some(expected)) if actual != expected => {
                        ResponseTemplate::new(409).set_body_json(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "Conflict",
                            "message": "the UID in the precondition does not match",
                            "code": 409
                        }))
                    }
                    (Some(_), _) => {
                        state.remove(&name);
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success"
                        }))
                    }
                }
            })
            .mount(server)
            .await;

        let list_state = Arc::clone(&held);
        Mock::given(method("GET"))
            .and(path(RESERVATIONS))
            .respond_with(move |request: &wiremock::Request| {
                let selector = request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "labelSelector")
                    .map(|(_, value)| value.to_string())
                    .unwrap_or_default();
                let required: Vec<(String, String)> = selector
                    .split(',')
                    .filter(|term| !term.is_empty())
                    .filter_map(|term| {
                        term.split_once('=')
                            .map(|(key, value)| (key.to_string(), value.to_string()))
                    })
                    .collect();
                let items: Vec<serde_json::Value> = list_state
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|object| {
                        required.iter().all(|(key, value)| {
                            object["metadata"]["labels"][key].as_str() == Some(value.as_str())
                        })
                    })
                    .cloned()
                    .collect();
                ResponseTemplate::new(200).set_body_json(crate::testutil::k8s_list_response(items))
            })
            .mount(server)
            .await;

        let get_state = Arc::clone(&held);
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/coordination\.k8s\.io/v1/namespaces/sandbox-ledger/leases/.+$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let name = request.url.path().rsplit('/').next().unwrap_or_default();
                match get_state.lock().unwrap().get(name).cloned() {
                    Some(object) => ResponseTemplate::new(200).set_body_json(object),
                    None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    })),
                }
            })
            .mount(server)
            .await;

        held
    }

    /// Full create-path harness: CRDs, an empty reservation ledger, and the
    /// SandboxLease object mocks.
    async fn mount_create_api(
        server: &MockServer,
        relist_created: bool,
        ambiguous_admit_response: bool,
    ) -> Arc<Mutex<Option<serde_json::Value>>> {
        mount_sandbox_crds(server).await;
        mount_reservation_api(server, &[]).await;
        mount_create_lease_objects(server, relist_created, ambiguous_admit_response).await
    }

    /// Just the SandboxLease object mocks, for tests that mount their own
    /// reservation ledger with pre-held slots.
    async fn mount_create_lease_only(server: &MockServer) -> Arc<Mutex<Option<serde_json::Value>>> {
        mount_create_lease_objects(server, true, false).await
    }

    async fn mount_create_lease_objects(
        server: &MockServer,
        relist_created: bool,
        ambiguous_admit_response: bool,
    ) -> Arc<Mutex<Option<serde_json::Value>>> {
        let lease_state = Arc::new(Mutex::new(None::<serde_json::Value>));
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool_json()))
            .mount(server)
            .await;

        let list_state = Arc::clone(&lease_state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let items = if relist_created {
                    list_state.lock().unwrap().clone().into_iter().collect()
                } else {
                    Vec::new()
                };
                ResponseTemplate::new(200).set_body_json(crate::testutil::k8s_list_response(items))
            })
            .mount(server)
            .await;

        let create_state = Arc::clone(&lease_state);
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let mut object: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let name = object["metadata"]["name"].as_str().unwrap().to_string();
                object["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
                object["metadata"]["resourceVersion"] = serde_json::json!("1");
                object["metadata"]["creationTimestamp"] = serde_json::json!("2026-08-10T00:00:00Z");
                *create_state.lock().unwrap() = Some(object.clone());
                ResponseTemplate::new(201).set_body_json(object)
            })
            .mount(server)
            .await;

        let get_state = Arc::clone(&lease_state);
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |_: &wiremock::Request| match get_state.lock().unwrap().clone() {
                Some(object) => ResponseTemplate::new(200).set_body_json(object),
                None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "NotFound",
                    "code": 404
                })),
            })
            .mount(server)
            .await;

        let status_patch_state = Arc::clone(&lease_state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+/status$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("status JSON Patch");
                let status = operations
                    .as_array()
                    .and_then(|operations| {
                        operations.iter().find_map(|operation| {
                            (operation["op"] == "add" && operation["path"] == "/status")
                                .then(|| operation["value"].clone())
                        })
                    })
                    .expect("deadline status operation");
                let mut guard = status_patch_state.lock().unwrap();
                let object = guard.as_mut().expect("created lease");
                object["status"] = status;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .mount(server)
            .await;

        let patch_state = Arc::clone(&lease_state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let mut guard = patch_state.lock().unwrap();
                let object = guard.as_mut().expect("created lease");
                let patch: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                if let Some(operations) = patch.as_array() {
                    for operation in operations {
                        if operation["op"] == "test" {
                            let actual = match operation["path"].as_str() {
                                Some("/metadata/uid") => &object["metadata"]["uid"],
                                Some("/metadata/resourceVersion") => {
                                    &object["metadata"]["resourceVersion"]
                                }
                                Some(
                                    "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
                                ) => &object["metadata"]["annotations"]
                                    [SANDBOX_ADMISSION_ANNOTATION],
                                _ => continue,
                            };
                            if actual != &operation["value"] {
                                return ResponseTemplate::new(409).set_body_json(
                                    serde_json::json!({
                                        "apiVersion": "v1", "kind": "Status",
                                        "status": "Failure", "reason": "Conflict", "code": 409
                                    }),
                                );
                            }
                            continue;
                        }
                        match operation["path"].as_str() {
                            Some("/metadata/finalizers") => {
                                object["metadata"]["finalizers"] = operation["value"].clone();
                            }
                            Some(
                                "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission",
                            ) => {
                                object["metadata"]["annotations"]
                                    [SANDBOX_ADMISSION_ANNOTATION] = operation["value"].clone();
                            }
                            Some(
                                "/metadata/annotations/kobe.kunobi.ninja~1sandbox-reservations",
                            ) => {
                                object["metadata"]["annotations"]
                                    [SANDBOX_RESERVATIONS_ANNOTATION] = operation["value"].clone();
                            }
                            Some(
                                "/metadata/annotations/kobe.kunobi.ninja~1sandbox-access-gate",
                            ) => {
                                object["metadata"]["annotations"]
                                    [crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION] =
                                    operation["value"].clone();
                            }
                            _ => {}
                        }
                    }
                    let next_resource_version = object["metadata"]["resourceVersion"]
                        .as_str()
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0)
                        + 1;
                    object["metadata"]["resourceVersion"] =
                        serde_json::json!(next_resource_version.to_string());
                    let admitted = object["metadata"]["annotations"]
                        [SANDBOX_ADMISSION_ANNOTATION]
                        == SANDBOX_ADMISSION_ADMITTED;
                    if ambiguous_admit_response && admitted {
                        return ResponseTemplate::new(500).set_body_json(serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Status",
                            "status": "Failure",
                            "reason": "InternalError",
                            "code": 500
                        }));
                    }
                    return ResponseTemplate::new(200).set_body_json(object.clone());
                }
                for (key, value) in patch["metadata"]["annotations"]
                    .as_object()
                    .expect("admission annotations")
                {
                    object["metadata"]["annotations"][key] = value.clone();
                }
                object["metadata"]["resourceVersion"] = serde_json::json!("3");
                if ambiguous_admit_response {
                    ResponseTemplate::new(500).set_body_json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "reason": "InternalError",
                        "code": 500
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(object.clone())
                }
            })
            .mount(server)
            .await;

        let delete_state = Arc::clone(&lease_state);
        Mock::given(method("DELETE"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |_: &wiremock::Request| {
                *delete_state.lock().unwrap() = None;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200
                }))
            })
            .mount(server)
            .await;

        lease_state
    }

    /// HTTP admission consumes only a current-generation Ready=True
    /// certificate. Missing, stale, and explicitly false Pool status must stop
    /// before the API creates even a pending SandboxLease.
    #[tokio::test]
    async fn admission_fails_closed_for_uncertified_pool_status() {
        for variant in ["missing", "stale", "false", "receiptless"] {
            let server = MockServer::start().await;
            mount_sandbox_crds(&server).await;
            let mut pool = pool_json();
            match variant {
                "missing" => {
                    pool.as_object_mut().unwrap().remove("status");
                }
                "stale" => {
                    pool["status"]["observedGeneration"] = serde_json::json!(0);
                }
                "false" => {
                    pool["status"]["conditions"][0]["status"] = serde_json::json!("False");
                    pool["status"]["conditions"][0]["reason"] =
                        serde_json::json!("CertificationPending");
                }
                "receiptless" => {
                    pool["status"]
                        .as_object_mut()
                        .unwrap()
                        .remove("certification");
                }
                _ => unreachable!(),
            }
            Mock::given(method("GET"))
                .and(path(
                    "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(pool))
                .mount(&server)
                .await;

            let response = create_sandbox_lease::<crate::testutil::MockBackend>(
                State(test_state(&server)),
                identity(),
                Json(CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                }),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "variant {variant}"
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == "POST"
                            && request.url.path().ends_with("/sandboxleases")
                    })
                    .count(),
                0,
                "variant {variant} must fail before lease creation"
            );
        }
    }

    #[tokio::test]
    async fn composition_eligible_child_pool_remains_closed_to_http_admission() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let mut pool = pool_json();
        pool["spec"]["placement"] = serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "children"
        });
        pool["status"]["placementAuthority"] = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "namespace": "test-ns",
            "name": "children",
            "uid": "cluster-pool-uid",
            "generation": 1
        });
        pool["status"]["conditions"] = serde_json::json!([{
            "type": "Ready",
            "status": "False",
            "reason": "CompositionEligible",
            "message": "discovery only",
            "observedGeneration": 1
        }]);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool))
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path().ends_with("/sandboxleases")
                })
                .count(),
            0
        );
    }

    #[test]
    fn request_rejects_server_owned_and_unsafe_fields() {
        for field in [
            "requester",
            "namespace",
            "runtimeClassName",
            "podSpec",
            "credentials",
            "placementAuthority",
        ] {
            let mut value = serde_json::json!({ "pool": "agent-small", "ttl": "1h" });
            value[field] = serde_json::json!({ "identity": "mallory" });
            assert!(
                serde_json::from_value::<CreateSandboxLeaseRequest>(value).is_err(),
                "field {field} must be rejected"
            );
        }
    }

    #[test]
    fn build_lease_derives_requester_and_contains_no_target_or_credentials() {
        let identity = identity();
        let lease = build_sandbox_lease(
            "sandbox-abc",
            "kobe",
            pool_reference(),
            None,
            "30m",
            Some("review"),
            &identity,
        );
        assert_eq!(lease.spec.requester.identity, identity.identity);
        assert_eq!(lease.spec.alias.as_deref(), Some("review"));
        assert!(lease.spec.placement_authority.is_none());
        assert!(lease.status.is_none());
        assert_eq!(
            normalized_finalizers(&lease),
            [SANDBOX_LEASE_FINALIZER],
            "cleanup fencing must exist on the initial object, not arrive later from a controller"
        );
        let json = serde_json::to_string(&lease).unwrap();
        assert!(!json.contains("placementAuthority"));
        for forbidden in ["kubeconfig", "bearer", "token", "credentials", "podSpec"] {
            assert!(
                !json
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase())
            );
        }
    }

    /// Admission snapshots UID and generation; a later same-named ClusterPool
    /// replacement cannot rewrite the lease's server-owned authority.
    #[test]
    fn admission_copies_child_authority_without_following_name_reuse() {
        let mut value = pool_json();
        value["spec"]["placement"] = serde_json::json!({
            "type": "childCluster",
            "clusterPoolRef": "children"
        });
        value["status"]["placementAuthority"] = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "namespace": "test-ns",
            "name": "children",
            "uid": "original-cluster-pool-uid",
            "generation": 4
        });
        value["status"]["conditions"] = serde_json::json!([{
            "type": "Ready",
            "status": "False",
            "reason": "CompositionEligible",
            "message": "discovery only",
            "observedGeneration": 1
        }]);
        let mut pool: SandboxPool = serde_json::from_value(value).unwrap();
        let copied = sandbox_placement_authority_for_admission(&pool)
            .unwrap()
            .expect("child authority");
        let expected = build_sandbox_lease(
            "sandbox-abc",
            "test-ns",
            pool_reference(),
            Some(copied.clone()),
            "30m",
            None,
            &identity(),
        );

        let replacement = SandboxPlacementAuthority {
            uid: "replacement-cluster-pool-uid".into(),
            generation: 1,
            ..copied.clone()
        };
        pool.status.as_mut().unwrap().placement_authority = Some(replacement.clone());
        assert_eq!(
            sandbox_placement_authority_for_admission(&pool).unwrap(),
            Some(replacement.clone())
        );
        assert_eq!(expected.spec.placement_authority, Some(copied));

        let mut rewritten = expected.clone();
        rewritten.metadata.uid = Some("lease-uid".into());
        rewritten.metadata.resource_version = Some("1".into());
        rewritten.spec.placement_authority = Some(replacement);
        assert!(matches!(
            validate_lease_shape(&expected, &rewritten, SANDBOX_ADMISSION_PENDING),
            Err(SandboxLeaseMutationError::LeaseShapeChanged)
        ));
    }

    #[test]
    fn admission_rejects_any_cleanup_finalizer_drift() {
        let expected = build_sandbox_lease(
            "sandbox-abc",
            "kobe",
            pool_reference(),
            None,
            "30m",
            None,
            &identity(),
        );
        let mut actual = expected.clone();
        actual.metadata.uid = Some("lease-uid".into());
        actual.metadata.resource_version = Some("1".into());
        assert!(validate_lease_shape(&expected, &actual, SANDBOX_ADMISSION_PENDING).is_ok());

        actual
            .metadata
            .finalizers
            .as_mut()
            .unwrap()
            .push("foreign.example/cleanup".into());
        assert!(matches!(
            validate_lease_shape(&expected, &actual, SANDBOX_ADMISSION_PENDING),
            Err(SandboxLeaseMutationError::LeaseShapeChanged)
        ));
    }

    #[test]
    fn quarantined_lease_still_consumes_quota() {
        assert!(SandboxLeasePhase::Pending.consumes_capacity());
        assert!(SandboxLeasePhase::Provisioning.consumes_capacity());
        assert!(SandboxLeasePhase::Ready.consumes_capacity());
        assert!(SandboxLeasePhase::Releasing.consumes_capacity());
        assert!(SandboxLeasePhase::Quarantined.consumes_capacity());
        assert!(!SandboxLeasePhase::Released.consumes_capacity());
        assert!(!SandboxLeasePhase::Expired.consumes_capacity());
    }

    #[test]
    fn response_never_contains_requester_or_credentials() {
        let mut lease = build_sandbox_lease(
            "sandbox-abc",
            "kobe",
            pool_reference(),
            None,
            "30m",
            None,
            &identity(),
        );
        lease.status = Some(SandboxLeaseStatus::default());
        let json = serde_json::to_string(&sandbox_lease_response(lease.clone(), None)).unwrap();
        assert!(!json.contains("alice@example.com"));
        assert!(!json.to_ascii_lowercase().contains("token"));
        assert!(!json.to_ascii_lowercase().contains("kubeconfig"));
        assert!(!json.contains("release_cause"));

        lease.status.as_mut().unwrap().release_cause =
            Some(SandboxReleaseCause::ProvisioningDeadline);
        let json = serde_json::to_value(sandbox_lease_response(lease, None)).unwrap();
        assert_eq!(json["release_cause"], "ProvisioningDeadline");
    }

    // NOTE: `quota_race_resolution_is_deterministic` lived here and is gone.
    // It exercised `lease_exceeds_quota`, an advisory list-then-rank check from
    // the design this branch replaced. Ranking a LIST cannot decide admission:
    // two API replicas can both observe a free slot and both admit. The
    // coordination-Lease CAS ledger above is authoritative instead, so the old
    // test pinned a contract that no longer exists.

    #[test]
    fn principal_hash_separates_providers_and_issuers() {
        let base = identity();
        let mut other_provider = base.clone();
        other_provider.provider = "other-oidc".into();
        let mut other_issuer = base.clone();
        other_issuer.issuer = "https://other.example".into();
        assert_ne!(principal_hash(&base), principal_hash(&other_provider));
        assert_ne!(principal_hash(&base), principal_hash(&other_issuer));

        // The hash NAMES the quota and alias reservations, so its width is a
        // security property, not a formatting detail: a short digest lets a
        // caller steer their identity onto a victim's hash and occupy that
        // victim's slots. 128 bits, hex-encoded.
        assert_eq!(
            principal_hash(&base).len(),
            32,
            "principal hash must retain 128 bits — it namespaces quota and aliases"
        );
        assert!(principal_hash(&base).chars().all(|c| c.is_ascii_hexdigit()));

        // Length-prefixing must stop component boundaries from sliding.
        let mut split_a = base.clone();
        split_a.provider = "ab".into();
        split_a.issuer = "c".into();
        let mut split_b = base.clone();
        split_b.provider = "a".into();
        split_b.issuer = "bc".into();
        assert_ne!(
            principal_hash(&split_a),
            principal_hash(&split_b),
            "concatenation must be unambiguous across component boundaries"
        );
    }

    /// A role change must not move a principal into a fresh quota namespace.
    ///
    /// `requester_type` is `"{provider}:{matched rule value}"` — it names the
    /// AccessPolicy rule that happened to match *this* request, not the caller.
    /// It moves when an admin reorders or edits rules, when the IdP changes a
    /// claim, and — decisively — when the same subject presents a token whose
    /// claims select a different rule. Feeding it into the digest would make
    /// every one of those a rename of `sbx-quota-{hash}-{slot}` and
    /// `sbx-alias-{hash}-{alias}`.
    ///
    /// A rename is a bypass, not a partition: the old reservations still exist
    /// and still consume backend resources, but the new selector cannot see
    /// them, so the caller immediately gets their full `max_concurrent_leases`
    /// again and can re-take an alias someone is still holding. `principal_hash`
    /// already documents that hazard for a *code* change, where it is a one-off
    /// migration; including `requester_type` would make it reachable at runtime,
    /// repeatedly, by a caller who can influence their own claims.
    ///
    /// The exclusion is therefore the safe direction, and this test is what
    /// stops it being "corrected" later.
    #[test]
    fn a_changed_requester_type_keeps_a_principal_in_the_same_quota_namespace() {
        let base = identity();
        let mut promoted = base.clone();
        promoted.requester_type = "oidc:admin".into();

        assert_eq!(
            principal_hash(&base),
            principal_hash(&promoted),
            "a role change must not renumber this principal's quota slots"
        );

        // The digest is only a prefilter; ownership is decided by
        // `principal_matches`. The two must agree, or the label selector
        // narrows a caller out of leases they still own — and then they cannot
        // release the very lease holding their slot.
        let lease = build_sandbox_lease(
            "sandbox-abc",
            "test-ns",
            pool_reference(),
            None,
            "1h",
            None,
            &base,
        );
        assert!(
            principal_owns_lease(&lease, &promoted),
            "a caller must keep ownership of their own lease across a role change"
        );
    }

    /// A caller whose every attempt fails must still run out of budget.
    ///
    /// This is the loop the rate limit exists to close. A principal at their
    /// concurrency limit is refused — but only after the handler has created a
    /// `SandboxLease`, contested the reservation ledger, and deleted the lease
    /// again. That work is done eagerly, before the answer is known, so an
    /// outcome-sensitive budget (charged on success, or refunded on failure)
    /// would leave the retry loop free and unbounded: the caller spends none of
    /// their own quota and saturates the API server every other principal
    /// shares.
    ///
    /// Asserting the limiter's arithmetic would prove nothing here — the
    /// mistake lives in *where* the handler charges, so the test has to be the
    /// endpoint. The request count is the assertion that matters: a throttled
    /// attempt must cost the API server nothing at all.
    #[tokio::test]
    async fn a_caller_whose_creates_all_fail_still_runs_out_of_admission_budget() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        // Both of this principal's slots are held by someone else's lease, so
        // every attempt below reaches the ledger and is refused there.
        mount_reservation_api(
            &server,
            &[
                quota_reservation_name(&principal, 0),
                quota_reservation_name(&principal, 1),
            ],
        )
        .await;
        mount_create_lease_objects(&server, false, false).await;

        // One state for every attempt: the limiter is shared process state, and
        // a fresh one per request would bound nothing.
        let state = test_state(&server);
        let attempt = || {
            create_sandbox_lease::<crate::testutil::MockBackend>(
                State(state.clone()),
                identity(),
                Json(CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                }),
            )
        };

        let burst = crate::api::sandbox_rate_limit::ADMISSION_BURST as u32;
        for index in 0..burst {
            let response = attempt().await;
            assert_eq!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "attempt {index} must be refused by the quota ledger"
            );
            assert!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .is_none(),
                "attempt {index} is within the burst and must reach the ledger, not the throttle"
            );
        }

        let throttled = attempt().await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            throttled
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_some(),
            "the throttled attempt must tell the caller when to come back"
        );

        let creates = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                request.method.as_str() == "POST" && request.url.path().ends_with("/sandboxleases")
            })
            .count();
        assert_eq!(
            creates as u32, burst,
            "a throttled attempt must not reach the API server at all"
        );
    }

    #[tokio::test]
    async fn sandbox_routes_require_authentication() {
        let server = MockServer::start().await;
        let app = crate::api::routes::build_router(test_state(&server));
        for (verb, uri) in [
            ("GET", "/v1/sandbox-leases"),
            ("POST", "/v1/sandbox-leases"),
            ("GET", "/v1/sandbox-leases/sandbox-a"),
            ("DELETE", "/v1/sandbox-leases/sandbox-a"),
        ] {
            let request = http::Request::builder()
                .method(verb)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{verb} {uri}");
        }
    }

    /// The id a caller is handed back must be usable as a lease id.
    ///
    /// REVIEW FINDING (expected to fail). `create_sandbox_lease` mints
    /// `sandbox-{12 hex}`, but `sandbox_access::looks_like_lease_id` decides
    /// "id or alias" by testing for a `sbx-` prefix. No id this endpoint issues
    /// carries it, so every operation addressed by id — logs, exec, attach,
    /// port-forward, executions — is routed through `resolve_alias`, finds no
    /// lease whose ALIAS is that string, and answers 404.
    ///
    /// That is the whole access surface dead for its primary identifier: `kobe
    /// sandbox run` creates a lease, is handed this id, and then cannot address
    /// it. Worse, the two are not merely disconnected: because the id falls
    /// through to alias resolution, a caller's own second lease created with
    /// `alias = <first lease's id>` silently captures operations aimed at the
    /// first — exactly the substitution `looks_like_lease_id` is documented to
    /// prevent.
    #[tokio::test]
    async fn the_id_a_caller_is_handed_back_resolves_as_a_lease_id() {
        let server = MockServer::start().await;
        mount_create_api(&server, true, false).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::ACCEPTED, "response: {body}");

        let id = body["id"].as_str().expect("the response carries an id");
        assert!(
            crate::api::sandbox_access::looks_like_lease_id(id),
            "the id this endpoint issues ({id:?}) is not recognised as a lease id, \
             so every operation addressed by it is resolved as an alias and 404s"
        );
    }

    #[tokio::test]
    async fn create_uses_server_identity_and_applies_pool_and_policy_ttl() {
        let server = MockServer::start().await;
        mount_create_api(&server, true, false).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("3h".into()),
                alias: Some("review".into()),
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::ACCEPTED, "response: {body}");
        assert_eq!(body["ttl"], "2h");
        assert_eq!(body["effective_ttl"], "2h");
        assert_eq!(body["provisioning_deadline"], "2026-08-10T00:10:00Z");
        assert!(body.get("kubeconfig").is_none());
        assert!(body.get("token").is_none());

        let requests = server.received_requests().await.unwrap();
        let create_index = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "POST" && request.url.path().ends_with("/sandboxleases")
            })
            .expect("SandboxLease create request");
        let deadline_index = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "PATCH"
                    && request.url.path().contains("/sandboxleases/sandbox-")
                    && request.url.path().ends_with("/status")
            })
            .expect("provisioning deadline status patch");
        let access_gate_index = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "POST"
                    && request.url.path()
                        == "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases"
                    && serde_json::from_slice::<serde_json::Value>(&request.body).is_ok_and(
                        |object| {
                            object["metadata"]["labels"]["kobe.kunobi.ninja/sandbox-access-kind"]
                                == "lease-gate"
                        },
                    )
            })
            .expect("distributed access gate create");
        let reservation_index = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "POST"
                    && request.url.path()
                        == "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases"
                    && serde_json::from_slice::<serde_json::Value>(&request.body).is_ok_and(
                        |object| {
                            object["metadata"]["labels"][SANDBOX_RESERVATION_TYPE_LABEL].is_string()
                        },
                    )
            })
            .expect("admission reservation create");
        let admission_index = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "PATCH"
                    && request.url.path().contains("/sandboxleases/sandbox-")
                    && !request.url.path().ends_with("/status")
            })
            .expect("admission metadata patch");
        assert!(
            create_index < deadline_index
                && deadline_index < access_gate_index
                && access_gate_index < reservation_index
                && reservation_index < admission_index,
            "the durable deadline and access gate must precede capacity reservation and admission"
        );

        let admission_patch: serde_json::Value =
            serde_json::from_slice(&requests[admission_index].body).unwrap();
        let admission_patch = admission_patch
            .as_array()
            .expect("admission must use JSON Patch");
        assert!(admission_patch.iter().any(|operation| {
            operation["op"] == "test" && operation["path"] == "/metadata/uid"
        }));
        assert!(admission_patch.iter().any(|operation| {
            operation["op"] == "test" && operation["path"] == "/metadata/resourceVersion"
        }));
        assert!(admission_patch.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                && operation["value"] == SANDBOX_ADMISSION_PENDING
        }));
        assert!(admission_patch.iter().any(|operation| {
            operation["op"] == "replace"
                && operation["path"] == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                && operation["value"] == SANDBOX_ADMISSION_ADMITTED
        }));

        let create = &requests[create_index];
        let object: serde_json::Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(object["spec"]["requester"]["identity"], "alice@example.com");
        assert_eq!(object["spec"]["requester"]["provider"], "developer-oidc");
        assert_eq!(object["spec"]["poolRef"]["uid"], "pool-uid");
        assert_eq!(object["spec"]["ttl"], "2h");
        assert_eq!(
            object["metadata"]["finalizers"],
            serde_json::json!([SANDBOX_LEASE_FINALIZER])
        );
        assert!(object["spec"].get("namespace").is_none());
        assert!(object["spec"].get("runtimeClassName").is_none());

        let operations: serde_json::Value =
            serde_json::from_slice(&requests[deadline_index].body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test" && operation["path"] == "/metadata/uid"
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "1"
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "add"
                && operation["path"] == "/status"
                && operation["value"]["phase"] == "Pending"
                && operation["value"]["provisioningDeadline"] == "2026-08-10T00:10:00Z"
        }));
    }

    #[tokio::test]
    async fn create_treats_applied_but_lost_admission_response_as_success() {
        let server = MockServer::start().await;
        let state = mount_create_api(&server, true, true).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            state.lock().unwrap().as_ref().unwrap()["metadata"]["finalizers"],
            serde_json::json!([SANDBOX_LEASE_FINALIZER]),
            "a lost admission response must not weaken the cleanup fence"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Admission must not consume quota until the API-server creation time has
    /// been converted into a durable provisioning deadline.
    #[tokio::test]
    async fn create_without_a_server_timestamp_never_reserves_quota() {
        let server = MockServer::start().await;
        let state = mount_create_api(&server, true, false).await;
        let create_state = Arc::clone(&state);
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let mut object: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let name = object["metadata"]["name"].as_str().unwrap().to_string();
                object["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
                object["metadata"]["resourceVersion"] = serde_json::json!("1");
                *create_state.lock().unwrap() = Some(object.clone());
                ResponseTemplate::new(201).set_body_json(object)
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method.as_str() != "POST"
                || request.url.path()
                    != "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases"
        }));
        assert!(requests.iter().any(|request| {
            request.method.as_str() == "DELETE"
                && request.url.path().contains("/sandboxleases/sandbox-")
        }));
    }

    /// A failed or unprovable status checkpoint is still before the admission
    /// commit point, so it removes the exact pending lease without reservations.
    #[tokio::test]
    async fn an_unproven_deadline_checkpoint_never_reserves_quota() {
        let server = MockServer::start().await;
        mount_create_api(&server, true, false).await;
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+/status$",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 500
            })))
            .with_priority(1)
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method.as_str() != "POST"
                || request.url.path()
                    != "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases"
        }));
        assert!(requests.iter().any(|request| {
            request.method.as_str() == "DELETE"
                && request.url.path().contains("/sandboxleases/sandbox-")
        }));
    }

    /// A lost status response is recoverable only when a re-read proves the
    /// exact deadline was committed to the exact created object.
    #[tokio::test]
    async fn create_recovers_an_exact_lost_deadline_checkpoint() {
        let server = MockServer::start().await;
        let state = mount_create_api(&server, true, false).await;
        let deadline_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+/status$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let status = operations
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|operation| operation["path"] == "/status")
                    .unwrap()["value"]
                    .clone();
                let mut guard = deadline_state.lock().unwrap();
                let object = guard.as_mut().unwrap();
                object["status"] = status;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 500
                }))
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// An admitted re-read with a mutated deadline cannot be reported as a
    /// normal accepted lease, but 503 would invite a duplicate. Preserve the
    /// exact ID as the distinct non-retry `admission_pending` handle.
    #[tokio::test]
    async fn a_lost_admission_response_with_deadline_drift_returns_only_pending_handle() {
        let server = MockServer::start().await;
        let state = mount_create_api(&server, true, false).await;
        let admission_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut guard = admission_state.lock().unwrap();
                let object = guard.as_mut().unwrap();
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                    serde_json::json!(SANDBOX_ADMISSION_ADMITTED);
                object["metadata"]["resourceVersion"] = serde_json::json!("3");
                object["status"]["provisioningDeadline"] =
                    serde_json::json!("2099-01-01T00:00:00Z");
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 500
                }))
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(
            response
                .headers()
                .contains_key(axum::http::header::LOCATION)
        );
        let body = response_json(response).await;
        assert_eq!(body["status"], "admission_pending");
        assert_eq!(body["retry"], false);
        assert_eq!(body["phase"], "Pending");
        assert!(body["provisioning_deadline"].as_str().is_some());
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    // NOTE: `create_fails_closed_and_removes_lease_missing_from_relist` was
    // here and is gone with the design it tested. It asserted that a lease
    // absent from a post-create LIST fails closed — the verification step of
    // the list-then-rank quota scheme this branch replaces. Under the CAS
    // ledger the LIST is not a verification step at all (it cannot be: two
    // replicas can both read a free slot), so the relist result no longer
    // decides admission. The tests below pin the mechanism that does.

    /// A request that dies between reserving and admitting must not lock its
    /// principal out permanently.
    ///
    /// This is the boundary the bug actually reaches a user at: reservations
    /// deliberately outlive SandboxLease garbage collection until Kobe performs
    /// exact cleanup. A lease abandoned at `pending` is never handled by
    /// placement, so its slot and alias stay consumed and every retry returns
    /// 429/409 without the admission reaper.
    ///
    /// Asserting only that `pending_admission_cancellation_due` returns true would prove
    /// nothing: the fix lives in the create handler, so the test has to be the
    /// create that was previously refused.
    #[tokio::test]
    async fn create_reclaims_quota_stranded_by_its_own_abandoned_lease() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());

        // One slot is stranded by the lease that never reached `admitted`; the
        // other belongs to a different live lease. Admission creates at most
        // one quota token per lease, and cleanup now rejects impossible
        // multi-slot ownership rather than normalising corrupted state.
        let stranded_uid = "sandbox-stranded-uid";
        let held = mount_reservation_api_owned(
            &server,
            &[
                (
                    quota_reservation_name(&principal, 0),
                    stranded_uid.to_string(),
                ),
                (
                    quota_reservation_name(&principal, 1),
                    FOREIGN_LEASE_UID.to_string(),
                ),
            ],
        )
        .await;

        // The abandoned lease itself: same principal, still `pending`, and old
        // enough to be past the deadline.
        let abandoned = {
            let mut object = lease_json("sandbox-stranded", "alice@example.com", "Pending");
            object["metadata"]["uid"] = serde_json::json!(stranded_uid);
            object["metadata"]["creationTimestamp"] =
                serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339());
            object["metadata"]["annotations"] = serde_json::json!({
                SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
            });
            object["status"] = serde_json::json!({ "phase": "Pending" });
            object
        };
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![abandoned.clone()])),
            )
            .mount(&server)
            .await;
        let abandoned_state = Arc::new(Mutex::new(Some(abandoned.clone())));
        let get_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stranded",
            ))
            .respond_with(move |_: &wiremock::Request| {
                match get_abandoned_state.lock().unwrap().clone() {
                    Some(object) => ResponseTemplate::new(200).set_body_json(object),
                    None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    })),
                }
            })
            .mount(&server)
            .await;
        let cancel_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stranded",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("cancellation JSON Patch");
                let operations = operations.as_array().expect("JSON Patch operations");
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == stranded_uid
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                        && operation["value"] == SANDBOX_ADMISSION_PENDING
                }));
                let mut guard = cancel_abandoned_state.lock().unwrap();
                let object = guard.as_mut().expect("lease is still present");
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                    serde_json::json!(SANDBOX_ADMISSION_CANCELLED);
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let delete_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stranded",
            ))
            .respond_with(move |_: &wiremock::Request| {
                *delete_abandoned_state.lock().unwrap() = None;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success"
                }))
            })
            .mount(&server)
            .await;
        mount_create_lease_only(&server).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "a principal locked out by their own abandoned lease must recover on retry"
        );

        // The slot names are expected to still be occupied — by the NEW lease,
        // which re-acquired them. What must be gone is any reservation still
        // carrying the abandoned lease's exact UID.
        let remaining = held.lock().unwrap().clone();
        let still_stranded: Vec<&String> = remaining
            .iter()
            .filter(|(_, object)| {
                object["metadata"]["labels"][SANDBOX_RESERVATION_LEASE_UID_LABEL].as_str()
                    == Some(stranded_uid)
            })
            .map(|(name, _)| name)
            .collect();
        assert!(
            still_stranded.is_empty(),
            "reservations carrying the abandoned lease UID must be released: {still_stranded:?}"
        );
    }

    /// Age authorizes cancellation but never proves a request died.
    ///
    /// The actual safety proof is the pending-to-cancelled CAS. This boundary
    /// test only pins when the controller is allowed to attempt that CAS.
    #[test]
    fn only_leases_past_the_deadline_may_be_cancelled() {
        let now = chrono::Utc::now();
        let fresh = (now - chrono::Duration::seconds(5)).to_rfc3339();
        let old = (now - chrono::Duration::seconds(SANDBOX_PENDING_CANCEL_DEADLINE_SECS + 60))
            .to_rfc3339();

        assert!(!pending_admission_cancellation_due(Some(&fresh), now));
        assert!(pending_admission_cancellation_due(Some(&old), now));
        assert!(!pending_admission_cancellation_due(None, now));
        assert!(!pending_admission_cancellation_due(
            Some("not-a-timestamp"),
            now
        ));
    }

    /// Admission and cancellation must contend on one API-server transaction.
    ///
    /// Here admission lands immediately before the cancellation PATCH. The
    /// stale cancellation receives a conflict, re-reads `admitted`, and must
    /// never turn that real success into deletion or a retry-inducing failure.
    #[tokio::test]
    async fn admitted_winner_survives_the_expiry_cancellation_cas() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let mut object = lease_json("sandbox-cas", "alice@example.com", "Pending");
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({ "phase": "Pending" });
        let expected: SandboxLease = serde_json::from_value(object.clone()).unwrap();
        let reservation_name = quota_reservation_name(&principal, 0);
        let provenance = serde_json::to_string(&vec![AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name: reservation_name.clone(),
            uid: format!("{reservation_name}-uid"),
        }])
        .unwrap();
        let state = Arc::new(Mutex::new(object));

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-cas",
            ))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-cas",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let operations = operations.as_array().unwrap();
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == "sandbox-cas-uid"
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                        && operation["value"] == SANDBOX_ADMISSION_PENDING
                }));
                let mut current = patch_state.lock().unwrap();
                current["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                    serde_json::json!(SANDBOX_ADMISSION_ADMITTED);
                current["metadata"]["annotations"][SANDBOX_RESERVATIONS_ANNOTATION] =
                    serde_json::json!(provenance);
                current["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(409).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "Conflict", "code": 409
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let leases: Api<SandboxLease> =
            Api::namespaced(crate::testutil::mock_k8s_client(&server), "test-ns");
        let outcome = cancel_pending_admission(&leases, &expected)
            .await
            .expect("the committed winner must be resolved by re-read");
        assert!(matches!(
            outcome,
            PendingAdmissionCancellation::AdmissionWon(_)
        ));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Exhausting one bounded cancellation attempt is still not proof that
    /// admission failed. The resolver must keep the HTTP outcome undecided
    /// until a later exact read exposes the winner, otherwise a caller can
    /// retry into a second Sandbox after a lost response.
    #[tokio::test]
    async fn unresolved_cancellation_never_turns_late_admission_into_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let deadline = "2026-08-10T00:10:00Z";
        let reservation_name = quota_reservation_name(&principal, 0);
        let admission_reservations = vec![AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name: reservation_name.clone(),
            uid: format!("{reservation_name}-uid"),
        }];
        let provenance = serde_json::to_string(&admission_reservations).unwrap();
        let mut object = lease_json("sandbox-unresolved", "alice@example.com", "Pending");
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({
            "phase": "Pending",
            "provisioningDeadline": deadline
        });
        let expected: SandboxLease = serde_json::from_value(object.clone()).unwrap();
        let state = Arc::new(Mutex::new(object));

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-unresolved",
            ))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        let patch_attempts = Arc::new(AtomicUsize::new(0));
        let responder_attempts = Arc::clone(&patch_attempts);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-unresolved",
            ))
            .respond_with(move |_: &wiremock::Request| {
                if responder_attempts.fetch_add(1, Ordering::SeqCst) >= 2 {
                    let mut current = patch_state.lock().unwrap();
                    current["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                        serde_json::json!(SANDBOX_ADMISSION_ADMITTED);
                    current["metadata"]["annotations"][SANDBOX_RESERVATIONS_ANNOTATION] =
                        serde_json::json!(provenance);
                    current["metadata"]["resourceVersion"] = serde_json::json!("2");
                }
                ResponseTemplate::new(409).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "Conflict", "code": 409
                }))
            })
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            resolve_timed_out_admission(
                &leases,
                &reservations,
                &expected,
                deadline,
                Some(&admission_reservations),
                None,
                &shutdown,
            ),
        )
        .await
        .expect("the resolver must make progress once the API exposes a winner");

        assert!(matches!(outcome, AdmissionResolution::Admitted));
        assert_eq!(patch_attempts.load(Ordering::SeqCst), 3);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Graceful shutdown must not wait forever for an ambiguous Kubernetes
    /// response, and it must not turn that ambiguity into a retryable 503 or a
    /// normal accepted lease. The durable parent is returned as the distinct
    /// `admission_pending` polling handle.
    #[tokio::test]
    async fn shutdown_hands_unresolved_admission_back_as_a_non_retry_handle() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let deadline = "2026-08-10T00:10:00Z";
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let admission_reservations = vec![AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name: reservation_name.clone(),
            uid: format!("{reservation_name}-uid"),
        }];
        let mut object = lease_json("sandbox-handoff", "alice@example.com", "Pending");
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"]["provisioningDeadline"] = serde_json::json!(deadline);
        let expected: SandboxLease = serde_json::from_value(object.clone()).unwrap();

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-handoff",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(object),
            )
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            trigger.cancel();
        });

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            resolve_timed_out_admission(
                &leases,
                &reservations,
                &expected,
                deadline,
                Some(&admission_reservations),
                None,
                &shutdown,
            ),
        )
        .await
        .expect("shutdown must bound an in-flight arbitration read");
        assert!(matches!(outcome, AdmissionResolution::HandedOff));

        let response = sandbox_admission_pending(
            "sandbox-handoff".into(),
            "agent-small".into(),
            "1h".into(),
            false,
            None,
            deadline.into(),
        );
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get(axum::http::header::LOCATION),
            Some(&axum::http::HeaderValue::from_static(
                "/v1/sandbox-leases/sandbox-handoff"
            ))
        );
        let body = response_json(response).await;
        assert_eq!(body["id"], "sandbox-handoff");
        assert_eq!(body["status"], "admission_pending");
        assert_eq!(body["retry"], false);
        assert_eq!(body["statusUrl"], "/v1/sandbox-leases/sandbox-handoff");
        assert_eq!(body["phase"], "Pending");
        assert_eq!(body["pool"], "agent-small");
        assert_eq!(body["provisioning_deadline"], deadline);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE"),
            "shutdown handoff must leave the durable parent for the reaper"
        );
    }

    /// Persistent Kubernetes errors cannot retain an HTTP task indefinitely.
    ///
    /// Every failed GET is ambiguous, so the resolver may neither DELETE nor
    /// return a retryable failure. Its independent deadline hands the durable
    /// parent to the supervised reaper and the handler returns the distinct
    /// polling-only 202 contract.
    #[tokio::test]
    async fn persistent_kubernetes_errors_handoff_without_deleting_admission() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let deadline = "2026-08-10T00:10:00Z";
        let mut object = lease_json("sandbox-api-down", "alice@example.com", "Pending");
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({
            "phase": "Pending",
            "provisioningDeadline": deadline
        });
        let expected: SandboxLease = serde_json::from_value(object).unwrap();

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-api-down",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "InternalError", "code": 500
            })))
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            resolve_timed_out_admission_until(
                &leases,
                &reservations,
                &expected,
                deadline,
                None,
                None,
                &shutdown,
                tokio::time::Instant::now() + std::time::Duration::from_millis(120),
            ),
        )
        .await
        .expect("the resolver's handoff deadline must bound persistent API errors");
        assert!(matches!(outcome, AdmissionResolution::HandedOff));

        let response = sandbox_admission_pending(
            "sandbox-api-down".into(),
            "agent-small".into(),
            "1h".into(),
            false,
            None,
            deadline.into(),
        );
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.method.as_str() == "GET")
        );
        assert!(
            requests
                .iter()
                .all(|request| { !matches!(request.method.as_str(), "PATCH" | "DELETE") })
        );
    }

    /// A reservation POST may commit after cancellation already deleted its
    /// parent. The next durable sweep must discover it by parent name+UID and
    /// delete the exact token under UID/resourceVersion preconditions.
    #[tokio::test]
    async fn a_late_reservation_post_is_recoverable_after_parent_deletion() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let held = mount_reservation_api_owned(&server, &[]).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-late",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);

        // First sweep sees no token: this is the parent cleanup's race window.
        reap_orphaned_admission_reservations(&leases, &reservations).await;
        assert!(held.lock().unwrap().is_empty());

        let principal = principal_hash(&identity());
        let mut parent: SandboxLease = serde_json::from_value({
            let mut value = lease_json("sandbox-late", "alice@example.com", "Pending");
            value["metadata"]["uid"] = serde_json::json!("sandbox-late-uid");
            value["metadata"]["annotations"] = serde_json::json!({
                SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
            });
            value
        })
        .unwrap();
        parent.metadata.resource_version = Some("1".into());
        let name = quota_reservation_name(&principal, 0);
        let reservation = build_admission_reservation(
            name.clone(),
            SANDBOX_RESERVATION_QUOTA,
            &parent,
            &principal,
            TEST_LEDGER_NAMESPACE,
        )
        .unwrap();
        let mut late = serde_json::to_value(reservation).unwrap();
        late["metadata"]["uid"] = serde_json::json!("late-token-uid");
        late["metadata"]["resourceVersion"] = serde_json::json!("9");
        held.lock().unwrap().insert(name.clone(), late);

        // The next sweep catches the POST even though no parent record remains.
        reap_orphaned_admission_reservations(&leases, &reservations).await;
        assert!(held.lock().unwrap().is_empty());

        let requests = server.received_requests().await.unwrap();
        let delete = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "DELETE"
                    && request.url.path().ends_with(&format!("/leases/{name}"))
            })
            .expect("the orphan token must be deleted");
        let options: serde_json::Value = serde_json::from_slice(&delete.body).unwrap();
        assert_eq!(options["preconditions"]["uid"], "late-token-uid");
        assert_eq!(options["preconditions"]["resourceVersion"], "9");
    }

    /// Token-carried parent hints are not allowed to override the admitted
    /// parent's exact persisted token set. Either hint may be changed to a
    /// different valid value without turning a live reservation into an
    /// orphan.
    #[tokio::test]
    async fn orphan_sweep_preserves_exact_tokens_persisted_by_a_live_parent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let held = mount_reservation_api_owned(
            &server,
            &[(reservation_name.clone(), "sandbox-live-uid".into())],
        )
        .await;
        let parent = lease_json("sandbox-live", "alice@example.com", "Pending");
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![parent])),
            )
            .mount(&server)
            .await;

        held.lock().unwrap().get_mut(&reservation_name).unwrap()["metadata"]["labels"]
            [SANDBOX_RESERVATION_LEASE_UID_LABEL] = serde_json::json!("sandbox-different-uid");
        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        reap_orphaned_admission_reservations(&leases, &reservations).await;
        assert!(held.lock().unwrap().contains_key(&reservation_name));

        {
            let mut guard = held.lock().unwrap();
            let token = guard.get_mut(&reservation_name).unwrap();
            token["metadata"]["labels"][SANDBOX_RESERVATION_LEASE_UID_LABEL] =
                serde_json::json!("sandbox-live-uid");
            token["metadata"]["annotations"][SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION] =
                serde_json::json!("sandbox-different");
        }
        reap_orphaned_admission_reservations(&leases, &reservations).await;

        assert!(held.lock().unwrap().contains_key(&reservation_name));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// A token exists before its exact name+UID set can be persisted on the
    /// parent. Mutable token hints must not let the orphan sweep delete that
    /// token while the admission CAS is already in flight: the CAS may still
    /// commit afterwards, which would leave a live admitted Sandbox uncounted.
    #[tokio::test]
    async fn orphan_sweep_retains_token_during_pending_to_admitted_cas() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let token_uid = format!("{reservation_name}-uid");
        let held = mount_reservation_api_owned(
            &server,
            &[(reservation_name.clone(), "sandbox-racing-uid".into())],
        )
        .await;
        {
            let mut guard = held.lock().unwrap();
            let token = guard.get_mut(&reservation_name).unwrap();
            token["metadata"]["labels"][SANDBOX_RESERVATION_LEASE_UID_LABEL] =
                serde_json::json!("sandbox-absent-uid");
            token["metadata"]["annotations"][SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION] =
                serde_json::json!("sandbox-absent");
        }

        let parent: SandboxLease = serde_json::from_value(pristine_pending_json(
            "sandbox-racing",
            Some(SANDBOX_ADMISSION_PENDING),
        ))
        .unwrap();
        let parent_state = Arc::new(Mutex::new(serde_json::to_value(&parent).unwrap()));
        let leases_path = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases";
        let parent_path = format!("{leases_path}/sandbox-racing");

        let list_state = Arc::clone(&parent_state);
        Mock::given(method("GET"))
            .and(path(leases_path))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(crate::testutil::k8s_list_response(vec![
                    list_state.lock().unwrap().clone(),
                ]))
            })
            .mount(&server)
            .await;
        let get_state = Arc::clone(&parent_state);
        Mock::given(method("GET"))
            .and(path(parent_path.clone()))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{leases_path}/sandbox-absent")))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;

        let reservation = AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name: reservation_name.clone(),
            uid: token_uid,
        };
        let persisted =
            encoded_reservation_provenance(&parent, std::slice::from_ref(&reservation)).unwrap();
        let parent_uid = parent.uid().unwrap();
        let access_gate = crate::sandbox_access_ledger::AccessGateReference {
            name: format!(
                "kobe-access-g-{}",
                &format!("{:x}", Sha256::digest(parent_uid.as_bytes()))[..40]
            ),
            uid: "access-gate-uid".into(),
        };
        let gate_provenance =
            crate::sandbox_access_ledger::encode_gate_reference(&access_gate).unwrap();
        let patch_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let allow_commit = Arc::new(tokio::sync::Notify::new());
        let patch_state = Arc::clone(&parent_state);
        let patch_signal = Arc::clone(&patch_started);
        let commit_signal = Arc::clone(&allow_commit);
        Mock::given(method("PATCH"))
            .and(path(parent_path))
            .respond_with(move |_: &wiremock::Request| {
                patch_signal.store(true, Ordering::SeqCst);
                let state = Arc::clone(&patch_state);
                let signal = Arc::clone(&commit_signal);
                let persisted = persisted.clone();
                let gate_provenance = gate_provenance.clone();
                tokio::spawn(async move {
                    signal.notified().await;
                    let mut parent = state.lock().unwrap();
                    parent["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                        serde_json::json!(SANDBOX_ADMISSION_ADMITTED);
                    parent["metadata"]["annotations"][SANDBOX_RESERVATIONS_ANNOTATION] =
                        serde_json::json!(persisted);
                    parent["metadata"]["annotations"]
                        [crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION] =
                        serde_json::json!(gate_provenance);
                    parent["metadata"]["resourceVersion"] = serde_json::json!("2");
                });
                // Model a committed PATCH whose response is lost. The delay
                // keeps the client future in flight until the test releases the
                // server-side commit after the orphan sweep snapshot.
                ResponseTemplate::new(500)
                    .set_delay(std::time::Duration::from_secs(1))
                    .set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "InternalError", "code": 500
                    }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let admit_leases = leases.clone();
        let admit_reservations = reservations.clone();
        let admit_parent = parent.clone();
        let admit_reservation = reservation.clone();
        let admission = tokio::spawn(async move {
            admit_sandbox_lease(
                &admit_leases,
                &admit_reservations,
                &admit_parent,
                &[admit_reservation],
                &access_gate,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !patch_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the admission PATCH must be in flight");

        reap_orphaned_admission_reservations(&leases, &reservations).await;
        assert!(held.lock().unwrap().contains_key(&reservation_name));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );

        allow_commit.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), admission)
            .await
            .expect("the lost-response admission must resolve")
            .unwrap()
            .unwrap();
        reap_orphaned_admission_reservations(&leases, &reservations).await;
        assert!(held.lock().unwrap().contains_key(&reservation_name));
        assert_eq!(
            parent_state.lock().unwrap()["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION],
            SANDBOX_ADMISSION_ADMITTED
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Broad protection is needed only before a parent has exact provenance.
    /// Once a live admitted lease names its own token, another orphaned slot for
    /// the same principal remains independently reclaimable after parent 404.
    #[tokio::test]
    async fn orphan_sweep_reclaims_unrelated_slot_beside_exact_live_provenance() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let live_name = quota_reservation_name(&principal, 0);
        let orphan_name = quota_reservation_name(&principal, 1);
        let held = mount_reservation_api_owned(
            &server,
            &[
                (live_name.clone(), "sandbox-live-uid".into()),
                (orphan_name.clone(), "sandbox-missing-uid".into()),
            ],
        )
        .await;
        let mut parent = lease_json("sandbox-live", "alice@example.com", "Pending");
        parent["metadata"]["finalizers"] = serde_json::json!([SANDBOX_LEASE_FINALIZER]);
        let leases_path = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases";
        Mock::given(method("GET"))
            .and(path(leases_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![parent])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{leases_path}/sandbox-missing")))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "NotFound", "code": 404
            })))
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        reap_orphaned_admission_reservations(&leases, &reservations).await;

        {
            let guard = held.lock().unwrap();
            assert!(guard.contains_key(&live_name));
            assert!(!guard.contains_key(&orphan_name));
        }
        let deletes: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .map(|request| request.url.path().rsplit('/').next().unwrap().to_string())
            .collect();
        assert_eq!(deletes, vec![orphan_name]);
    }

    #[test]
    fn active_timeout_precedes_controller_cancellation_deadline() {
        assert!(
            SANDBOX_ACTIVE_ADMISSION_TIMEOUT_SECS + SANDBOX_ADMISSION_RESOLUTION_TIMEOUT_SECS
                < SANDBOX_PENDING_CANCEL_DEADLINE_SECS as u64
        );
    }

    /// The create budget includes the pre-create recovery sweep. If that LIST
    /// stalls, the handler must time out before issuing any new mutating API
    /// request; starting the clock after the sweep makes this test hang.
    #[tokio::test]
    async fn admission_budget_expires_inside_the_abandoned_admission_sweep() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool_json()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(crate::testutil::k8s_list_response(
                        Vec::<serde_json::Value>::new(),
                    )),
            )
            .mount(&server)
            .await;

        // Leave enough wall-clock margin for the preceding local CRD and Pool
        // reads when the full test binary is scheduler-saturated. The mocked
        // sweep still stalls for 30 seconds, so this remains a stage-specific
        // deadline proof rather than a race against unrelated preflight work.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                test_state(&server),
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                deadline,
            ),
        )
        .await
        .expect("the active budget must bound the stalled recovery sweep");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_json(response).await;
        assert_eq!(
            body["error"],
            "Sandbox lease admission timed out during abandoned-admission recovery"
        );

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().any(|request| {
            request.method.as_str() == "GET" && request.url.path().ends_with("/sandboxleases")
        }));
        assert!(
            requests
                .iter()
                .all(|request| matches!(request.method.as_str(), "GET")),
            "no parent or reservation mutation may start after sweep budget expiry"
        );
    }

    /// CRD discovery is part of the request budget, not startup work the
    /// handler may wait on forever.
    #[tokio::test]
    async fn admission_budget_bounds_a_stalled_crd_preflight() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{SANDBOX_POOL_CRD}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(crd_json(SANDBOX_POOL_CRD, "sandboxpools", "SandboxPool")),
            )
            .with_priority(1)
            .mount(&server)
            .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                test_state(&server),
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                tokio::time::Instant::now() + std::time::Duration::from_millis(100),
            ),
        )
        .await
        .expect("the absolute deadline must stop a stalled CRD read");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() == "GET")
        );
    }

    /// Shutdown before the durable parent exists is a bounded retryable
    /// refusal and must not start a create after a stalled pool read.
    #[tokio::test]
    async fn shutdown_bounds_a_stalled_pool_preflight_before_parent_creation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let state = test_state(&server);
        let trigger = state.shutdown.clone();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(move |_: &wiremock::Request| {
                trigger.cancel();
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(pool_json())
            })
            .mount(&server)
            .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                state,
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("shutdown must stop a stalled pool read");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE"))
        );
    }

    /// Once CREATE has returned a durable parent, shutdown cannot answer 503:
    /// the stalled status write could still commit. Hand the exact ID to the
    /// reaper as a non-retry 202 instead.
    #[tokio::test]
    async fn shutdown_during_stalled_post_create_checkpoint_returns_pending_handle() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let parent = mount_create_api(&server, true, false).await;
        let state = test_state(&server);
        let trigger = state.shutdown.clone();
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+/status$",
            ))
            .respond_with(move |_: &wiremock::Request| {
                trigger.cancel();
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(serde_json::json!({}))
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                state,
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("shutdown must hand off a durable admission promptly");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response_json(response).await;
        assert_eq!(body["status"], "admission_pending");
        assert_eq!(body["retry"], false);
        assert!(parent.lock().unwrap().is_some());
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method.as_str() != "DELETE"
                && !(request.method.as_str() == "POST"
                    && request.url.path().contains("coordination.k8s.io"))
        }));
    }

    /// The access gate is part of admission, so its CREATE shares the same
    /// absolute deadline and shutdown handoff as every other post-parent stage.
    /// A lost gate response must not pin graceful shutdown or return a retryable
    /// 503 while the durable parent is still owned by the admission reaper.
    #[tokio::test]
    async fn shutdown_during_access_gate_create_returns_pending_handle() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let parent = mount_create_api(&server, true, false).await;
        let state = test_state(&server);
        let trigger = state.shutdown.clone();
        Mock::given(method("POST"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases",
            ))
            .respond_with(move |_: &wiremock::Request| {
                trigger.cancel();
                ResponseTemplate::new(201)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(serde_json::json!({}))
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                state,
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("shutdown must hand off a stalled access-gate CREATE");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response_json(response).await;
        assert_eq!(body["status"], "admission_pending");
        assert_eq!(body["retry"], false);
        assert!(parent.lock().unwrap().is_some());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path().contains("coordination.k8s.io")
                })
                .count(),
            1,
            "reservation admission must not start after gate handoff"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Cleanup after a malformed CREATE response shares the original absolute
    /// deadline. A stalled absence proof must not retain the HTTP task or begin
    /// reservation admission after that budget expires.
    #[tokio::test]
    async fn admission_budget_bounds_stalled_post_create_cleanup() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let parent = mount_create_api(&server, true, false).await;
        let create_parent = Arc::clone(&parent);
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let mut object: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let name = object["metadata"]["name"].as_str().unwrap().to_string();
                object["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
                object["metadata"]["resourceVersion"] = serde_json::json!("1");
                *create_parent.lock().unwrap() = Some(object.clone());
                ResponseTemplate::new(201).set_body_json(object)
            })
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(serde_json::json!({})),
            )
            .with_priority(1)
            .mount(&server)
            .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            create_sandbox_lease_until::<crate::testutil::MockBackend>(
                test_state(&server),
                identity(),
                CreateSandboxLeaseRequest {
                    pool: "agent-small".into(),
                    ttl: Some("1h".into()),
                    alias: None,
                },
                tokio::time::Instant::now() + std::time::Duration::from_millis(200),
            ),
        )
        .await
        .expect("the original deadline must bound malformed-parent cleanup");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(parent.lock().unwrap().is_some());
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method.as_str() != "DELETE"
                && !(request.method.as_str() == "POST"
                    && request.url.path().contains("coordination.k8s.io"))
        }));
    }

    /// A lease that reached `phase`, carrying the `CleanupVerified` condition
    /// the controller writes at that same transition — which is the only thing
    /// dating the end of the lease.
    fn terminal_lease_json(
        name: &str,
        phase: &str,
        cleanup: crate::crd::SandboxConditionStatus,
        terminal_since: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        let mut object = lease_json(name, "alice@example.com", phase);
        object["status"]["conditions"] = serde_json::json!([{
            "type": crate::controllers::sandbox::CLEANUP_VERIFIED_CONDITION,
            "status": cleanup,
            "reason": "TeardownVerified",
            "message": "Lease-owned footprint observed absent",
            "lastTransitionTime": terminal_since.to_rfc3339(),
        }]);
        object
    }

    /// Mount the SandboxLease API for one sweep tick.
    ///
    /// `listed` is what LIST returns; `current` is what a subsequent GET on the
    /// same name returns. They are separate on purpose — the sweep re-reads
    /// before deleting, and a mock that could not disagree with itself could
    /// never show that the re-read decides anything.
    async fn mount_lease_sweep_api(
        server: &MockServer,
        listed: &[serde_json::Value],
        current: &[serde_json::Value],
    ) {
        const LEASES: &str = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases";
        Mock::given(method("GET"))
            .and(path(LEASES))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(listed.to_vec())),
            )
            .mount(server)
            .await;
        for object in current {
            let name = object["metadata"]["name"].as_str().unwrap().to_string();
            Mock::given(method("GET"))
                .and(path(format!("{LEASES}/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(object.clone()))
                .mount(server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{LEASES}/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success"
                })))
                .mount(server)
                .await;
        }
    }

    /// Every lease name the sweep issued a DELETE for.
    async fn deleted_lease_names(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .filter_map(|request| {
                request
                    .url
                    .path()
                    .split("/sandboxleases/")
                    .nth(1)
                    .map(str::to_string)
            })
            .collect()
    }

    /// `Quarantined` is terminal, and is the one terminal phase the sweep must
    /// never touch.
    ///
    /// If it did, the capacity that phase withholds — withheld precisely
    /// because nobody could prove the Sandbox was gone — would be handed back
    /// on no evidence at all, and the record of the unproven teardown would go
    /// with it. That is the exact double-booking the quarantine exists to
    /// prevent, now with nothing left to explain where the slot went.
    ///
    /// Asserted at the sweep rather than at the predicate: the predicate is
    /// only where the rule is written, and the sweep is where a DELETE
    /// actually goes out.
    ///
    /// Two quarantined leases, because one is not enough to constrain the
    /// rule. The `False` cleanup condition is the shape a real quarantine
    /// carries, and it is spared twice over — by the phase *and* by having no
    /// verified end date. A test built only from that shape passes even with
    /// the phase exemption deleted, which is the mutation this is here to
    /// catch. The second lease carries a `True` condition dated a year back,
    /// so the phase is the only thing left that can save it.
    #[tokio::test]
    async fn quarantined_leases_are_never_swept() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let now = chrono::Utc::now();
        let long_ago = now - chrono::Duration::days(365);

        let objects = vec![
            terminal_lease_json(
                "sandbox-released",
                "Released",
                crate::crd::SandboxConditionStatus::True,
                long_ago,
            ),
            terminal_lease_json(
                "sandbox-quarantined",
                "Quarantined",
                crate::crd::SandboxConditionStatus::False,
                long_ago,
            ),
            terminal_lease_json(
                "sandbox-quarantined-dated",
                "Quarantined",
                crate::crd::SandboxConditionStatus::True,
                long_ago,
            ),
        ];
        mount_lease_sweep_api(&server, &objects, &objects).await;

        let leases: Api<SandboxLease> =
            Api::namespaced(crate::testutil::mock_k8s_client(&server), "test-ns");
        sweep_retired_leases(&leases, chrono::Duration::days(7), now).await;

        assert_eq!(
            deleted_lease_names(&server).await,
            vec!["sandbox-released".to_string()],
            "the sweep must retire the clean terminal lease and leave the quarantined one"
        );
    }

    /// The sweep decides on the object as it stands when the DELETE is sent,
    /// not as it stood when it was listed.
    ///
    /// Teardown verification is asynchronous, so a lease can be quarantined in
    /// the gap between the two. Acting on the listed copy would delete the one
    /// record that must never be deleted, and the resourceVersion precondition
    /// would not save it: the controller writes status, so the version the
    /// sweep fences on is the quarantined one.
    ///
    /// The re-read object keeps a `True` cleanup condition dated a year back,
    /// so the phase it was re-read *as* is the only thing that can stop the
    /// delete — otherwise this would pass without the re-read deciding
    /// anything.
    #[tokio::test]
    async fn a_lease_quarantined_after_the_list_is_left_alone() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let now = chrono::Utc::now();
        let long_ago = now - chrono::Duration::days(365);

        let listed = terminal_lease_json(
            "sandbox-reopened",
            "Released",
            crate::crd::SandboxConditionStatus::True,
            long_ago,
        );
        let requeried = terminal_lease_json(
            "sandbox-reopened",
            "Quarantined",
            crate::crd::SandboxConditionStatus::True,
            long_ago,
        );
        mount_lease_sweep_api(&server, &[listed], &[requeried]).await;

        let leases: Api<SandboxLease> =
            Api::namespaced(crate::testutil::mock_k8s_client(&server), "test-ns");
        sweep_retired_leases(&leases, chrono::Duration::days(7), now).await;

        assert!(
            deleted_lease_names(&server).await.is_empty(),
            "a lease quarantined since the list must survive the sweep"
        );
    }

    /// The window is the whole promise the retention policy makes, and every
    /// phase that is not a *clean* terminal one is outside the sweep entirely.
    ///
    /// Sweeping a live lease would delete a running Sandbox's record; sweeping
    /// a fresh terminal one would destroy the audit trail at the moment it is
    /// most likely to be read — right after whatever went wrong.
    #[test]
    fn only_clean_terminal_leases_past_the_window_are_retired() {
        let now = chrono::Utc::now();
        let retention = chrono::Duration::days(7);
        let overdue = (now - retention - chrono::Duration::hours(1)).to_rfc3339();
        let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
        let retired =
            |phase, since: &str| terminal_lease_is_retired(phase, Some(since), now, retention);

        for phase in [SandboxLeasePhase::Released, SandboxLeasePhase::Expired] {
            assert!(
                retired(phase, &overdue),
                "{phase} past the window is retired"
            );
            assert!(
                !retired(phase, &recent),
                "{phase} inside the window is kept"
            );
        }

        // Terminal, and permanently exempt: a quarantine is not made safe to
        // delete by age. Nothing has proven the teardown in the meantime.
        assert!(!retired(SandboxLeasePhase::Quarantined, &overdue));

        // Not terminal at all. These leases may still be running, and their
        // age says nothing about whether they are.
        for phase in [
            SandboxLeasePhase::Pending,
            SandboxLeasePhase::Provisioning,
            SandboxLeasePhase::Ready,
            SandboxLeasePhase::Releasing,
        ] {
            assert!(!retired(phase, &overdue), "{phase} is not terminal");
        }

        // Absent or unreadable evidence of when it ended is not evidence that
        // it ended long enough ago.
        assert!(!terminal_lease_is_retired(
            SandboxLeasePhase::Released,
            None,
            now,
            retention
        ));
        assert!(!terminal_lease_is_retired(
            SandboxLeasePhase::Released,
            Some("not-a-timestamp"),
            now,
            retention
        ));
    }

    /// A lease is dated by when it *ended*, never by when it was created.
    ///
    /// The `False` form of `CleanupVerified` is written when teardown became
    /// unprovable, so reading it as an end date would date a quarantine — and
    /// a sweep that trusted `creationTimestamp` instead would retire a lease
    /// that ran for a fortnight the instant it was released.
    #[test]
    fn a_terminal_lease_is_dated_by_its_verified_cleanup() {
        let ended_at = "2026-08-01T00:00:00+00:00";
        let with_condition = |status| crate::crd::SandboxLeaseStatus {
            phase: SandboxLeasePhase::Released,
            conditions: vec![crate::crd::SandboxCondition {
                condition_type: crate::controllers::sandbox::CLEANUP_VERIFIED_CONDITION.into(),
                status,
                reason: "TeardownVerified".into(),
                message: String::new(),
                observed_generation: Some(1),
                last_transition_time: Some(ended_at.to_string()),
            }],
            ..Default::default()
        };

        assert_eq!(
            terminal_lease_recorded_at(&with_condition(crate::crd::SandboxConditionStatus::True)),
            Some(ended_at)
        );
        assert_eq!(
            terminal_lease_recorded_at(&with_condition(crate::crd::SandboxConditionStatus::False)),
            None
        );
        assert_eq!(
            terminal_lease_recorded_at(&crate::crd::SandboxLeaseStatus::default()),
            None
        );
    }

    /// A retention setting nobody can act on must not become a short one.
    ///
    /// Every rejection here is a value an operator typed. Falling back to zero
    /// — or honouring `7s` from a dropped `2`, or `1y` from a stray keystroke —
    /// would delete audit records wholesale on a typo, with a successful
    /// startup and no error anywhere to say why they went.
    #[test]
    fn an_unusable_retention_setting_never_shortens_the_window() {
        let default = parse_duration(DEFAULT_SANDBOX_LEASE_RETENTION).unwrap();
        assert_eq!(default, chrono::Duration::days(7));

        // Unset, blank, unparseable, and past the one-year ceiling all mean
        // "no usable instruction", which is the default and not zero.
        for unusable in [
            None,
            Some(""),
            Some("   "),
            Some("7"),
            Some("7d"),
            Some("forever"),
            Some("9000h"),
        ] {
            assert_eq!(
                sandbox_lease_retention(unusable),
                default,
                "{unusable:?} must fall back to the default"
            );
        }

        // Honoured as written.
        assert_eq!(
            sandbox_lease_retention(Some("720h")),
            chrono::Duration::days(30)
        );
        assert_eq!(
            sandbox_lease_retention(Some(" 24h ")),
            chrono::Duration::days(1)
        );

        // Clamped, not honoured: below the floor is a typo, not a policy.
        let floor = chrono::Duration::seconds(MIN_SANDBOX_LEASE_RETENTION_SECS);
        assert_eq!(sandbox_lease_retention(Some("7s")), floor);
        assert_eq!(sandbox_lease_retention(Some("59m")), floor);
        assert_eq!(sandbox_lease_retention(Some("1h")), floor);
    }

    /// Quota is decided by CREATE contention on a per-slot name, not by
    /// counting. With every slot pre-held, admission must refuse, and must not
    /// leave the caller's pending lease behind.
    #[tokio::test]
    async fn create_refuses_when_every_quota_slot_is_held() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        // The policy in `identity()` allows 2 concurrent Sandbox leases.
        let preheld: Vec<String> = (0..2)
            .map(|slot| quota_reservation_name(&principal, slot))
            .collect();
        mount_reservation_api(&server, &preheld).await;
        mount_create_lease_only(&server).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method.as_str() == "DELETE"
                    && request.url.path().contains("/sandboxleases/")),
            "the unadmitted lease must be removed when its quota reservation fails"
        );
    }

    /// An alias already held by another live lease is a conflict, and it must be
    /// detected without burning one of the caller's quota slots.
    #[tokio::test]
    async fn create_refuses_a_taken_alias_without_consuming_a_quota_slot() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        let held =
            mount_reservation_api(&server, &[alias_reservation_name(&principal, "review")]).await;
        mount_create_lease_only(&server).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: Some("review".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let remaining = held.lock().unwrap().clone();
        assert_eq!(
            remaining.len(),
            1,
            "only the pre-existing alias should remain; no quota slot may be consumed: {remaining:?}"
        );
        assert!(remaining.contains_key(&alias_reservation_name(&principal, "review")));
    }

    /// The happy path must take exactly one access gate, one quota slot, and
    /// one alias, so a caller's second lease cannot silently reuse the first
    /// lease's capacity or teardown barrier.
    #[tokio::test]
    async fn create_acquires_exactly_one_quota_slot_and_one_alias() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let held = mount_reservation_api(&server, &[]).await;
        let lease_state = mount_create_lease_only(&server).await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: Some("review".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let principal = principal_hash(&identity());
        let remaining = held.lock().unwrap().clone();
        assert_eq!(
            remaining.len(),
            3,
            "expected one gate + one slot + one alias: {remaining:?}"
        );
        assert!(remaining.contains_key(&quota_reservation_name(&principal, 0)));
        assert!(remaining.contains_key(&alias_reservation_name(&principal, "review")));
        assert_eq!(
            remaining
                .values()
                .filter(|object| {
                    object["metadata"]["labels"]["kobe.kunobi.ninja/sandbox-access-kind"]
                        == "lease-gate"
                })
                .count(),
            1
        );

        let admitted: SandboxLease =
            serde_json::from_value(lease_state.lock().unwrap().clone().expect("admitted lease"))
                .unwrap();
        let access_gate = crate::sandbox_access_ledger::persisted_gate_reference(&admitted)
            .expect("admission persists the exact access gate");
        assert_eq!(
            remaining[&access_gate.name]["metadata"]["uid"].as_str(),
            Some(access_gate.uid.as_str())
        );
        let provenance = persisted_reservation_provenance(&admitted).unwrap();
        assert_eq!(provenance.len(), 2);
        for reservation in provenance {
            let object = remaining
                .get(&reservation.name)
                .expect("persisted name exists in ledger");
            assert_eq!(
                object["metadata"]["uid"].as_str(),
                Some(reservation.uid.as_str()),
                "admission must atomically persist the exact UID returned by CREATE"
            );
        }
    }

    /// Releasing a reservation must delete OUR object, never whatever now holds
    /// that name.
    ///
    /// The names are deterministic and reused: once a slot is freed, the next
    /// request takes the identical name. If a release ever runs against a stale
    /// record — the reservation was already reaped and recreated in between —
    /// deleting by bare name would silently free a *live* lease's slot, letting
    /// a third request over-admit against it.
    ///
    /// Hardening the mock to honour UID preconditions was necessary but not
    /// sufficient: without this test nothing reached that code path, so removing
    /// the precondition from the production release still passed the suite.
    #[tokio::test]
    async fn releasing_a_stale_record_leaves_the_current_owner_alone() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let contested = quota_reservation_name(&principal, 0);
        // The name is currently held by a DIFFERENT lease than the one our
        // stale record remembers.
        let held = mount_reservation_api_owned(
            &server,
            &[(contested.clone(), "current-owner-lease-uid".to_string())],
        )
        .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let stale = AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name: contested.clone(),
            uid: "a-previous-reservation-uid".into(),
        };

        release_admission_reservations(&reservations, std::slice::from_ref(&stale))
            .await
            .expect("a stale record is not an error — ours is simply already gone");

        assert!(
            held.lock().unwrap().contains_key(&contested),
            "the current owner's reservation must survive a stale release"
        );
    }

    /// An accepted reservation DELETE is not absence proof: a foreign
    /// finalizer may keep the exact UID alive and still consuming its slot.
    #[tokio::test]
    async fn reservation_delete_acceptance_never_masquerades_as_absence() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let name = quota_reservation_name(&principal_hash(&identity()), 0);
        let path_value =
            format!("/apis/coordination.k8s.io/v1/namespaces/sandbox-ledger/leases/{name}");
        let still_present = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": name.clone(),
                "namespace": TEST_LEDGER_NAMESPACE,
                "uid": "reservation-uid",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-08-20T00:00:00Z",
                "finalizers": ["foreign.example/hold"]
            }
        });
        Mock::given(method("DELETE"))
            .and(path(path_value.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(still_present.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(path_value))
            .respond_with(ResponseTemplate::new(200).set_body_json(still_present))
            .expect(1)
            .mount(&server)
            .await;

        let reservations: Api<Lease> = Api::namespaced(
            crate::testutil::mock_k8s_client(&server),
            TEST_LEDGER_NAMESPACE,
        );
        let held = AdmissionReservation {
            kind: SandboxReservationKind::Quota,
            name,
            uid: "reservation-uid".into(),
        };
        assert!(matches!(
            release_admission_reservations(&reservations, &[held]).await,
            Err(AdmissionReservationError::DeletionNotConfirmed)
        ));
    }

    async fn assert_active_pending_sweep_repairs(use_background_path: bool) {
        let server = MockServer::start().await;
        let name = if use_background_path {
            "sandbox-background-drift"
        } else {
            "sandbox-caller-drift"
        };
        let lease_uid = format!("{name}-uid");
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let held =
            mount_reservation_api_owned(&server, &[(reservation_name, lease_uid.clone())]).await;
        let mut object = active_release_json(name, Some(SANDBOX_ADMISSION_PENDING));
        object["metadata"]["creationTimestamp"] =
            serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339());
        if !use_background_path {
            object["status"]["phase"] = serde_json::json!("Provisioning");
            object["status"].as_object_mut().unwrap().remove("readyAt");
            object["status"]
                .as_object_mut()
                .unwrap()
                .remove("expiresAt");
        }
        let state = Arc::new(Mutex::new(object));

        let list_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(crate::testutil::k8s_list_response(vec![
                    list_state.lock().unwrap().clone(),
                ]))
            })
            .mount(&server)
            .await;

        let lease_path =
            format!("/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{name}");
        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(lease_path.clone()))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let operations = operations.as_array().unwrap();
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == lease_uid
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                assert!(!operations.iter().any(|operation| {
                    operation["value"] == SANDBOX_ADMISSION_CANCELLED
                }));
                let admission = operations
                    .iter()
                    .find(|operation| {
                        operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                    })
                    .unwrap()["value"]
                    .clone();
                let release = operations
                    .iter()
                    .find(|operation| {
                        operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-release-requested-at"
                    })
                    .unwrap()["value"]
                    .clone();
                let mut object = patch_state.lock().unwrap();
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] = admission;
                object["metadata"]["annotations"][SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION] =
                    release;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .expect(1)
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        if use_background_path {
            reap_expired_pending_admissions_once(&leases, &reservations, chrono::Utc::now()).await;
        } else {
            cancel_expired_pending_admissions(
                &leases,
                &reservations,
                &identity(),
                chrono::Utc::now(),
            )
            .await;
        }

        let repaired = state.lock().unwrap().clone();
        assert_eq!(
            repaired["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION],
            SANDBOX_ADMISSION_ADMITTED
        );
        assert!(
            repaired["metadata"]["annotations"]
                .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
                .is_some()
        );
        assert_eq!(held.lock().unwrap().len(), 1);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| {
                    request.method.as_str() != "DELETE"
                        && !(request.url.path() == lease_path
                            && request
                                .body
                                .windows(SANDBOX_ADMISSION_CANCELLED.len())
                                .any(|window| window == SANDBOX_ADMISSION_CANCELLED.as_bytes()))
                })
        );
    }

    /// The replica-wide sweep repairs Ready lifecycle drift and requests
    /// teardown; it never reclassifies that active object as abandoned.
    #[tokio::test]
    async fn background_reaper_repairs_active_pending_drift_before_cancellation() {
        assert_active_pending_sweep_repairs(true).await;
    }

    /// The caller-side recovery sweep applies the same lifecycle classifier to
    /// Provisioning objects before considering its cancellation CAS.
    #[tokio::test]
    async fn caller_sweep_repairs_active_pending_drift_before_cancellation() {
        assert_active_pending_sweep_repairs(false).await;
    }

    /// Active status without committed exact provenance is ambiguity, not
    /// cancellation authority. Both the parent and live ledger stay untouched.
    #[tokio::test]
    async fn active_pending_drift_without_exact_provenance_fails_closed() {
        let server = MockServer::start().await;
        let name = "sandbox-ambiguous-drift";
        let lease_uid = format!("{name}-uid");
        let reservation_name = quota_reservation_name(&principal_hash(&identity()), 0);
        let held = mount_reservation_api_owned(&server, &[(reservation_name, lease_uid)]).await;
        let ledger_before = held.lock().unwrap().clone();
        let mut object = active_release_json(name, Some(SANDBOX_ADMISSION_PENDING));
        object["metadata"]["creationTimestamp"] =
            serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339());
        object["metadata"]["annotations"]
            .as_object_mut()
            .unwrap()
            .remove(SANDBOX_RESERVATIONS_ANNOTATION);
        let parent_before = object.clone();
        let list_object = object.clone();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![list_object])),
            )
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        cancel_expired_pending_admissions(&leases, &reservations, &identity(), chrono::Utc::now())
            .await;

        assert_eq!(*held.lock().unwrap(), ledger_before);
        assert_eq!(object, parent_before);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| { !matches!(request.method.as_str(), "PATCH" | "DELETE") })
        );
    }

    /// The durable reaper must reclaim a stranded lease belonging to a
    /// principal who never comes back.
    ///
    /// The create-path sweep only helps a caller who retries. This is the case
    /// it cannot cover: the request died mid-admission and nobody returns, so
    /// the quota slot and alias stay consumed with no controller willing to
    /// touch the `pending` lease.
    ///
    /// Driving the whole background loop would mean waiting on its interval, so
    /// this exercises the same decision and the same fenced deletion the loop
    /// performs per lease.
    #[tokio::test]
    async fn the_reaper_reclaims_a_lease_whose_principal_never_returns() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        let stranded_uid = "sandbox-orphan-uid";

        let held = mount_reservation_api_owned(
            &server,
            &[(
                quota_reservation_name(&principal, 0),
                stranded_uid.to_string(),
            )],
        )
        .await;

        let abandoned = {
            let mut object = lease_json("sandbox-orphan", "alice@example.com", "Pending");
            object["metadata"]["uid"] = serde_json::json!(stranded_uid);
            object["metadata"]["creationTimestamp"] =
                serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339());
            object["metadata"]["annotations"] = serde_json::json!({
                SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
            });
            object["status"] = serde_json::json!({ "phase": "Pending" });
            object
        };
        let abandoned_state = Arc::new(Mutex::new(Some(abandoned.clone())));
        let get_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-orphan",
            ))
            .respond_with(move |_: &wiremock::Request| {
                match get_abandoned_state.lock().unwrap().clone() {
                    Some(object) => ResponseTemplate::new(200).set_body_json(object),
                    None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    })),
                }
            })
            .mount(&server)
            .await;
        let cancel_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-orphan",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("cancellation JSON Patch");
                let operations = operations.as_array().expect("JSON Patch operations");
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == stranded_uid
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                        && operation["value"] == SANDBOX_ADMISSION_PENDING
                }));
                let mut guard = cancel_abandoned_state.lock().unwrap();
                let object = guard.as_mut().expect("lease is still present");
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                    serde_json::json!(SANDBOX_ADMISSION_CANCELLED);
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let delete_abandoned_state = Arc::clone(&abandoned_state);
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-orphan",
            ))
            .respond_with(move |_: &wiremock::Request| {
                *delete_abandoned_state.lock().unwrap() = None;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success"
                }))
            })
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let lease: SandboxLease = serde_json::from_value(abandoned).unwrap();

        // Age only authorizes cancellation. The exact CAS must commit before
        // the reaper is allowed to delete the object and free its slot.
        assert!(pending_admission_cancellation_due(
            lease
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|timestamp| timestamp.0.to_string())
                .as_deref(),
            chrono::Utc::now()
        ));
        assert!(matches!(
            cancel_and_reap_pending_admission(&leases, &reservations, &lease).await,
            Ok(PendingAdmissionCancellation::Cancelled(_))
        ));

        let remaining = held.lock().unwrap().clone();
        assert!(
            remaining.is_empty(),
            "the stranded principal's quota must be released even though they never retried:              {remaining:?}"
        );
    }

    /// Both mutating calls can commit and lose their responses. Cleanup must
    /// recover from the exact re-read, but quota still cannot move until the
    /// post-DELETE GET proves 404.
    #[tokio::test]
    async fn pending_cleanup_recovers_lost_responses_and_releases_only_after_404() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let lease_uid = "sandbox-fenced-uid";
        let held = mount_reservation_api_owned(
            &server,
            &[(quota_reservation_name(&principal, 0), lease_uid.into())],
        )
        .await;

        let mut object = lease_json("sandbox-fenced", "alice@example.com", "Pending");
        object["metadata"]["uid"] = serde_json::json!(lease_uid);
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({ "phase": "Pending" });
        object["metadata"]["finalizers"] = serde_json::json!([SANDBOX_LEASE_FINALIZER]);
        let state = Arc::new(Mutex::new(Some(object.clone())));

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-fenced",
            ))
            .respond_with(
                move |_: &wiremock::Request| match get_state.lock().unwrap().clone() {
                    Some(object) => ResponseTemplate::new(200).set_body_json(object),
                    None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    })),
                },
            )
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-fenced",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let finalizers = operations
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|operation| operation["path"] == "/metadata/finalizers")
                    .unwrap()["value"]
                    .clone();
                let mut guard = patch_state.lock().unwrap();
                let object = guard.as_mut().unwrap();
                object["metadata"]["finalizers"] = finalizers;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "InternalError", "code": 500
                }))
            })
            .mount(&server)
            .await;

        let delete_state = Arc::clone(&state);
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-fenced",
            ))
            .respond_with(move |_: &wiremock::Request| {
                *delete_state.lock().unwrap() = None;
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "InternalError", "code": 500
                }))
            })
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let lease: SandboxLease = serde_json::from_value(object).unwrap();
        delete_exact_pending_lease(&leases, &reservations, &lease)
            .await
            .expect("exact 404 proof makes both lost responses recoverable");
        assert!(held.lock().unwrap().is_empty());

        let requests = server.received_requests().await.unwrap();
        let finalizer_patch = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "PATCH"
                    && request
                        .url
                        .path()
                        .ends_with("/sandboxleases/sandbox-fenced")
            })
            .unwrap();
        let operations: serde_json::Value = serde_json::from_slice(&finalizer_patch.body).unwrap();
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/uid"
                && operation["value"] == lease_uid
        }));
        assert!(operations.as_array().unwrap().iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "1"
        }));
        let sandbox_delete = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "DELETE"
                    && request
                        .url
                        .path()
                        .ends_with("/sandboxleases/sandbox-fenced")
            })
            .unwrap();
        let delete_options: serde_json::Value =
            serde_json::from_slice(&requests[sandbox_delete].body).unwrap();
        assert_eq!(delete_options["preconditions"]["uid"], lease_uid);
        assert_eq!(delete_options["preconditions"]["resourceVersion"], "2");
        let absence_get = requests
            .iter()
            .enumerate()
            .skip(sandbox_delete + 1)
            .find(|(_, request)| {
                request.method.as_str() == "GET"
                    && request
                        .url
                        .path()
                        .ends_with("/sandboxleases/sandbox-fenced")
            })
            .map(|(index, _)| index)
            .unwrap();
        let reservation_delete = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "DELETE"
                    && request.url.path().contains("coordination.k8s.io")
            })
            .unwrap();
        assert!(sandbox_delete < absence_get && absence_get < reservation_delete);
    }

    /// Kobe may remove only its own finalizer. If a foreign controller still
    /// holds the object, DELETE acceptance is not absence and quota stays held.
    #[tokio::test]
    async fn pending_cleanup_preserves_foreign_finalizers_and_quota() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let lease_uid = "sandbox-foreign-uid";
        let held = mount_reservation_api_owned(
            &server,
            &[(quota_reservation_name(&principal, 0), lease_uid.into())],
        )
        .await;

        let mut object = lease_json("sandbox-foreign", "alice@example.com", "Pending");
        object["metadata"]["uid"] = serde_json::json!(lease_uid);
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({ "phase": "Pending" });
        object["metadata"]["finalizers"] =
            serde_json::json!(["foreign.example/cleanup", SANDBOX_LEASE_FINALIZER]);
        let state = Arc::new(Mutex::new(object.clone()));

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-foreign",
            ))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-foreign",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let finalizers = operations
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|operation| operation["path"] == "/metadata/finalizers")
                    .unwrap()["value"]
                    .clone();
                let mut object = patch_state.lock().unwrap();
                object["metadata"]["finalizers"] = finalizers;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-foreign",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Success", "code": 200
            })))
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let lease: SandboxLease = serde_json::from_value(object).unwrap();
        assert!(matches!(
            delete_exact_pending_lease(&leases, &reservations, &lease).await,
            Err(SandboxLeaseMutationError::DeletionNotConfirmed)
        ));
        assert_eq!(
            state.lock().unwrap()["metadata"]["finalizers"],
            serde_json::json!(["foreign.example/cleanup"])
        );
        assert_eq!(held.lock().unwrap().len(), 1);
    }

    /// A same-named replacement is not the 404 proof for the deleted UID. Its
    /// presence must stop explicit reservation release even though selectors
    /// and UID preconditions would otherwise make that release look harmless.
    #[tokio::test]
    async fn pending_cleanup_does_not_release_on_name_reuse() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let lease_uid = "sandbox-old-uid";
        let held = mount_reservation_api_owned(
            &server,
            &[(quota_reservation_name(&principal, 0), lease_uid.into())],
        )
        .await;

        let mut object = lease_json("sandbox-reused", "alice@example.com", "Pending");
        object["metadata"]["uid"] = serde_json::json!(lease_uid);
        object["metadata"]["annotations"] = serde_json::json!({
            SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
        });
        object["status"] = serde_json::json!({ "phase": "Pending" });
        object["metadata"]["finalizers"] = serde_json::json!([SANDBOX_LEASE_FINALIZER]);
        let state = Arc::new(Mutex::new(object.clone()));

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-reused",
            ))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-reused",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let finalizers = operations
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|operation| operation["path"] == "/metadata/finalizers")
                    .unwrap()["value"]
                    .clone();
                let mut object = patch_state.lock().unwrap();
                object["metadata"]["finalizers"] = finalizers;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .mount(&server)
            .await;

        let delete_state = Arc::clone(&state);
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-reused",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut replacement = delete_state.lock().unwrap().clone();
                replacement["metadata"]["uid"] = serde_json::json!("sandbox-replacement-uid");
                replacement["metadata"]["resourceVersion"] = serde_json::json!("1");
                replacement["metadata"]["finalizers"] =
                    serde_json::json!([SANDBOX_LEASE_FINALIZER]);
                *delete_state.lock().unwrap() = replacement;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success", "code": 200
                }))
            })
            .mount(&server)
            .await;

        let client = crate::testutil::mock_k8s_client(&server);
        let leases: Api<SandboxLease> = Api::namespaced(client.clone(), "test-ns");
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);
        let lease: SandboxLease = serde_json::from_value(object).unwrap();
        assert!(matches!(
            delete_exact_pending_lease(&leases, &reservations, &lease).await,
            Err(SandboxLeaseMutationError::UidChanged)
        ));
        assert_eq!(held.lock().unwrap().len(), 1);
    }

    /// Admission landing in the final cleanup window must not become a 503.
    ///
    /// The race, from the review that found it: the PATCH commits, but the
    /// response is lost; `admit_sandbox_lease` re-reads and still sees
    /// `pending` (the write has not surfaced yet); its fenced DELETE then 409s
    /// against the now-landed patch; so it returns a *Kubernetes* error rather
    /// than `AdmissionNotCommitted`. The old code returned 503 for that with no
    /// further checking — while an admitted, placeable lease existed. The
    /// caller retries and ends up with TWO sandboxes for one request.
    ///
    /// The first three reads keep internal admission cleanup pending. The old
    /// outer one-off read is also pending; admission becomes visible only on
    /// the GET that its final best-effort cleanup performs. That cleanup error
    /// used to be ignored before returning 503. Routing the entire ambiguous
    /// tail through the arbiter makes its next read observe `admitted` instead.
    /// The parameter also exercises a committed lease whose exact access-gate
    /// annotation was stripped: it must return a durable handle for quarantine
    /// instead of inviting a duplicate create.
    async fn assert_late_admission_returns_durable_handle(include_exact_gate: bool) {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let ledger = mount_reservation_api(&server, &[]).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool_json()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        let created_state = Arc::new(Mutex::new(None::<serde_json::Value>));
        let create_state = Arc::clone(&created_state);
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let mut object: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let name = object["metadata"]["name"].as_str().unwrap().to_string();
                object["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
                object["metadata"]["resourceVersion"] = serde_json::json!("1");
                object["metadata"]["creationTimestamp"] = serde_json::json!("2026-08-12T00:00:00Z");
                *create_state.lock().unwrap() = Some(object.clone());
                ResponseTemplate::new(201).set_body_json(object)
            })
            .mount(&server)
            .await;

        let deadline_state = Arc::clone(&created_state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+/status$",
            ))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("deadline JSON Patch");
                let status = operations
                    .as_array()
                    .and_then(|operations| {
                        operations.iter().find_map(|operation| {
                            (operation["op"] == "add" && operation["path"] == "/status")
                                .then(|| operation["value"].clone())
                        })
                    })
                    .expect("deadline status operation");
                let mut guard = deadline_state.lock().unwrap();
                let object = guard.as_mut().expect("created lease");
                object["status"] = status;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .mount(&server)
            .await;

        // The PATCH "fails" from the client's point of view.
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 500
            })))
            .mount(&server)
            .await;

        // Reads 1-3 are admit's internal cleanup; read 4 is the outer
        // resolution attempt. The write becomes visible only in the exact
        // final-cleanup window that previously ended in an ambiguous 503.
        let reads = Arc::new(Mutex::new(0u32));
        let get_state = Arc::clone(&created_state);
        let get_reads = Arc::clone(&reads);
        let get_ledger = Arc::clone(&ledger);
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut object = get_state.lock().unwrap().clone().unwrap();
                let mut seen = get_reads.lock().unwrap();
                *seen += 1;
                object["metadata"]["annotations"] = if *seen < 5 {
                    serde_json::json!({
                        SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_PENDING
                    })
                } else {
                    let principal = principal_hash(&identity());
                    let name = quota_reservation_name(&principal, 0);
                    let provenance = serde_json::to_string(&vec![AdmissionReservation {
                        kind: SandboxReservationKind::Quota,
                        uid: format!("{name}-uid"),
                        name,
                    }])
                    .unwrap();
                    let gate = get_ledger
                        .lock()
                        .unwrap()
                        .values()
                        .find(|object| {
                            object["metadata"]["labels"]
                                ["kobe.kunobi.ninja/sandbox-access-kind"]
                                == "lease-gate"
                        })
                        .cloned()
                        .expect("prepared access gate");
                    let gate_provenance = crate::sandbox_access_ledger::encode_gate_reference(
                        &crate::sandbox_access_ledger::AccessGateReference {
                            name: gate["metadata"]["name"].as_str().unwrap().into(),
                            uid: gate["metadata"]["uid"].as_str().unwrap().into(),
                        },
                    )
                    .unwrap();
                    let mut annotations = serde_json::json!({
                        SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_ADMITTED,
                        SANDBOX_RESERVATIONS_ANNOTATION: provenance
                    });
                    if include_exact_gate {
                        annotations[crate::sandbox_access_ledger::ACCESS_GATE_ANNOTATION] =
                            serde_json::json!(gate_provenance);
                    }
                    annotations
                };
                ResponseTemplate::new(200).set_body_json(object)
            })
            .mount(&server)
            .await;

        // The fenced DELETE loses to the late-landing patch.
        Mock::given(method("DELETE"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "Conflict", "code": 409
            })))
            .mount(&server)
            .await;

        let response = create_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Json(CreateSandboxLeaseRequest {
                pool: "agent-small".into(),
                ttl: Some("1h".into()),
                alias: None,
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "an admitted lease must return its durable handle; a 503 here makes \
             the caller retry and create a second sandbox"
        );
        assert!(
            body["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("sandbox-"))
        );
        assert_eq!(body["phase"], "Pending");
        assert!(
            *reads.lock().unwrap() >= 5,
            "the regression must reach the final-cleanup visibility window"
        );
    }

    #[tokio::test]
    async fn an_admission_that_lands_late_is_not_reported_as_failure() {
        assert_late_admission_returns_durable_handle(true).await;
    }

    /// A lost response may surface an `admitted` object whose gate annotation
    /// was stripped by mutation. It is not placement authority, but it is still
    /// a committed lease: return its 202 handle so the controller can
    /// quarantine it without inviting a duplicate create.
    #[tokio::test]
    async fn admitted_without_the_exact_gate_returns_a_non_retry_handoff() {
        assert_late_admission_returns_durable_handle(false).await;
    }

    /// A lease with a corrupted admission annotation must stay deletable.
    ///
    /// The release handler routes everything not-`admitted` to the delete path,
    /// which used to demand the annotation read exactly `pending`. So a lease
    /// whose annotation went missing or unrecognised could not be removed
    /// through the API at all — it 503'd forever, holding its principal's quota
    /// with no operator recourse short of editing etcd.
    ///
    /// Relaxing this must NOT weaken the real invariant: an admitted lease is
    /// still refused, because deleting one here would drop a live sandbox's
    /// record while its workload runs.
    #[test]
    fn a_corrupted_annotation_stays_deletable_but_an_admitted_lease_does_not() {
        let base = sandbox_lease_from_json_with_admission(
            pristine_pending_json("sandbox-x", Some(SANDBOX_ADMISSION_PENDING)),
            SANDBOX_ADMISSION_PENDING,
        );

        // Normal case still works.
        assert!(validate_lease_shape_unadmitted(&base, &base).is_ok());

        // Corrupted / unrecognised annotation: deletable.
        let corrupted = sandbox_lease_from_json_with_admission(
            pristine_pending_json("sandbox-x", Some("garbage-value")),
            "garbage-value",
        );
        assert!(
            validate_lease_shape_unadmitted(&corrupted, &corrupted).is_ok(),
            "an unrecognised annotation is still unadmitted, so it must be removable"
        );

        // Admitted: still refused. This is the invariant the relaxation keeps.
        let admitted = sandbox_lease_from_json_with_admission(
            pristine_pending_json("sandbox-x", Some(SANDBOX_ADMISSION_ADMITTED)),
            SANDBOX_ADMISSION_ADMITTED,
        );
        assert!(
            matches!(
                validate_lease_shape_unadmitted(&admitted, &admitted),
                Err(SandboxLeaseMutationError::UnexpectedAdmissionState)
            ),
            "an admitted lease must never be removed by the unadmitted delete path"
        );
    }

    fn sandbox_lease_from_json_with_admission(
        mut object: serde_json::Value,
        admission: &str,
    ) -> SandboxLease {
        object["metadata"]["annotations"] =
            serde_json::json!({ SANDBOX_ADMISSION_ANNOTATION: admission });
        serde_json::from_value(object).expect("lease fixture must deserialize")
    }

    /// An object carrying our UID label but NOT our name shape must survive.
    ///
    /// The label is caller-supplied data. Anyone able to create a coordination
    /// Lease in this namespace could stamp a victim's SandboxLease UID onto an
    /// unrelated object and have Kobe's privileged credentials delete it during
    /// that victim's cleanup — a confused deputy. Only names derived from this
    /// lease's own principal may be deleted.
    #[test]
    fn only_names_derived_from_our_principal_may_be_deleted() {
        let principal = principal_hash(&identity());

        // Ours.
        assert_eq!(
            expected_reservation_kind(
                &quota_reservation_name(&principal, 0),
                &principal,
                Some("review")
            ),
            Some(SandboxReservationKind::Quota)
        );
        assert_eq!(
            expected_reservation_kind(
                &alias_reservation_name(&principal, "review"),
                &principal,
                Some("review")
            ),
            Some(SandboxReservationKind::Alias)
        );

        // An injected object that merely carries our label.
        assert!(
            expected_reservation_kind("important-system-lease", &principal, Some("review"))
                .is_none()
        );
        assert!(
            expected_reservation_kind("kube-controller-manager", &principal, Some("review"))
                .is_none()
        );

        // Another principal's reservations are not ours to release.
        let other = principal_hash(&AuthIdentity {
            identity: "mallory@example.com".into(),
            ..identity()
        });
        assert!(
            expected_reservation_kind(
                &quota_reservation_name(&other, 0),
                &principal,
                Some("review")
            )
            .is_none()
        );

        // Right prefix, wrong shape: a crafted suffix must not ride along.
        assert!(
            expected_reservation_kind(
                &format!("sbx-quota-{principal}-0-extra"),
                &principal,
                Some("review")
            )
            .is_none()
        );
        assert!(
            expected_reservation_kind(
                &format!("sbx-quota-{principal}-"),
                &principal,
                Some("review")
            )
            .is_none()
        );
        assert!(
            expected_reservation_kind(
                &format!("sbx-quota-{principal}-00"),
                &principal,
                Some("review")
            )
            .is_none()
        );
        assert!(
            expected_reservation_kind(
                &quota_reservation_name(&principal, MAX_SANDBOX_CONCURRENCY_SLOTS),
                &principal,
                Some("review")
            )
            .is_none()
        );
        assert!(
            expected_reservation_kind(
                &alias_reservation_name(&principal, "some-other-alias"),
                &principal,
                Some("review")
            )
            .is_none()
        );
    }

    /// One malformed selector result poisons the whole cleanup batch. This is
    /// the confused-deputy boundary: Kobe must not delete even a valid token
    /// until every object carrying the victim lease UID has proved its full
    /// server-minted shape.
    #[tokio::test]
    async fn malformed_reservation_prevents_every_delete() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let lease_uid = "sandbox-ledger-uid";
        let quota = quota_reservation_name(&principal, 0);
        let alias = alias_reservation_name(&principal, "review");
        let held = mount_reservation_api_owned(
            &server,
            &[
                (quota.clone(), lease_uid.into()),
                (alias.clone(), lease_uid.into()),
            ],
        )
        .await;
        held.lock().unwrap().get_mut(&alias).unwrap()["metadata"]["labels"]
            [SANDBOX_RESERVATION_TYPE_LABEL] = serde_json::json!(SANDBOX_RESERVATION_QUOTA);

        let mut object = lease_json("sandbox-ledger", "alice@example.com", "Releasing");
        object["spec"]["alias"] = serde_json::json!("review");
        object["metadata"]["annotations"][SANDBOX_RESERVATIONS_ANNOTATION] = serde_json::json!(
            serde_json::to_string(&vec![
                AdmissionReservation {
                    kind: SandboxReservationKind::Quota,
                    name: quota.clone(),
                    uid: format!("{quota}-uid"),
                },
                AdmissionReservation {
                    kind: SandboxReservationKind::Alias,
                    name: alias.clone(),
                    uid: format!("{alias}-uid"),
                },
            ])
            .unwrap()
        );
        let lease: SandboxLease = serde_json::from_value(object).unwrap();
        let client = crate::testutil::mock_k8s_client(&server);
        let reservations: Api<Lease> = Api::namespaced(client, TEST_LEDGER_NAMESPACE);

        assert!(matches!(
            release_reservations_for_lease(&reservations, &lease, lease_uid).await,
            Err(SandboxLeaseMutationError::ReservationShapeChanged { .. })
        ));
        assert_eq!(
            held.lock().unwrap().len(),
            2,
            "no valid reservation may be deleted from a malformed batch"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// The same token can hide from the UID-label LIST after label corruption;
    /// cleanup must GET its persisted name and refuse to treat it as absent.
    #[tokio::test]
    async fn same_uid_hidden_by_a_mutated_label_is_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let name = quota_reservation_name(&principal, 0);
        let lease_uid = "sandbox-ledger-uid";
        let held =
            mount_reservation_api_owned(&server, &[(name.clone(), lease_uid.to_string())]).await;
        held.lock().unwrap().get_mut(&name).unwrap()["metadata"]["labels"]
            [SANDBOX_RESERVATION_LEASE_UID_LABEL] = serde_json::json!("replacement-lease-uid");

        let lease: SandboxLease = serde_json::from_value(lease_json(
            "sandbox-ledger",
            "alice@example.com",
            "Releasing",
        ))
        .unwrap();
        let reservations: Api<Lease> = Api::namespaced(
            crate::testutil::mock_k8s_client(&server),
            TEST_LEDGER_NAMESPACE,
        );
        assert!(matches!(
            release_reservations_for_lease(&reservations, &lease, lease_uid).await,
            Err(SandboxLeaseMutationError::ReservationShapeChanged { .. })
        ));
        assert!(held.lock().unwrap().contains_key(&name));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Cleanup may delete one exact token before another DELETE fails. A later
    /// admission can then reuse the freed deterministic name; retry must leave
    /// that new UID alone and finish deleting only the old token still held.
    #[tokio::test]
    async fn partial_cleanup_retry_preserves_a_reacquired_reservation_name() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let principal = principal_hash(&identity());
        let lease_uid = "sandbox-ledger-uid";
        let quota = quota_reservation_name(&principal, 0);
        let alias = alias_reservation_name(&principal, "review");
        let held = mount_reservation_api_owned(
            &server,
            &[
                (quota.clone(), lease_uid.into()),
                (alias.clone(), lease_uid.into()),
            ],
        )
        .await;

        let quota_attempts = Arc::new(Mutex::new(0u32));
        let quota_attempt_state = Arc::clone(&quota_attempts);
        let quota_held = Arc::clone(&held);
        let quota_for_delete = quota.clone();
        let quota_path = format!(
            "/apis/coordination.k8s.io/v1/namespaces/{TEST_LEDGER_NAMESPACE}/leases/{quota}"
        );
        Mock::given(method("DELETE"))
            .and(path(quota_path))
            .respond_with(move |_: &wiremock::Request| {
                let mut attempts = quota_attempt_state.lock().unwrap();
                *attempts += 1;
                if *attempts == 1 {
                    ResponseTemplate::new(500).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "InternalError", "code": 500
                    }))
                } else {
                    quota_held.lock().unwrap().remove(&quota_for_delete);
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Success"
                    }))
                }
            })
            .with_priority(1)
            .mount(&server)
            .await;

        let mut object = lease_json("sandbox-ledger", "alice@example.com", "Releasing");
        object["spec"]["alias"] = serde_json::json!("review");
        object["metadata"]["annotations"][SANDBOX_RESERVATIONS_ANNOTATION] = serde_json::json!(
            serde_json::to_string(&vec![
                AdmissionReservation {
                    kind: SandboxReservationKind::Quota,
                    name: quota.clone(),
                    uid: format!("{quota}-uid"),
                },
                AdmissionReservation {
                    kind: SandboxReservationKind::Alias,
                    name: alias.clone(),
                    uid: format!("{alias}-uid"),
                },
            ])
            .unwrap()
        );
        let lease: SandboxLease = serde_json::from_value(object).unwrap();
        let reservations: Api<Lease> = Api::namespaced(
            crate::testutil::mock_k8s_client(&server),
            TEST_LEDGER_NAMESPACE,
        );

        assert!(matches!(
            release_reservations_for_lease(&reservations, &lease, lease_uid).await,
            Err(SandboxLeaseMutationError::Kubernetes(_))
        ));
        assert!(!held.lock().unwrap().contains_key(&alias));
        assert!(held.lock().unwrap().contains_key(&quota));

        held.lock().unwrap().insert(
            alias.clone(),
            serde_json::json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {
                    "name": alias,
                    "namespace": TEST_LEDGER_NAMESPACE,
                    "uid": "replacement-reservation-uid",
                    "labels": {
                        SANDBOX_RESERVATION_TYPE_LABEL: SANDBOX_RESERVATION_ALIAS,
                        SANDBOX_RESERVATION_LEASE_UID_LABEL: "replacement-lease-uid",
                        REQUESTER_HASH_LABEL: principal,
                    },
                    "annotations": {
                        SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION: "sandbox-later",
                    }
                },
                "spec": {}
            }),
        );

        release_reservations_for_lease(&reservations, &lease, lease_uid)
            .await
            .expect("retry removes only the remaining exact old reservation");
        let remaining = held.lock().unwrap();
        assert!(remaining.contains_key(&alias));
        assert!(!remaining.contains_key(&quota));
    }

    /// Every field used as deletion authority is immutable admission
    /// provenance, not advisory metadata.
    #[test]
    fn reservation_cleanup_requires_the_complete_minted_shape() {
        let mut lease_value = lease_json("sandbox-shape", "alice@example.com", "Releasing");
        lease_value["spec"]["alias"] = serde_json::json!("review");
        let lease: SandboxLease = serde_json::from_value(lease_value).unwrap();
        let principal = principal_hash(&identity());
        let mut reservation = build_admission_reservation(
            alias_reservation_name(&principal, "review"),
            SANDBOX_RESERVATION_ALIAS,
            &lease,
            &principal,
            "ledger-ns",
        )
        .unwrap();
        reservation.metadata.uid = Some("reservation-uid".into());
        assert_eq!(lease.namespace().as_deref(), Some("test-ns"));
        assert_eq!(reservation.namespace().as_deref(), Some("ledger-ns"));
        assert_eq!(
            validate_reservation_shape(
                &reservation,
                &lease,
                "sandbox-shape-uid",
                "ledger-ns",
                &principal,
            )
            .unwrap(),
            SandboxReservationKind::Alias
        );

        let base = serde_json::to_value(reservation).unwrap();
        let rejects = |value: serde_json::Value| {
            let changed: Lease = serde_json::from_value(value).unwrap();
            assert!(matches!(
                validate_reservation_shape(
                    &changed,
                    &lease,
                    "sandbox-shape-uid",
                    "ledger-ns",
                    &principal,
                ),
                Err(SandboxLeaseMutationError::ReservationShapeChanged { .. })
            ));
        };

        let mut changed = base.clone();
        changed["metadata"]["labels"][SANDBOX_RESERVATION_TYPE_LABEL] =
            serde_json::json!(SANDBOX_RESERVATION_QUOTA);
        rejects(changed);
        let mut changed = base.clone();
        changed["metadata"]["labels"][REQUESTER_HASH_LABEL] = serde_json::json!("foreign");
        rejects(changed);
        let mut changed = base.clone();
        changed["metadata"]["annotations"][SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION] =
            serde_json::json!("sandbox-other");
        rejects(changed);
        let mut changed = base.clone();
        changed["metadata"]["ownerReferences"] = serde_json::json!([{
            "apiVersion": "v1", "kind": "ConfigMap", "name": "foreign", "uid": "foreign"
        }]);
        rejects(changed);
        let mut changed = base.clone();
        changed["metadata"]["finalizers"] = serde_json::json!(["foreign.example/hold"]);
        rejects(changed);
        let mut changed = base.clone();
        changed["metadata"]["uid"] = serde_json::json!("");
        rejects(changed);
        let mut changed = base;
        changed["spec"]["holderIdentity"] = serde_json::json!("foreign");
        rejects(changed);
    }

    /// The fast LIST may reduce latency but cannot turn attacker-controlled
    /// labels into an authoritative 429.
    #[test]
    fn advisory_quota_counts_only_canonical_slots_inside_the_policy() {
        let lease: SandboxLease = serde_json::from_value(lease_json(
            "sandbox-advisory",
            "alice@example.com",
            "Pending",
        ))
        .unwrap();
        let principal = principal_hash(&identity());
        let valid = build_admission_reservation(
            quota_reservation_name(&principal, 0),
            SANDBOX_RESERVATION_QUOTA,
            &lease,
            &principal,
            "test-ns",
        )
        .unwrap();
        assert!(counts_toward_advisory_quota(&valid, &principal, 2));

        let mut arbitrary_name = valid.clone();
        arbitrary_name.metadata.name = Some("important-system-lease".into());
        assert!(!counts_toward_advisory_quota(
            &arbitrary_name,
            &principal,
            2
        ));

        let mut outside_policy = valid.clone();
        outside_policy.metadata.name = Some(quota_reservation_name(&principal, 200));
        assert!(!counts_toward_advisory_quota(
            &outside_policy,
            &principal,
            2
        ));

        let mut missing_owner = valid;
        missing_owner
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(SANDBOX_RESERVATION_LEASE_UID_LABEL);
        assert!(!counts_toward_advisory_quota(&missing_owner, &principal, 2));
    }

    /// The persisted-principal digest must agree with the live-identity one, or
    /// cleanup would compute names that never match what admission created.
    #[test]
    fn stored_and_live_principal_digests_agree() {
        let live = identity();
        let stored = SandboxPrincipal {
            provider: live.provider.clone(),
            requester_type: live.requester_type.clone(),
            issuer: live.issuer.clone(),
            identity: live.identity.clone(),
        };
        assert_eq!(principal_hash(&live), principal_hash_for(&stored));
    }

    /// Reservations are fenced to the lease UID, so a different principal's
    /// identical alias is a different reservation name and does not collide.
    #[test]
    fn reservation_names_are_scoped_per_principal() {
        let alice = principal_hash(&identity());
        let bob = principal_hash(&AuthIdentity {
            identity: "bob@example.com".into(),
            ..identity()
        });
        assert_ne!(alice, bob);
        assert_ne!(
            alias_reservation_name(&alice, "review"),
            alias_reservation_name(&bob, "review")
        );
        assert_ne!(
            quota_reservation_name(&alice, 0),
            quota_reservation_name(&bob, 0)
        );
    }

    /// Kubernetes GC must not release capacity ahead of Kobe's teardown proof
    /// when somebody foreground-deletes the owning SandboxLease.
    #[test]
    fn admission_reservations_are_not_garbage_collected_with_the_sandbox_lease() {
        let lease: SandboxLease =
            serde_json::from_value(lease_json("sandbox-owned", "alice@example.com", "Pending"))
                .unwrap();
        let principal = principal_hash(&identity());
        let reservation = build_admission_reservation(
            quota_reservation_name(&principal, 0),
            SANDBOX_RESERVATION_QUOTA,
            &lease,
            &principal,
            "test-ns",
        )
        .unwrap();

        assert!(reservation.metadata.owner_references.is_none());
        assert_eq!(
            reservation
                .labels()
                .get(SANDBOX_RESERVATION_LEASE_UID_LABEL)
                .map(String::as_str),
            Some("sandbox-owned-uid")
        );
    }

    #[tokio::test]
    async fn list_filters_exact_identity_after_hash_prefilter() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    lease_json("sandbox-own", "alice@example.com", "Ready"),
                    lease_json("sandbox-foreign", "mallory@example.com", "Ready"),
                ]),
            ))
            .mount(&server)
            .await;

        let response = list_sandbox_leases::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["id"], "sandbox-own");
        assert!(body[0].get("requester").is_none());
    }

    #[tokio::test]
    async fn foreign_get_and_release_are_indistinguishable_from_missing() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-foreign",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "sandbox-foreign",
                "mallory@example.com",
                "Ready",
            )))
            .mount(&server)
            .await;

        let get_response = get_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-foreign".into()),
        )
        .await;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let release_response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-foreign".into()),
        )
        .await;
        assert_eq!(release_response.status(), StatusCode::NOT_FOUND);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }

    /// A caller must not learn which cluster is hosting their Sandbox.
    ///
    /// They cannot connect to it, extend it or release it — but returning its
    /// name and UID would hand them the exact identifiers every cluster-lease
    /// endpoint is keyed on. "No authority" and "no authority, but knows
    /// precisely what to ask for" are not the same posture, and #74 requires
    /// the internal composition be undiscoverable, not merely unusable.
    #[test]
    fn the_internal_child_cluster_is_not_discoverable_through_the_sandbox_api() {
        let reference = |kind: &str, name: &str| crate::crd::SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: kind.into(),
            namespace: Some("kobe".into()),
            name: name.into(),
            uid: format!("{name}-uid"),
            generation: Some(1),
        };
        let target = SandboxTargetProvenance {
            namespace: "kobe".into(),
            child_cluster_lease: Some(reference("ClusterLease", "kobe-sbx-sbx-1")),
            child_cluster_instance: Some(reference("ClusterInstance", "kobe-abc123")),
            child_cluster_kubeconfig_secret: Some(crate::crd::SandboxObjectReference {
                api_version: "v1".into(),
                kind: "Secret".into(),
                namespace: Some("kobe".into()),
                name: "kobe-abc123-kubeconfig".into(),
                uid: "kubeconfig-secret-uid".into(),
                generation: None,
            }),
            child_cluster_kubeconfig_sha256: Some("a".repeat(64)),
            sandbox_template: Some(reference("SandboxTemplate", "kobe-agents")),
            sandbox_warm_pool: Some(reference("SandboxWarmPool", "kobe-agents")),
            sandbox_claim: Some(reference("SandboxClaim", "kobe-sbx-1")),
            sandbox: Some(reference("Sandbox", "sbx")),
            pod: Some(reference("Pod", "sbx-0")),
            service: Some(reference("Service", "sbx")),
        };

        let visible = caller_visible_provenance(target.clone());
        assert!(visible.child_cluster_lease.is_none());
        assert!(visible.child_cluster_instance.is_none());
        assert!(visible.child_cluster_kubeconfig_secret.is_none());
        assert!(visible.child_cluster_kubeconfig_sha256.is_none());

        // Nothing else is stripped: the Sandbox-side objects are the caller's
        // own, and #81 resolves targets against exactly these.
        assert_eq!(visible.sandbox_claim, target.sandbox_claim);
        assert_eq!(visible.pod, target.pod);
        assert_eq!(visible.service, target.service);
        assert_eq!(visible.namespace, target.namespace);

        // The serialized form is what actually reaches the caller, so assert on
        // it rather than on the struct alone — a field renamed into the wire
        // format later would pass a struct-level check and still leak.
        let json = serde_json::to_string(&visible).unwrap();
        for secret in [
            "kobe-sbx-sbx-1",
            "kobe-abc123",
            &"a".repeat(64),
            "ClusterLease",
            "ClusterInstance",
            "kobe-abc123-kubeconfig",
            "kubeconfig-secret-uid",
            "Secret",
        ] {
            assert!(!json.contains(secret), "{secret} leaked into {json}");
        }
    }

    /// A missing admission annotation does not strand a parent that has never
    /// accumulated any active-lifecycle authority.
    #[tokio::test]
    async fn missing_admission_on_pristine_pending_lease_is_deleted_safely() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let held = mount_reservation_api(&server, &[]).await;
        let object = pristine_pending_json("sandbox-pristine", None);
        let state = Arc::new(Mutex::new(Some(object)));
        let lease_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-pristine";

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(lease_path))
            .respond_with(move |_: &wiremock::Request| {
                get_state.lock().unwrap().clone().map_or_else(
                    || {
                        ResponseTemplate::new(404).set_body_json(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "code": 404
                        }))
                    },
                    |object| ResponseTemplate::new(200).set_body_json(object),
                )
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(lease_path))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let operations = operations.as_array().unwrap();
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == "sandbox-pristine-uid"
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                let finalizers = operations
                    .iter()
                    .find(|operation| operation["path"] == "/metadata/finalizers")
                    .unwrap()["value"]
                    .clone();
                let mut guard = patch_state.lock().unwrap();
                let object = guard.as_mut().unwrap();
                object["metadata"]["finalizers"] = finalizers;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(200).set_body_json(object.clone())
            })
            .expect(1)
            .mount(&server)
            .await;

        let delete_state = Arc::clone(&state);
        Mock::given(method("DELETE"))
            .and(path(lease_path))
            .respond_with(move |request: &wiremock::Request| {
                let options: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(options["preconditions"]["uid"], "sandbox-pristine-uid");
                assert_eq!(options["preconditions"]["resourceVersion"], "2");
                *delete_state.lock().unwrap() = None;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success", "code": 200
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-pristine".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.lock().unwrap().is_none());
        assert!(held.lock().unwrap().is_empty());

        let requests = server.received_requests().await.unwrap();
        let delete = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "DELETE" && request.url.path() == lease_path
            })
            .unwrap();
        assert!(requests.iter().skip(delete + 1).any(|request| {
            request.method.as_str() == "GET" && request.url.path() == lease_path
        }));
    }

    /// A formerly admitted Pending lease whose annotations were stripped is
    /// indistinguishable from pre-admission while a deterministic token
    /// survives. Even removing the mutable lease-UID label cannot hide that
    /// token from the full-ledger proof or authorize parent deletion.
    #[tokio::test]
    async fn stripped_admitted_pending_with_live_reservations_is_never_deleted() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let alias_reservation = alias_reservation_name(&principal, "review");
        let lease_uid = "sandbox-stripped-uid";
        let held = mount_reservation_api_owned(
            &server,
            &[
                (reservation_name, lease_uid.into()),
                (alias_reservation, lease_uid.into()),
            ],
        )
        .await;
        for token in held.lock().unwrap().values_mut() {
            token["metadata"]["labels"]
                .as_object_mut()
                .unwrap()
                .remove(SANDBOX_RESERVATION_LEASE_UID_LABEL);
        }
        let ledger_before = held.lock().unwrap().clone();
        let mut object = pristine_pending_json("sandbox-stripped", None);
        object["metadata"]["uid"] = serde_json::json!(lease_uid);
        object["spec"]["alias"] = serde_json::json!("review");
        let parent_before = object.clone();
        let lease_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stripped";
        Mock::given(method("GET"))
            .and(path(lease_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(object))
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-stripped".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(*held.lock().unwrap(), ledger_before);

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !(request.url.path() == lease_path
                && matches!(request.method.as_str(), "PATCH" | "DELETE")
                || request.url.path().contains("coordination.k8s.io")
                    && request.method.as_str() == "DELETE")
        }));
        assert_eq!(
            serde_json::from_value::<SandboxLease>(parent_before)
                .unwrap()
                .metadata
                .finalizers,
            Some(vec![SANDBOX_LEASE_FINALIZER.into()])
        );
    }

    /// A Ready object is never reinterpreted as an unadmitted parent merely
    /// because its admission marker is corrupt.
    #[tokio::test]
    async fn corrupt_admission_on_ready_lease_never_uses_pending_delete() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let lease_uid = "sandbox-ready-corrupt-uid";
        let held =
            mount_reservation_api_owned(&server, &[(reservation_name.clone(), lease_uid.into())])
                .await;
        held.lock().unwrap().get_mut(&reservation_name).unwrap()["metadata"]["uid"] =
            serde_json::json!("wrong-token-uid");
        let ledger_before = held.lock().unwrap().clone();
        let object = active_release_json("sandbox-ready-corrupt", Some("corrupt"));
        let parent_before = object.clone();
        let state = Arc::new(Mutex::new(object));
        let lease_path = "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-ready-corrupt";
        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(lease_path))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-ready-corrupt".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(*held.lock().unwrap(), ledger_before);
        assert_eq!(*state.lock().unwrap(), parent_before);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| {
                    !(request.url.path() == lease_path
                        && matches!(request.method.as_str(), "PATCH" | "DELETE")
                        || request.url.path().contains("coordination.k8s.io")
                            && request.method.as_str() == "DELETE")
                })
        );
    }

    async fn assert_mismatched_active_release_is_retained(name: &str, object: serde_json::Value) {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let lease_uid = format!("{name}-uid");
        let reservation_name = quota_reservation_name(&principal_hash(&identity()), 0);
        let held = mount_reservation_api_owned(&server, &[(reservation_name, lease_uid)]).await;
        let ledger_before = held.lock().unwrap().clone();
        let parent_before = object.clone();
        let state = Arc::new(Mutex::new(object));
        let lease_path =
            format!("/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/{name}");
        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(lease_path.clone()))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path(name.into()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(*held.lock().unwrap(), ledger_before);
        assert_eq!(*state.lock().unwrap(), parent_before);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| {
                    !(request.url.path() == lease_path
                        && matches!(request.method.as_str(), "PATCH" | "DELETE")
                        || request.url.path().contains("coordination.k8s.io")
                            && request.method.as_str() == "DELETE")
                })
        );
    }

    /// Management teardown cannot be selected for a target that proves a
    /// child composition. Repairing this mismatch would strand that child
    /// after the management path returned quota.
    #[tokio::test]
    async fn management_placement_with_child_target_never_repairs_admission() {
        let name = "sandbox-management-child-target";
        let mut object = active_release_json(name, Some("corrupt"));
        object["status"]["target"] = serde_json::json!({
            "namespace": "test-ns",
            "childClusterLease": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "namespace": "test-ns",
                "name": "kobe-sbx-management-child-target",
                "uid": "child-lease-uid",
                "generation": 1
            },
            "childClusterInstance": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "namespace": "test-ns",
                "name": "child-instance",
                "uid": "child-instance-uid",
                "generation": 2
            }
        });

        assert_mismatched_active_release_is_retained(name, object).await;
    }

    /// Child teardown cannot be selected from placement alone when the target
    /// proves only management-cluster objects. Without child identities the
    /// child path can see a derived 404 and return quota while those objects
    /// survive.
    #[tokio::test]
    async fn child_placement_with_management_target_never_repairs_admission() {
        let name = "sandbox-child-management-target";
        let mut object = active_release_json(name, Some("corrupt"));
        object["status"]["placement"] = serde_json::json!({
            "type": "childCluster",
            "clusterPool": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "namespace": "test-ns",
                "name": "children",
                "uid": "child-pool-uid",
                "generation": 1
            }
        });

        assert_mismatched_active_release_is_retained(name, object).await;
    }

    /// Child placement always composes into Kobe's fixed child namespace.
    /// Internally consistent references that echo a different top-level
    /// namespace still cannot authorize admission repair or teardown.
    #[tokio::test]
    async fn child_target_in_a_noncanonical_namespace_never_repairs_admission() {
        let name = "sandbox-child-wrong-namespace";
        let mut object = active_release_json(name, Some("corrupt"));
        object["status"]["placement"] = serde_json::json!({
            "type": "childCluster",
            "clusterPool": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterPool",
                "namespace": "test-ns",
                "name": "children",
                "uid": "child-pool-uid",
                "generation": 1
            }
        });
        object["status"]["target"] = serde_json::json!({
            "namespace": "caller-selected",
            "childClusterLease": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "namespace": "test-ns",
                "name": "kobe-sbx-child-wrong-namespace",
                "uid": "child-lease-uid",
                "generation": 1
            },
            "childClusterInstance": {
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterInstance",
                "namespace": "test-ns",
                "name": "child-instance",
                "uid": "child-instance-uid",
                "generation": 2
            },
            "sandboxClaim": {
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                "kind": "SandboxClaim",
                "namespace": "caller-selected",
                "name": "claim",
                "uid": "claim-uid"
            }
        });

        assert_mismatched_active_release_is_retained(name, object).await;
    }

    /// Exact active provenance is repaired and released by one indivisible
    /// parent mutation; even a lost response resolves from the exact re-read,
    /// while reservation tokens remain held for verified teardown.
    #[tokio::test]
    async fn proven_admitted_shape_repairs_admission_and_records_release_atomically() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());
        let reservation_name = quota_reservation_name(&principal, 0);
        let lease_uid = "sandbox-repair-uid";
        let held =
            mount_reservation_api_owned(&server, &[(reservation_name.clone(), lease_uid.into())])
                .await;
        let object = active_release_json("sandbox-repair", Some("corrupt"));
        let state = Arc::new(Mutex::new(object));
        let lease_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-repair";

        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(lease_path))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let patch_state = Arc::clone(&state);
        Mock::given(method("PATCH"))
            .and(path(lease_path))
            .respond_with(move |request: &wiremock::Request| {
                let operations: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let operations = operations.as_array().unwrap();
                assert_eq!(operations.len(), 4, "repair must be one exact atomic patch");
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/uid"
                        && operation["value"] == lease_uid
                }));
                assert!(operations.iter().any(|operation| {
                    operation["op"] == "test"
                        && operation["path"] == "/metadata/resourceVersion"
                        && operation["value"] == "1"
                }));
                let admission = operations
                    .iter()
                    .find(|operation| {
                        operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-admission"
                    })
                    .unwrap()["value"]
                    .clone();
                let release_requested_at = operations
                    .iter()
                    .find(|operation| {
                        operation["path"]
                            == "/metadata/annotations/kobe.kunobi.ninja~1sandbox-release-requested-at"
                    })
                    .unwrap()["value"]
                    .clone();
                let mut object = patch_state.lock().unwrap();
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] = admission;
                object["metadata"]["annotations"][SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION] =
                    release_requested_at;
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "InternalError", "code": 500
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-repair".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(held.lock().unwrap().len(), 1);
        let repaired = state.lock().unwrap().clone();
        assert_eq!(
            repaired["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION],
            SANDBOX_ADMISSION_ADMITTED
        );
        assert!(
            repaired["metadata"]["annotations"]
                .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
                .is_some()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == lease_path
                    && request.method.as_str() == "PATCH")
                .count(),
            1
        );
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    /// Non-pristine status without exact active proof is retained unchanged.
    #[tokio::test]
    async fn ambiguous_corrupt_admission_fails_closed() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let held = mount_reservation_api(&server, &[]).await;
        let mut object = pristine_pending_json("sandbox-ambiguous", None);
        object["status"]["placement"] = serde_json::json!({ "type": "management" });
        let before = object.clone();
        let state = Arc::new(Mutex::new(object));
        let lease_path =
            "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-ambiguous";
        let get_state = Arc::clone(&state);
        Mock::given(method("GET"))
            .and(path(lease_path))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().clone())
            })
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-ambiguous".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(held.lock().unwrap().is_empty());
        assert_eq!(*state.lock().unwrap(), before);
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !(request.url.path() == lease_path
                && matches!(request.method.as_str(), "PATCH" | "DELETE")
                || request.url.path().contains("coordination.k8s.io")
                    && matches!(request.method.as_str(), "PATCH" | "DELETE"))
        }));
        assert_eq!(
            state.lock().unwrap()["metadata"]["finalizers"],
            serde_json::json!([SANDBOX_LEASE_FINALIZER])
        );
    }

    #[tokio::test]
    async fn release_records_intent_without_writing_controller_status() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-own",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "sandbox-own",
                "alice@example.com",
                "Ready",
            )))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-own",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "sandbox-own",
                "alice@example.com",
                "Ready",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-own".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let requests = server.received_requests().await.unwrap();
        let patch = requests
            .iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("release intent patch");
        assert!(!patch.url.path().ends_with("/status"));
        let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert_eq!(body["metadata"]["resourceVersion"], "1");
        assert!(
            body["metadata"]["annotations"]
                .get(SANDBOX_RELEASE_REQUESTED_AT_ANNOTATION)
                .is_some()
        );
        assert!(body.get("status").is_none());
    }

    #[tokio::test]
    async fn quarantined_release_is_explicit_conflict() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-own",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "sandbox-own",
                "alice@example.com",
                "Quarantined",
            )))
            .mount(&server)
            .await;

        let response = release_sandbox_lease::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path("sandbox-own".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "PATCH")
        );
    }
    /// A pool with no runner refuses every durable execution, and refuses it
    /// before the caller's idempotency key is spent.
    ///
    /// The order is the point. Reserving first and failing afterwards would
    /// burn the key on an execution that never existed: the caller's retry —
    /// with the same key, as retries must — would then get a conflict, or
    /// worse, the record of a command nobody ever ran.
    ///
    /// And it is refused rather than approximated. Raw exec cannot implement
    /// wait-mode `cwd`, exact exit status and process-group cancellation; mode
    /// must not silently select a weaker contract.
    #[tokio::test]
    async fn a_pool_without_a_runner_refuses_all_modes_before_spending_the_key() {
        for detached in [false, true] {
            let server = MockServer::start().await;
            mount_sandbox_crds(&server).await;
            mount_ready_sandbox(&server, pool_json()).await;

            let response = create_sandbox_execution::<crate::testutil::MockBackend>(
                State(test_state(&server)),
                identity(),
                Path("sandbox-own".into()),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "command": ["/agent", "run"],
                        "cwd": "/workspace",
                        "idempotencyKey": "key-1",
                        "detach": detached
                    }))
                    .unwrap(),
                ),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap_or_default()
                    .iter()
                    .all(|request| !(request.method.as_str() == "POST"
                        && request.url.path().contains("/sandboxexecutions"))),
                "the idempotency key must not be reserved for a request that cannot be served"
            );
        }
    }

    /// Wait-mode output remains runner-addressable after its inline response.
    ///
    /// A disconnect can happen after the command settles but before the client
    /// receives the body. Refusing logs solely because `detached=false` would
    /// make that exact output unrecoverable and force a dangerous retry.
    #[tokio::test]
    async fn logs_for_a_wait_mode_execution_are_not_rejected_by_mode() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        mount_ready_sandbox(&server, pool_json_with_runner()).await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions/sbxe-.*$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(execution_json(false)))
            .mount(&server)
            .await;

        let response = get_sandbox_execution_logs::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path(("sandbox-own".into(), "sbxe-1".into())),
            Query(ExecutionLogsQuery {
                stdout_offset: None,
                stderr_offset: None,
            }),
        )
        .await;

        // The mock does not provide scoped credentials, so the request stops
        // later at that boundary. What must not return is the old mode-only
        // conflict before runner access is even attempted.
        assert_ne!(response.status(), StatusCode::CONFLICT);
    }

    /// A pre-runner wait record has no retained runner output to address.
    ///
    /// Attempting to poll that id would receive runner `NotFound` and corrupt
    /// a valid rolling-upgrade record to `Unknown`, so the boundary is refused
    /// before any runner access is attempted.
    #[tokio::test]
    async fn legacy_wait_logs_are_refused_without_runner_reconciliation() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        mount_ready_sandbox(&server, pool_json_with_runner()).await;
        let mut legacy = execution_json(false);
        legacy["spec"]
            .as_object_mut()
            .unwrap()
            .remove("runnerManaged");
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions/sbxe-.*$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(legacy))
            .mount(&server)
            .await;

        let response = get_sandbox_execution_logs::<crate::testutil::MockBackend>(
            State(test_state(&server)),
            identity(),
            Path(("sandbox-own".into(), "sbxe-1".into())),
            Query(ExecutionLogsQuery {
                stdout_offset: None,
                stderr_offset: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A runner-managed record never falls back to record-only cancellation.
    /// Missing runner access is uncertainty about a live process, so both wait
    /// and detached mode must remain Running and retryable.
    #[tokio::test]
    async fn runner_managed_cancel_without_runner_never_records_a_fake_cancellation() {
        for detached in [false, true] {
            let server = MockServer::start().await;
            mount_sandbox_crds(&server).await;
            mount_ready_sandbox(&server, pool_json()).await;
            Mock::given(method("GET"))
                .and(path_regex(
                    r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxexecutions/sbxe-.*$",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(execution_json(detached)))
                .mount(&server)
                .await;

            let response = cancel_sandbox_execution::<crate::testutil::MockBackend>(
                State(test_state(&server)),
                identity(),
                Path(("sandbox-own".into(), "sbxe-1".into())),
            )
            .await;

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap_or_default()
                    .iter()
                    .all(|request| {
                        !(request.method.as_str() == "PATCH"
                            && request.url.path().contains("/sandboxexecutions/"))
                    }),
                "an unconfirmed runner-managed process must remain Running"
            );
        }
    }

    /// A supervised wait-mode execution must never fall through to the legacy
    /// record-only cancellation path when its Pool no longer exposes a runner.
    ///
    /// `detached` describes response timing, not supervision, after wait mode
    /// moved to the runner. The optional provenance field preserves the exact
    /// old behavior for records created before that change.
    #[test]
    fn runner_managed_wait_execution_never_falls_back_to_record_only_cancellation() {
        let spec = |detached, runner_managed| crate::crd::SandboxExecutionSpec {
            lease_name: None,
            lease_uid: "lease-uid".into(),
            pod_uid: "pod-uid".into(),
            idempotency_key: "key-1".into(),
            request_digest: "d".repeat(64),
            timeout: "60s".into(),
            detached,
            runner_managed,
            target: None,
        };

        assert!(execution_is_runner_managed(&spec(false, Some(true))));
        assert!(
            execution_is_runner_managed(&spec(true, None)),
            "legacy detached records were runner-managed"
        );
        assert!(
            !execution_is_runner_managed(&spec(false, None)),
            "only legacy wait records may use record-only cancellation"
        );
        assert!(
            !execution_is_runner_managed(&spec(true, Some(false))),
            "explicit provenance takes precedence over the legacy inference"
        );
    }

    /// Retrying a wait-mode POST after its response was lost resumes the exact
    /// runner record. It must not return the durable status with empty streams,
    /// and it must never select the fresh-start path again.
    #[test]
    fn lost_wait_response_resumes_the_exact_runner_record() {
        let mut record: crate::crd::SandboxExecution =
            serde_json::from_value(execution_json(false)).unwrap();
        assert_eq!(
            reused_execution_response_status(&record),
            None,
            "current wait mode must resume runner polling/output"
        );

        record.status.as_mut().unwrap().state = crate::crd::ExecutionState::Failed;
        record.status.as_mut().unwrap().exit_code = Some(42);
        assert_eq!(
            reused_execution_response_status(&record),
            None,
            "terminal wait mode must recover retained output"
        );
        let response = execution_response(
            &record,
            Some(crate::api::sandbox_access::SandboxExecResponse {
                stdout: "retained-out".into(),
                stderr: "retained-err".into(),
                success: false,
                exit_code: Some(42),
                truncated: false,
            }),
        );
        assert_eq!(response.exit_code, Some(42));
        assert_eq!(response.stdout.as_deref(), Some("retained-out"));
        assert_eq!(response.stderr.as_deref(), Some("retained-err"));

        record.spec.runner_managed = None;
        assert_eq!(
            reused_execution_response_status(&record),
            Some(StatusCode::OK),
            "legacy raw wait records keep their old record-only response"
        );
        record.spec.detached = true;
        record.status.as_mut().unwrap().state = crate::crd::ExecutionState::Running;
        assert_eq!(
            reused_execution_response_status(&record),
            Some(StatusCode::ACCEPTED),
            "detached retries remain handle-based"
        );
    }

    /// Revocation wins while retained output is being read and drops the
    /// in-flight operation, so no later runner log chunk can be requested.
    #[tokio::test]
    async fn revocation_aborts_wait_output_retrieval() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropSignal(std::sync::Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let revoked = tokio_util::sync::CancellationToken::new();
        let observed = revoked.clone();
        let dropped = std::sync::Arc::new(AtomicBool::new(false));
        let dropped_by_operation = dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            complete_before_revocation(&observed, async move {
                let _drop_signal = DropSignal(dropped_by_operation);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .await
        });

        started_rx.await.unwrap();
        revoked.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("revocation must stop output retrieval")
            .unwrap();
        assert_eq!(result, None);
        assert!(
            dropped.load(Ordering::SeqCst),
            "the in-flight runner operation must be dropped"
        );
    }

    /// Log offsets are per stream, and unknown options are refused.
    ///
    /// One offset for both streams would re-read whichever stream was behind
    /// or skip whichever was ahead — and a silently ignored option means a
    /// caller believes they set a bound that was never applied.
    #[test]
    fn a_log_window_is_addressed_per_stream() {
        let query: ExecutionLogsQuery =
            serde_json::from_value(serde_json::json!({ "stdoutOffset": 10, "stderrOffset": 20 }))
                .unwrap();
        assert_eq!(query.stdout_offset, Some(10));
        assert_eq!(query.stderr_offset, Some(20));

        for smuggled in ["offset", "tail", "follow", "container", "stream", "limit"] {
            assert!(
                serde_json::from_value::<ExecutionLogsQuery>(serde_json::json!({ smuggled: 1 }))
                    .is_err(),
                "{smuggled} must be refused, not ignored"
            );
        }
    }

    /// The CLI and conformance clients consume camelCase. A server response
    /// that emitted `exit_code` would silently deserialize as `None` in the CLI
    /// and replace the real remote result with Kobe's transport-failure code.
    #[test]
    fn the_execution_wire_contract_uses_stable_camel_case_fields() {
        let request: CreateExecutionRequest = serde_json::from_value(serde_json::json!({
            "command": ["/agent", "run"],
            "cwd": "/workspace",
            "timeout": "60s",
            "idempotencyKey": "key-1",
            "detach": false
        }))
        .unwrap();
        assert_eq!(request.idempotency_key, "key-1");
        assert!(
            serde_json::from_value::<CreateExecutionRequest>(serde_json::json!({
                "command": ["/agent"],
                "idempotency_key": "key-1"
            }))
            .is_err(),
            "snake_case must not become an undocumented second wire shape"
        );

        let response = serde_json::to_value(ExecutionResponse {
            id: "sbxe-1".into(),
            state: "Failed".into(),
            exit_code: Some(42),
            started_at: None,
            finished_at: None,
            reason: Some("completed".into()),
            stdout: Some("out".into()),
            stderr: Some("err".into()),
            truncated: false,
        })
        .unwrap();
        assert_eq!(response["exitCode"], 42);
        assert!(response.get("exit_code").is_none());
    }

    fn pool_json_with_runner() -> serde_json::Value {
        let mut pool = pool_json();
        pool["spec"]["template"]["runnerPath"] = serde_json::json!("/kobe-runner");
        pool
    }

    fn execution_json(detached: bool) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxExecution",
            "metadata": {
                "name": "sbxe-1", "namespace": "test-ns",
                "uid": "sbxe-1-uid", "resourceVersion": "1"
            },
            "spec": {
                "leaseUid": "sandbox-own-uid",
                "podUid": "pod-uid",
                "idempotencyKey": "key-1",
                "requestDigest": "d".repeat(64),
                "timeout": "60s",
                "detached": detached,
                "runnerManaged": true
            },
            "status": { "state": "Running" }
        })
    }

    /// A lease that is Ready and fully placed, so execution paths reach their
    /// own logic instead of stopping at resolution.
    async fn mount_ready_sandbox(server: &MockServer, pool: serde_json::Value) {
        // The id must LOOK like a lease id: anything else is resolved as a
        // caller alias, which is a different code path entirely.
        let mut lease = lease_json("sandbox-own", &identity().identity, "Ready");
        lease["status"] = serde_json::json!({
            "phase": "Ready",
            "observedGeneration": 1,
            "readyAt": chrono::Utc::now().to_rfc3339(),
            "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            "placement": { "type": "management" },
            "target": {
                "namespace": "test-ns",
                "sandboxClaim": {
                    "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "SandboxClaim",
                    "name": "claim", "uid": "claim-uid"
                },
                "sandbox": {
                    "apiVersion": "agents.x-k8s.io/v1alpha1", "kind": "Sandbox",
                    "name": "sbx", "uid": "sandbox-uid"
                },
                "pod": {
                    "apiVersion": "v1", "kind": "Pod",
                    "name": "sbx-0", "uid": "pod-uid"
                }
            }
        });
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-own",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agent-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool))
            .mount(server)
            .await;
    }
}
