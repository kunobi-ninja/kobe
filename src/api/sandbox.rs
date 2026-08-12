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
use crate::backend::ClusterBackend;
use crate::crd::{
    ResolvedSandboxPlacement, SandboxCondition, SandboxLease, SandboxLeasePhase, SandboxLeaseSpec,
    SandboxPool, SandboxPoolReference, SandboxPrincipal, SandboxTargetProvenance, SandboxVerb,
};
use crate::pool::{is_valid_k8s_name, parse_duration};
use crate::sandbox::{aggregate_resource_limits, resource_ceiling_allows};

const REQUESTER_HASH_LABEL: &str = "kobe.kunobi.ninja/requester-hash";
const SANDBOX_POOL_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool";
const SANDBOX_ALIAS_LABEL: &str = "kobe.kunobi.ninja/alias";
const SANDBOX_POOL_CRD: &str = "sandboxpools.kobe.kunobi.ninja";
const SANDBOX_LEASE_CRD: &str = "sandboxleases.kobe.kunobi.ninja";
const SANDBOX_RESERVATION_TYPE_LABEL: &str = "kobe.kunobi.ninja/sandbox-reservation";
pub(crate) const SANDBOX_RESERVATION_LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-uid";
const SANDBOX_RESERVATION_LEASE_NAME_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-lease-name";
const SANDBOX_RESERVATION_QUOTA: &str = "quota";
const SANDBOX_RESERVATION_ALIAS: &str = "alias";
const MAX_SANDBOX_CONCURRENCY_SLOTS: u32 = 256;
/// Server-owned admission gate. Placement controllers must ignore every lease
/// unless this annotation has the exact `admitted` value.
pub(crate) const SANDBOX_ADMISSION_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-admission";
pub(crate) const SANDBOX_ADMISSION_PENDING: &str = "pending";
pub(crate) const SANDBOX_ADMISSION_ADMITTED: &str = "admitted";
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

/// Everything an interactive operation needs, resolved before the upgrade.
///
/// Resolution happens *before* the WebSocket handshake completes on purpose:
/// a denial has to be an HTTP status the caller's client understands, not a
/// close frame delivered a moment after a successful-looking upgrade.
struct UpgradeContext {
    target: crate::api::sandbox_access::SandboxTarget,
    container: String,
    scoped: kube::Client,
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

    let (_lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, id, identity).await {
            Ok(resolved) => resolved,
            Err(denied) => return Err(access_denied(identity, id, operation.as_str(), denied)),
        };
    let container = match target.resolve_container(requested_container) {
        Ok(container) => container.to_string(),
        Err(denied) => return Err(access_denied(identity, id, operation.as_str(), denied)),
    };
    if target.placement != access::TargetPlacement::Management {
        return Err(sandbox_error(
            StatusCode::NOT_IMPLEMENTED,
            "Interactive Sandbox access is not yet available for child placement",
            None,
        ));
    }

    // Concurrency is checked before the upgrade, so a caller over the limit
    // gets a status rather than a socket that closes immediately.
    if !crate::api::sandbox_streams::may_start_stream(
        crate::api::sandbox_streams::registry(),
        &target.lease_uid,
    )
    .await
    {
        return Err(access_denied_with(
            identity,
            id,
            operation.as_str(),
            "concurrency_limit",
            StatusCode::TOO_MANY_REQUESTS,
            "Too many concurrent operations for this Sandbox lease",
        ));
    }

    let scoped =
        match crate::api::sandbox_credentials::scoped_client(&state.client, &target, operation)
            .await
        {
            Ok(client) => client,
            Err(denied) => return Err(access_denied(identity, id, operation.as_str(), denied)),
        };

    Ok(UpgradeContext {
        target,
        container,
        scoped,
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

    let context = match prepare_upgrade(
        &state,
        &identity,
        &id,
        SandboxOperation::Exec,
        query.container.as_deref(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };

    let principal = identity.identity.clone();
    upgrade.on_upgrade(move |mut socket| async move {
        let guard = crate::api::sandbox_streams::registry()
            .register(&context.target.lease_uid)
            .await;
        let revoked = guard.cancelled();

        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(context.scoped.clone(), &context.target.namespace);
        let params = kube::api::AttachParams::default()
            .container(&context.container)
            .stdin(true)
            .stdout(true)
            // A TTY merges stderr into stdout at the kernel level, so asking
            // for both is a contradiction rather than a preference.
            .stderr(!query.tty)
            .tty(query.tty);

        let attached = match query.command.as_ref() {
            Some(command) => pods.exec(&context.target.pod_name, command, &params).await,
            None => pods.attach(&context.target.pod_name, &params).await,
        };
        let mut attached = match attached {
            Ok(attached) => attached,
            Err(_) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
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
        let guard = crate::api::sandbox_streams::registry()
            .register(&context.target.lease_uid)
            .await;
        let revoked = guard.cancelled();

        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(context.scoped.clone(), &context.target.namespace);
        let mut forwarder = match pods.portforward(&context.target.pod_name, &[port]).await {
            Ok(forwarder) => forwarder,
            Err(_) => {
                transport::close_with(&mut socket, transport::StreamEnd::TargetError).await;
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

    if let Err(response) = require_sandbox_crds(&state.client, &[SANDBOX_LEASE_CRD]).await {
        return response;
    }
    if !is_valid_k8s_name(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (_lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "exec", denied),
        };
    let container = match target.resolve_container(request.container.as_deref()) {
        Ok(container) => container.to_string(),
        Err(denied) => return access_denied(&identity, &id, "exec", denied),
    };
    if target.placement != access::TargetPlacement::Management {
        return sandbox_error(
            StatusCode::NOT_IMPLEMENTED,
            "Sandbox exec is not yet available for child placement",
            None,
        );
    }

    let scoped = match credentials::scoped_client(
        &state.client,
        &target,
        credentials::SandboxOperation::Exec,
    )
    .await
    {
        Ok(client) => client,
        Err(denied) => return access_denied(&identity, &id, "exec", denied),
    };

    // Registered for the duration, so releasing or expiring the lease cancels
    // the command rather than letting it run on inside a workload that is
    // being torn down. The guard deregisters on every exit path, including a
    // panic — a leaked registration would later report cancelling something
    // that ended long ago.
    let streams = crate::api::sandbox_streams::registry();
    if !crate::api::sandbox_streams::may_start_stream(streams, &target.lease_uid).await {
        return access_denied_with(
            &identity,
            &id,
            "exec",
            "concurrency_limit",
            StatusCode::TOO_MANY_REQUESTS,
            "Too many concurrent operations for this Sandbox lease",
        );
    }
    let guard = streams.register(&target.lease_uid).await;
    let revoked = guard.cancelled();

    let result = tokio::select! {
        result = access::exec_in_sandbox(
            &scoped,
            &target,
            &container,
            &request.command,
            SANDBOX_EXEC_TIMEOUT,
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

    let (_lease, target) =
        match access::resolve_sandbox_target(&state.client, &state.namespace, &id, &identity).await
        {
            Ok(resolved) => resolved,
            Err(denied) => return access_denied(&identity, &id, "logs", denied),
        };

    let container = match target.resolve_container(query.container.as_deref()) {
        Ok(container) => container.to_string(),
        Err(denied) => return access_denied(&identity, &id, "logs", denied),
    };

    // Child-placed Sandboxes live in a cluster this API server reaches with a
    // different client. Resolving that is #74's composition, not something the
    // logs path may improvise, so it is refused explicitly rather than read
    // from the wrong cluster — which would return another workload's output or
    // a misleading 404.
    if target.placement != access::TargetPlacement::Management {
        return sandbox_error(
            StatusCode::NOT_IMPLEMENTED,
            "Sandbox logs are not yet available for child placement",
            None,
        );
    }

    // The read runs under a credential that cannot name a second Pod, rather
    // than under the operator's own authority. The resolver has already denied
    // everything it should — this is the layer that makes a bug in the request
    // path a 403 instead of a privilege escalation.
    let scoped = match crate::api::sandbox_credentials::scoped_client(
        &state.client,
        &target,
        crate::api::sandbox_credentials::SandboxOperation::Logs,
    )
    .await
    {
        Ok(client) => client,
        Err(denied) => return access_denied(&identity, &id, "logs", denied),
    };

    match access::read_sandbox_logs(&scoped, &target, &container, access::clamp_tail(query.tail))
        .await
    {
        Ok(logs) => {
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
        Err(denied) => access_denied(&identity, &id, "logs", denied),
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

#[tracing::instrument(skip_all)]
async fn create_sandbox_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Json(request): Json<CreateSandboxLeaseRequest>,
) -> Response {
    if let Err(response) =
        require_sandbox_crds(&state.client, &[SANDBOX_POOL_CRD, SANDBOX_LEASE_CRD]).await
    {
        return response;
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
    let pool = match pools.get(&request.pool).await {
        Ok(pool) => pool,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return sandbox_error(StatusCode::NOT_FOUND, "SandboxPool not found", None);
        }
        Err(err) => return sandbox_infra_error("Unable to load SandboxPool", err),
    };

    if let Err(err) = pool.spec.validate() {
        return sandbox_infra_error("SandboxPool configuration is invalid", err);
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
    if parse_duration(&pool.spec.provisioning_timeout)
        .filter(|duration| *duration > chrono::Duration::zero())
        .is_none()
    {
        return sandbox_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SandboxPool provisioning timeout is invalid",
            None,
        );
    }
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
    let reservations: Api<Lease> = Api::namespaced(state.client.clone(), &state.namespace);
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
    reap_abandoned_pending_leases(&leases, &reservations, &identity, chrono::Utc::now()).await;

    let lease_id = format!(
        "sandbox-{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );
    let lease = build_sandbox_lease(
        &lease_id,
        &state.namespace,
        pool_reference,
        &effective_ttl,
        request.alias.as_deref(),
        &identity,
    );
    let created = match leases.create(&PostParams::default(), &lease).await {
        Ok(created) => created,
        Err(err) => return sandbox_infra_error("Failed to create Sandbox lease", err),
    };
    if let Err(err) = validate_lease_shape(&lease, &created, SANDBOX_ADMISSION_PENDING) {
        if let Err(cleanup_err) = delete_exact_pending_lease(&leases, &reservations, &created).await
        {
            error!(error = %cleanup_err, "Failed to remove malformed Sandbox lease create response");
        }
        return sandbox_infra_error("Sandbox lease create response failed validation", err);
    }

    // Quota and alias admission use atomic, per-principal Kubernetes Lease
    // reservations. Advisory LIST checks above improve error latency, but only
    // these CREATE operations are authoritative across API replicas.
    let admission_reservations = match acquire_admission_reservations(
        &reservations,
        &created,
        &identity,
        request.alias.as_deref(),
        grant.max_concurrent_leases,
    )
    .await
    {
        Ok(reservations) => reservations,
        Err(AdmissionReservationError::QuotaExhausted) => {
            if let Err(err) = delete_exact_pending_lease(&leases, &reservations, &created).await {
                return sandbox_infra_error(
                    "Sandbox quota reservation cleanup failed; lease remains unadmitted",
                    err,
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
        Err(AdmissionReservationError::AliasTaken) => {
            if let Err(err) = delete_exact_pending_lease(&leases, &reservations, &created).await {
                return sandbox_infra_error(
                    "Sandbox alias reservation cleanup failed; lease remains unadmitted",
                    err,
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
        Err(err) => {
            if let Err(cleanup_err) =
                delete_exact_pending_lease(&leases, &reservations, &created).await
            {
                error!(error = %cleanup_err, "Failed to remove Sandbox lease after reservation error");
            }
            return sandbox_infra_error("Failed to reserve Sandbox admission", err);
        }
    };

    if let Err(err) = admit_sandbox_lease(&leases, &reservations, &created).await {
        if matches!(err, SandboxLeaseMutationError::AdmissionNotCommitted) {
            if let Err(cleanup_err) =
                release_admission_reservations(&reservations, &admission_reservations).await
            {
                error!(error = %cleanup_err, "Failed to release Sandbox admission reservations");
            }
            if let Err(cleanup_err) =
                delete_exact_pending_lease(&leases, &reservations, &created).await
            {
                error!(error = %cleanup_err, "Failed to remove Sandbox lease after admission failure");
            }
        }
        return sandbox_infra_error("Failed to finalize Sandbox lease admission", err);
    }

    info!(
        lease_id = %lease_id,
        pool = %request.pool,
        identity = %identity.identity,
        "Sandbox lease accepted for placement"
    );

    (
        StatusCode::ACCEPTED,
        Json(SandboxLeaseResponse {
            id: lease_id,
            phase: SandboxLeasePhase::Pending.to_string(),
            pool: request.pool,
            ttl: effective_ttl.clone(),
            effective_ttl: was_clamped.then_some(effective_ttl),
            alias: request.alias,
            observed_generation: None,
            provisioning_deadline: None,
            ready_at: None,
            expires_at: None,
            placement: None,
            target: None,
            conditions: Vec::new(),
        }),
    )
        .into_response()
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
        SandboxLeasePhase::Releasing | SandboxLeasePhase::Released | SandboxLeasePhase::Expired
    ) {
        return StatusCode::NO_CONTENT.into_response();
    }

    if lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        != Some(SANDBOX_ADMISSION_ADMITTED)
    {
        let reservations: Api<Lease> = Api::namespaced(state.client.clone(), &state.namespace);
        return match delete_exact_pending_lease(&leases, &reservations, &lease).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(err) => sandbox_infra_error("Failed to remove unadmitted Sandbox lease", err),
        };
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
        ..target
    }
}

fn build_sandbox_lease(
    id: &str,
    namespace: &str,
    pool_ref: SandboxPoolReference,
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
            ..Default::default()
        },
        spec: SandboxLeaseSpec {
            pool_ref,
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

/// How long a lease may sit unadmitted before it is treated as abandoned.
///
/// Admission is a handful of API calls, so a legitimately in-flight request is
/// orders of magnitude below this. The margin is deliberately large: reaping a
/// live request would delete a lease its caller is about to be told succeeded,
/// which is far worse than a slot staying busy for a few extra minutes.
const SANDBOX_PENDING_DEADLINE_SECS: i64 = 600;

/// Whether an unadmitted lease is old enough to be treated as abandoned.
///
/// Pure so the boundary is testable without a clock: `now` is supplied.
fn pending_lease_is_abandoned(
    created_at: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(created_at) = created_at else {
        // No creation timestamp means we cannot prove it is old. Reaping on
        // absent evidence is exactly the mistake this whole module avoids.
        return false;
    };
    let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    (now - created_at.with_timezone(&chrono::Utc)).num_seconds() >= SANDBOX_PENDING_DEADLINE_SECS
}

/// Release quota and aliases stranded by a request that died mid-admission.
///
/// Reservations are created before the lease is admitted, and they are owned by
/// that lease — so Kubernetes garbage-collects them only once the lease is
/// *deleted*. If the process dies (or a cleanup path itself fails) between
/// acquiring reservations and committing admission, the lease stays `pending`
/// forever, no controller touches it (placement ignores anything not `admitted`),
/// and its slot plus alias are consumed permanently. The caller then gets 429 or
/// 409 on every retry with no way out but manual deletion.
///
/// This sweep is the recovery path. It runs on the caller's own next create, so
/// the principal who was locked out is exactly the one who unlocks themselves.
///
/// Scope, stated narrowly: it reclaims **this principal's** abandoned pending
/// leases at **create time only**. It is not a general reaper — a principal who
/// never calls create again keeps their slot stranded until #73's controller
/// owns a durable sweep. That is a deliberately smaller claim than "crash-safe".
async fn reap_abandoned_pending_leases(
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
        if lease
            .annotations()
            .get(SANDBOX_ADMISSION_ANNOTATION)
            .map(String::as_str)
            != Some(SANDBOX_ADMISSION_PENDING)
        {
            continue;
        }
        if !pending_lease_is_abandoned(
            lease
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|timestamp| timestamp.0.to_string())
                .as_deref(),
            now,
        ) {
            continue;
        }

        // UID + resourceVersion fenced, and it releases the lease's
        // reservations. A lease that got admitted since we listed fails the
        // shape check and is left alone.
        match delete_exact_pending_lease(leases, reservations, &lease).await {
            Ok(()) => info!(
                lease_id = %lease.name_any(),
                "Reclaimed an abandoned unadmitted Sandbox lease and its reservations"
            ),
            Err(error) => warn!(
                lease_id = %lease.name_any(),
                error = %error,
                "Could not reclaim an abandoned unadmitted Sandbox lease"
            ),
        }
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

async fn admit_sandbox_lease(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    let name = lease.name_any();
    let resource_version = lease
        .resource_version()
        .ok_or(SandboxLeaseMutationError::MissingResourceVersion)?;
    let patch = serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": { SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_ADMITTED }
        }
    });
    match leases
        .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(admitted) => validate_lease_shape(lease, &admitted, SANDBOX_ADMISSION_ADMITTED),
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
                    validate_lease_shape(lease, &current, SANDBOX_ADMISSION_ADMITTED)
                }
                Some(SANDBOX_ADMISSION_PENDING) => {
                    validate_lease_shape(lease, &current, SANDBOX_ADMISSION_PENDING)?;
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
#[derive(Debug, Clone)]
struct AdmissionReservation {
    name: String,
    uid: String,
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
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

/// Quota slots are named per principal and per slot index, so acquiring one is
/// a race for a *specific* name. `CREATE` is the atomic primitive: two API
/// replicas contending for the last slot cannot both succeed, because the
/// second gets 409 from the API server.
fn quota_reservation_name(principal: &str, slot: u32) -> String {
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
/// The owner reference is the crash-safety net: if the `SandboxLease` is
/// deleted by any path we did not anticipate, Kubernetes garbage-collects the
/// reservations with it, so a slot cannot leak and permanently consume quota.
fn build_admission_reservation(
    name: String,
    reservation_type: &str,
    lease: &SandboxLease,
    principal: &str,
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
            namespace: lease.namespace(),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: Some(vec![
                k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                    api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
                    kind: "SandboxLease".to_string(),
                    name: lease.name_any(),
                    uid: lease_uid,
                    controller: Some(false),
                    block_owner_deletion: Some(false),
                },
            ]),
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
    reservations: &Api<Lease>,
    lease: &SandboxLease,
    identity: &AuthIdentity,
    alias: Option<&str>,
    max_concurrent_leases: u32,
) -> Result<Vec<AdmissionReservation>, AdmissionReservationError> {
    let principal = principal_hash(identity);
    let mut acquired: Vec<AdmissionReservation> = Vec::new();

    if let Some(alias) = alias {
        let reservation = build_admission_reservation(
            alias_reservation_name(&principal, alias),
            SANDBOX_RESERVATION_ALIAS,
            lease,
            &principal,
        )?;
        match reservations
            .create(&PostParams::default(), &reservation)
            .await
        {
            Ok(created) => acquired.push(AdmissionReservation {
                name: created.name_any(),
                uid: created.uid().unwrap_or_default(),
            }),
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
    // still decides.
    match reservations
        .list(&ListParams::default().labels(&format!(
            "{SANDBOX_RESERVATION_TYPE_LABEL}={SANDBOX_RESERVATION_QUOTA},{REQUESTER_HASH_LABEL}={principal}"
        )))
        .await
    {
        Ok(existing) if existing.items.len() as u32 >= max_concurrent_leases => {
            rollback_partial_reservations(reservations, &acquired).await;
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
        )?;
        match reservations
            .create(&PostParams::default(), &reservation)
            .await
        {
            Ok(created) => {
                acquired.push(AdmissionReservation {
                    name: created.name_any(),
                    uid: created.uid().unwrap_or_default(),
                });
                slot_taken = true;
                break;
            }
            // This slot belongs to another live lease; try the next one.
            Err(kube::Error::Api(error)) if error.code == 409 => continue,
            Err(error) => {
                // Never leave a partially-acquired alias behind: it would block
                // the caller's own retry with a spurious 409.
                rollback_partial_reservations(reservations, &acquired).await;
                return Err(error.into());
            }
        }
    }

    if !slot_taken {
        rollback_partial_reservations(reservations, &acquired).await;
        return Err(AdmissionReservationError::QuotaExhausted);
    }

    Ok(acquired)
}

/// Best-effort unwind of reservations taken earlier in a failed acquire.
///
/// Deliberately swallows errors: the caller is already returning a failure, and
/// the owner reference guarantees Kubernetes reaps anything left behind when
/// the pending lease is removed. Losing the original error to a cleanup error
/// would be strictly worse for the caller.
async fn rollback_partial_reservations(
    reservations: &Api<Lease>,
    acquired: &[AdmissionReservation],
) {
    if let Err(error) = release_admission_reservations(reservations, acquired).await {
        error!(error = %error, "Failed to roll back partial Sandbox admission reservations");
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
            // 404: already gone. 409: the name now holds someone else's
            // reservation. Both mean "ours is not there", which is the goal.
            Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Release every reservation owned by one exact lease UID.
///
/// Used on the cleanup path, where we hold the lease rather than the list of
/// reservations we created. Selecting on the UID label (not the name) is what
/// keeps a recreated same-named lease from dropping its predecessor's slots.
pub(crate) async fn release_reservations_for_lease(
    reservations: &Api<Lease>,
    lease_uid: &str,
) -> Result<(), SandboxLeaseMutationError> {
    let params = ListParams::default().labels(&format!(
        "{SANDBOX_RESERVATION_LEASE_UID_LABEL}={lease_uid}"
    ));
    let owned = reservations.list(&params).await?;
    let held: Vec<AdmissionReservation> = owned
        .into_iter()
        .filter_map(|reservation| {
            Some(AdmissionReservation {
                name: reservation.name_any(),
                uid: reservation.uid()?,
            })
        })
        .collect();
    if let Err(error) = release_admission_reservations(reservations, &held).await {
        return match error {
            AdmissionReservationError::Kubernetes(error) => Err(error.into()),
            // The other variants cannot arise from a release.
            other => {
                error!(error = %other, "Unexpected Sandbox reservation release failure");
                Ok(())
            }
        };
    }
    Ok(())
}

/// Remove a still-unadmitted lease and free whatever it reserved.
///
/// Reservations are released *after* the lease is gone. Doing it in the other
/// order would briefly leave an admitted-looking lease with no quota slot,
/// which a concurrent request could then double-book.
async fn delete_exact_pending_lease(
    leases: &Api<SandboxLease>,
    reservations: &Api<Lease>,
    lease: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    let expected_uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let current = match leases.get(&lease.name_any()).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            // The lease is already gone; its reservations may not be.
            return release_reservations_for_lease(reservations, &expected_uid).await;
        }
        Err(error) => return Err(error.into()),
    };
    validate_lease_shape(lease, &current, SANDBOX_ADMISSION_PENDING)?;
    if current.uid().as_deref() != Some(expected_uid.as_str()) {
        return Err(SandboxLeaseMutationError::UidChanged);
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
    leases.delete(&current.name_any(), &params).await?;
    release_reservations_for_lease(reservations, &expected_uid).await
}

fn validate_lease_shape(
    expected: &SandboxLease,
    actual: &SandboxLease,
    admission: &str,
) -> Result<(), SandboxLeaseMutationError> {
    if actual.name_any() != expected.name_any()
        || actual.namespace() != expected.namespace()
        || actual.spec != expected.spec
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

#[derive(Debug, Error)]
pub(crate) enum SandboxLeaseMutationError {
    #[error("SandboxLease has no UID")]
    MissingUid,
    #[error("SandboxLease has no resourceVersion")]
    MissingResourceVersion,
    #[error("SandboxLease identity or server-owned admission fields changed")]
    LeaseShapeChanged,
    #[error("SandboxLease UID changed")]
    UidChanged,
    #[error("SandboxLease has an unexpected admission state")]
    UnexpectedAdmissionState,
    #[error("SandboxLease admission patch did not commit; the pending object was removed")]
    AdmissionNotCommitted,
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::api::policy::{Policy, SandboxPolicy};
    use crate::crd::{SandboxLeaseStatus, SandboxResourceCeiling};
    use axum::body;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
            backend: crate::testutil::MockBackend::new(),
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
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
                    SANDBOX_ADMISSION_ANNOTATION: SANDBOX_ADMISSION_ADMITTED
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
        const RESERVATIONS: &str = "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases";

        // Reconstruct the labels a real reservation would carry from its name
        // (`sbx-<type>-<principal>-<suffix>`), so selector filtering behaves.
        let seeded: std::collections::BTreeMap<String, serde_json::Value> = preheld
            .iter()
            .map(|(name, owner_uid)| {
                let parts: Vec<&str> = name.splitn(4, '-').collect();
                let reservation_type = parts.get(1).copied().unwrap_or_default();
                let principal = parts.get(2).copied().unwrap_or_default();
                (
                    name.clone(),
                    serde_json::json!({
                        "apiVersion": "coordination.k8s.io/v1",
                        "kind": "Lease",
                        "metadata": {
                            "name": name,
                            "namespace": "test-ns",
                            "uid": format!("{name}-uid"),
                            "labels": {
                                SANDBOX_RESERVATION_TYPE_LABEL: reservation_type,
                                SANDBOX_RESERVATION_LEASE_UID_LABEL: owner_uid,
                                REQUESTER_HASH_LABEL: principal,
                            }
                        }
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
                r"^/apis/coordination\.k8s\.io/v1/namespaces/test-ns/leases/.+$",
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

        let patch_state = Arc::clone(&lease_state);
        Mock::given(method("PATCH"))
            .and(path_regex(
                r"^/apis/kobe\.kunobi\.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-[a-z0-9]+$",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut guard = patch_state.lock().unwrap();
                let object = guard.as_mut().expect("created lease");
                object["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
                    serde_json::json!(SANDBOX_ADMISSION_ADMITTED);
                object["metadata"]["resourceVersion"] = serde_json::json!("2");
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

    #[test]
    fn request_rejects_server_owned_and_unsafe_fields() {
        for field in [
            "requester",
            "namespace",
            "runtimeClassName",
            "podSpec",
            "credentials",
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
            "30m",
            Some("review"),
            &identity,
        );
        assert_eq!(lease.spec.requester.identity, identity.identity);
        assert_eq!(lease.spec.alias.as_deref(), Some("review"));
        assert!(lease.status.is_none());
        let json = serde_json::to_string(&lease).unwrap();
        for forbidden in ["kubeconfig", "bearer", "token", "credentials", "podSpec"] {
            assert!(
                !json
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase())
            );
        }
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
            "30m",
            None,
            &identity(),
        );
        lease.status = Some(SandboxLeaseStatus::default());
        let json = serde_json::to_string(&sandbox_lease_response(lease, None)).unwrap();
        assert!(!json.contains("alice@example.com"));
        assert!(!json.to_ascii_lowercase().contains("token"));
        assert!(!json.to_ascii_lowercase().contains("kubeconfig"));
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
        assert!(body.get("kubeconfig").is_none());
        assert!(body.get("token").is_none());

        let requests = server.received_requests().await.unwrap();
        let create = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "POST" && request.url.path().ends_with("/sandboxleases")
            })
            .expect("SandboxLease create request");
        let object: serde_json::Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(object["spec"]["requester"]["identity"], "alice@example.com");
        assert_eq!(object["spec"]["requester"]["provider"], "developer-oidc");
        assert_eq!(object["spec"]["poolRef"]["uid"], "pool-uid");
        assert_eq!(object["spec"]["ttl"], "2h");
        assert!(object["spec"].get("namespace").is_none());
        assert!(object["spec"].get("runtimeClassName").is_none());
    }

    #[tokio::test]
    async fn create_treats_applied_but_lost_admission_response_as_success() {
        let server = MockServer::start().await;
        mount_create_api(&server, true, true).await;

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
    /// This is the boundary the bug actually reaches a user at: reservations are
    /// owned by their SandboxLease, so Kubernetes GC frees them only once that
    /// lease is *deleted*. A lease abandoned at `pending` is never deleted —
    /// placement ignores anything not `admitted` — so its slot and alias stay
    /// consumed and every retry returns 429/409 with no way out but manual
    /// deletion.
    ///
    /// Asserting only that `pending_lease_is_abandoned` returns true would prove
    /// nothing: the fix lives in the create handler, so the test has to be the
    /// create that was previously refused.
    #[tokio::test]
    async fn create_reclaims_quota_stranded_by_its_own_abandoned_lease() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let principal = principal_hash(&identity());

        // Both of this principal's slots are held by reservations owned by a
        // lease that never reached `admitted`.
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
                    stranded_uid.to_string(),
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
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stranded",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(abandoned))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sandbox-stranded",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Success"
            })))
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
        // owned by the abandoned lease.
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
            "reservations owned by the abandoned lease must be released: {still_stranded:?}"
        );
    }

    /// The deadline must never reap a request that is merely in flight — that
    /// would delete a lease its caller is about to be told succeeded.
    #[test]
    fn only_leases_past_the_deadline_are_treated_as_abandoned() {
        let now = chrono::Utc::now();
        let fresh = (now - chrono::Duration::seconds(5)).to_rfc3339();
        let old =
            (now - chrono::Duration::seconds(SANDBOX_PENDING_DEADLINE_SECS + 60)).to_rfc3339();

        assert!(!pending_lease_is_abandoned(Some(&fresh), now));
        assert!(pending_lease_is_abandoned(Some(&old), now));
        // Absent or unparseable evidence of age is not evidence of abandonment.
        assert!(!pending_lease_is_abandoned(None, now));
        assert!(!pending_lease_is_abandoned(Some("not-a-timestamp"), now));
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

    /// The happy path must take exactly one quota slot and one alias, so a
    /// caller's second lease cannot silently reuse the first one's slot.
    #[tokio::test]
    async fn create_acquires_exactly_one_quota_slot_and_one_alias() {
        let server = MockServer::start().await;
        mount_sandbox_crds(&server).await;
        let held = mount_reservation_api(&server, &[]).await;
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
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let principal = principal_hash(&identity());
        let remaining = held.lock().unwrap().clone();
        assert_eq!(
            remaining.len(),
            2,
            "expected one slot + one alias: {remaining:?}"
        );
        assert!(remaining.contains_key(&quota_reservation_name(&principal, 0)));
        assert!(remaining.contains_key(&alias_reservation_name(&principal, "review")));
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
        let reservations: Api<Lease> = Api::namespaced(client, "test-ns");
        let stale = AdmissionReservation {
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
            sandbox_template: Some(reference("SandboxTemplate", "kobe-agents")),
            sandbox_warm_pool: Some(reference("SandboxWarmPool", "kobe-agents")),
            sandbox_claim: Some(reference("SandboxClaim", "kobe-sbx-1")),
            sandbox: Some(reference("Sandbox", "sbx")),
            pod: Some(reference("Pod", "sbx-0")),
        };

        let visible = caller_visible_provenance(target.clone());
        assert!(visible.child_cluster_lease.is_none());
        assert!(visible.child_cluster_instance.is_none());

        // Nothing else is stripped: the Sandbox-side objects are the caller's
        // own, and #81 resolves targets against exactly these.
        assert_eq!(visible.sandbox_claim, target.sandbox_claim);
        assert_eq!(visible.pod, target.pod);
        assert_eq!(visible.namespace, target.namespace);

        // The serialized form is what actually reaches the caller, so assert on
        // it rather than on the struct alone — a field renamed into the wire
        // format later would pass a struct-level check and still leak.
        let json = serde_json::to_string(&visible).unwrap();
        for secret in [
            "kobe-sbx-sbx-1",
            "kobe-abc123",
            "ClusterLease",
            "ClusterInstance",
        ] {
            assert!(!json.contains(secret), "{secret} leaked into {json}");
        }
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
}
