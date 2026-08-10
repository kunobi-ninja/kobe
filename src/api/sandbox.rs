//! HTTP admission for caller-safe [`SandboxLease`](crate::crd::SandboxLease)
//! intent.
//!
//! The routes in this module deliberately stop at admission and lifecycle
//! intent. They never resolve a target cluster, return Kubernetes credentials,
//! or expose upstream Agent Sandbox objects. Placement controllers in #73/#74
//! own those transitions.

use axum::extract::{Path, State};
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
use tracing::{error, info};

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
const SANDBOX_RESERVATION_LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-uid";
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

    if let Err(err) = admit_sandbox_lease(&leases, &created).await {
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
        return match delete_exact_pending_lease(&leases, &lease).await {
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
        target: status.target,
        conditions: status.conditions,
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

/// Stable, non-reversible label value used only as a server-side prefilter.
/// Exact identity is always rechecked from the object, so hash collision never
/// grants visibility or consumes another caller's quota.
fn principal_hash(identity: &AuthIdentity) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut hash = FNV_OFFSET;
    for component in [
        identity.provider.as_bytes(),
        identity.issuer.as_bytes(),
        identity.identity.as_bytes(),
    ] {
        for byte in (component.len() as u64)
            .to_be_bytes()
            .iter()
            .chain(component)
        {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    format!("{hash:016x}")
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
                    delete_exact_pending_lease(leases, &current).await?;
                    Err(SandboxLeaseMutationError::AdmissionNotCommitted)
                }
                _ => Err(SandboxLeaseMutationError::UnexpectedAdmissionState),
            }
        }
    }
}

async fn delete_exact_pending_lease(
    leases: &Api<SandboxLease>,
    lease: &SandboxLease,
) -> Result<(), SandboxLeaseMutationError> {
    let expected_uid = lease.uid().ok_or(SandboxLeaseMutationError::MissingUid)?;
    let current = match leases.get(&lease.name_any()).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
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
            uid: Some(expected_uid),
            resource_version: Some(resource_version),
        }),
        ..Default::default()
    };
    leases.delete(&current.name_any(), &params).await?;
    Ok(())
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
enum SandboxLeaseMutationError {
    #[error("SandboxLease has no UID")]
    MissingUid,
    #[error("SandboxLease has no resourceVersion")]
    MissingResourceVersion,
    #[error("current SandboxLease was absent from the admission verification list")]
    CurrentLeaseMissing,
    #[error("current SandboxLease appeared more than once in the admission verification list")]
    DuplicateCurrentLease,
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

    fn sandbox_lease_from_json(mut value: serde_json::Value, admission: &str) -> SandboxLease {
        value["metadata"]["annotations"][SANDBOX_ADMISSION_ANNOTATION] =
            serde_json::json!(admission);
        serde_json::from_value(value).unwrap()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn mount_create_api(
        server: &MockServer,
        relist_created: bool,
        ambiguous_admit_response: bool,
    ) -> Arc<Mutex<Option<serde_json::Value>>> {
        let lease_state = Arc::new(Mutex::new(None::<serde_json::Value>));
        mount_sandbox_crds(server).await;
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

    #[test]
    fn quota_race_resolution_is_deterministic() {
        let pending = sandbox_lease_from_json(
            lease_json("sandbox-a", "alice@example.com", "Pending"),
            SANDBOX_ADMISSION_PENDING,
        );
        let admitted = sandbox_lease_from_json(
            lease_json("sandbox-z", "alice@example.com", "Pending"),
            SANDBOX_ADMISSION_ADMITTED,
        );
        let active = vec![admitted, pending.clone()];
        assert!(lease_exceeds_quota(&active, &pending, 1).unwrap());
        assert!(matches!(
            lease_exceeds_quota(
                &active,
                &sandbox_lease_from_json(
                    lease_json("sandbox-missing", "alice@example.com", "Pending"),
                    SANDBOX_ADMISSION_PENDING,
                ),
                2
            ),
            Err(SandboxLeaseMutationError::CurrentLeaseMissing)
        ));
    }

    #[test]
    fn principal_hash_separates_providers_and_issuers() {
        let base = identity();
        let mut other_provider = base.clone();
        other_provider.provider = "other-oidc".into();
        let mut other_issuer = base.clone();
        other_issuer.issuer = "https://other.example".into();
        assert_ne!(principal_hash(&base), principal_hash(&other_provider));
        assert_ne!(principal_hash(&base), principal_hash(&other_issuer));
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

    #[tokio::test]
    async fn create_fails_closed_and_removes_lease_missing_from_relist() {
        let server = MockServer::start().await;
        mount_create_api(&server, false, false).await;

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
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method.as_str() == "DELETE")
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
