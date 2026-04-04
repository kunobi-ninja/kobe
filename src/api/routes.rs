use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use kube::api::{Api, ListParams, ObjectMeta, Patch as KubePatch, PatchParams, PostParams};
use kube::{Client, ResourceExt};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use crate::api::auth::{AuthIdentity, JwtAuthenticator};
use crate::api::policy::{self, format_duration, is_pool_allowed, policy_for};
use crate::backend::ClusterBackend;
use crate::controllers::claim::extend_lease_ttl;
use crate::crd::{ClusterLease, ClusterLeaseSpec, ClusterPool, LeasePhase, Requester};
use crate::metrics;
use crate::pool::{PoolState, count_states, is_valid_k8s_name, parse_duration};

/// Shared application state for axum routes.
#[derive(Clone)]
pub struct AppState<B: ClusterBackend> {
    pub client: Client,
    pub authenticator: Arc<JwtAuthenticator>,
    pub namespace: String,
    pub pools: Arc<RwLock<std::collections::HashMap<String, PoolState>>>,
    pub backend: B,
}

/// Maximum concurrent API requests. Provides application-level DoS protection.
/// For per-client rate limiting, configure at the ingress controller level.
const MAX_CONCURRENT_API_REQUESTS: usize = 200;

static API_SEMAPHORE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

/// Build the axum router with all API routes.
///
/// API routes have a concurrency limit for DoS protection.
/// Infrastructure routes (/healthz, /metrics) are exempt.
pub fn build_router<B: ClusterBackend + Clone + 'static>(state: AppState<B>) -> Router {
    // Concurrency-limited API routes
    let api_routes = Router::new()
        .route("/v1/leases", post(create_lease::<B>))
        .route("/v1/leases", get(list_leases::<B>))
        .route("/v1/leases/{id}", get(get_lease::<B>))
        .route("/v1/leases/{id}", delete(release_lease::<B>))
        .route("/v1/leases/{id}", patch(extend_lease::<B>))
        .route("/v1/leases/{id}/diagnostics", get(get_diagnostics::<B>))
        .route("/v1/pools", get(list_pools::<B>))
        .route("/v1/pools/{name}", get(get_pool::<B>))
        .layer(axum::middleware::from_fn(concurrency_limit));

    // Non-limited infrastructure routes
    Router::new()
        .merge(api_routes)
        .route("/v1/status", get(status::<B>))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler::<B>))
        .with_state(state)
}

async fn concurrency_limit(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let sem =
        API_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_API_REQUESTS));
    let _permit = match sem.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Server is under heavy load".to_string(),
                    detail: Some("Too many concurrent requests, please retry".to_string()),
                }),
            )
                .into_response();
        }
    };
    next.run(request).await
}

// --- Request/Response types ---

#[derive(Deserialize)]
struct CreateLeaseRequest {
    profile: String,
    #[serde(default)]
    ttl: Option<String>,
}

#[derive(Serialize)]
struct LeaseResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kubeconfig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    phase: String,
    profile: String,
    #[serde(skip_serializing_if = "is_zero")]
    queue_position: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_ttl: Option<String>,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Serialize)]
struct LeaseSummary {
    id: String,
    phase: String,
    profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    queue_position: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics_url: Option<String>,
}

#[derive(Deserialize)]
struct ExtendLeaseRequest {
    extend_ttl: String,
}

#[derive(Serialize)]
struct ExtendLeaseResponse {
    expires_at: String,
}

#[derive(Serialize)]
struct ProfileResponse {
    name: String,
    ready: u32,
    claimed: u32,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

// --- Route handlers ---

#[tracing::instrument(skip_all)]
async fn create_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Json(req): Json<CreateLeaseRequest>,
) -> Response {
    let policy = policy_for(&identity);

    if !is_valid_k8s_name(&req.profile) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid profile name".to_string(),
                detail: Some(
                    "Profile name must be a valid DNS label (lowercase alphanumeric and hyphens, 1-63 chars)"
                        .to_string(),
                ),
            }),
        )
            .into_response();
    }

    if !is_pool_allowed(&req.profile, &policy) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Profile '{}' not allowed for your identity type",
                    req.profile
                ),
                detail: None,
            }),
        )
            .into_response();
    }

    let ttl_str = req.ttl.as_deref().unwrap_or("1h");
    let requested_ttl = match parse_duration(ttl_str) {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid TTL format".to_string(),
                    detail: Some(format!(
                        "Could not parse '{}'. Use format like '30m', '1h', '2h30m'",
                        ttl_str
                    )),
                }),
            )
                .into_response();
        }
    };
    let effective_ttl = policy::clamp_ttl(ttl_str, &policy);
    let was_clamped = effective_ttl < requested_ttl;
    let ttl_formatted = format_duration(&effective_ttl);

    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let active_count = match count_active_leases(&leases_api, &identity.identity).await {
        Ok(count) => count,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Unable to verify lease quota".to_string(),
                    detail: Some(e.to_string()),
                }),
            )
                .into_response();
        }
    };
    if active_count >= policy.max_concurrent_leases {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!(
                    "Concurrent lease limit ({}) reached",
                    policy.max_concurrent_leases
                ),
                detail: Some(format!("You have {} active leases", active_count)),
            }),
        )
            .into_response();
    }

    let lease_id = format!(
        "lease-{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );

    let claim = build_lease_crd(
        &lease_id,
        &state.namespace,
        &req.profile,
        &ttl_formatted,
        &identity,
        policy.default_priority,
    );

    if let Err(e) = leases_api.create(&PostParams::default(), &claim).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create lease".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response();
    }

    metrics::CLAIMS_TOTAL
        .with_label_values(&[req.profile.as_str(), "created"])
        .inc();

    info!(
        lease_id = %lease_id,
        profile = %req.profile,
        identity = %identity.identity,
        priority = policy.default_priority,
        "Lease created, queued for binding"
    );

    let mut resp = LeaseResponse {
        id: lease_id,
        kubeconfig: None,
        expires_at: None,
        phase: "Pending".to_string(),
        profile: req.profile,
        queue_position: 0,
        diagnostics_url: None,
        effective_ttl: None,
    };

    if was_clamped {
        resp.effective_ttl = Some(ttl_formatted);
    }

    (StatusCode::ACCEPTED, Json(resp)).into_response()
}

#[tracing::instrument(skip_all)]
async fn list_leases<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let label_hash = hash_identity(&identity.identity);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/requester-hash={label_hash}"));

    match leases_api.list(&lp).await {
        Ok(claims) => {
            let my_claims: Vec<LeaseSummary> = claims
                .iter()
                .filter(|c| c.spec.requester.identity == identity.identity)
                .map(|c| {
                    let status = c.status.clone().unwrap_or_default();
                    LeaseSummary {
                        id: c.name_any(),
                        phase: status.phase.to_string(),
                        profile: c.spec.pool_ref.clone(),
                        expires_at: status.expires_at,
                        queue_position: status.queue_position,
                        diagnostics_url: status.diagnostics_url,
                    }
                })
                .collect();

            (StatusCode::OK, Json(my_claims)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list leases".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip_all)]
async fn get_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    match leases_api.get(&id).await {
        Ok(claim) => {
            if claim.spec.requester.identity != identity.identity {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Lease not found".to_string(),
                        detail: None,
                    }),
                )
                    .into_response();
            }

            let status = claim.status.clone().unwrap_or_default();

            let kubeconfig = if status.phase == LeasePhase::Bound {
                if let Some(ref cluster_name) = status.cluster_name {
                    match state
                        .backend
                        .extract_kubeconfig(cluster_name, &state.namespace)
                        .await
                    {
                        Ok(kc) => Some(kc),
                        Err(_) => {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(ErrorResponse {
                                    error: "Failed to extract kubeconfig".to_string(),
                                    detail: Some("The cluster may be shutting down".to_string()),
                                }),
                            )
                                .into_response();
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(LeaseResponse {
                    id,
                    kubeconfig,
                    expires_at: status.expires_at,
                    phase: status.phase.to_string(),
                    profile: claim.spec.pool_ref,
                    queue_position: status.queue_position,
                    diagnostics_url: status.diagnostics_url,
                    effective_ttl: None,
                }),
            )
                .into_response()
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Lease not found".to_string(),
                detail: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get lease".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip_all)]
async fn release_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    let claim = match leases_api.get(&id).await {
        Ok(c) => c,
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get lease".to_string(),
                    detail: Some(e.to_string()),
                }),
            )
                .into_response();
        }
    };

    if claim.spec.requester.identity != identity.identity {
        return StatusCode::NOT_FOUND.into_response();
    }

    let status = claim.status.clone().unwrap_or_default();

    if matches!(
        status.phase,
        LeasePhase::Released | LeasePhase::Expired | LeasePhase::Recycling
    ) {
        return StatusCode::NO_CONTENT.into_response();
    }

    let patch = serde_json::json!({
        "status": { "phase": "Released" }
    });
    if let Err(e) = leases_api
        .patch_status(
            &id,
            &PatchParams::apply("kobe-operator"),
            &KubePatch::Merge(&patch),
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to release lease".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response();
    }

    metrics::CLAIMS_TOTAL
        .with_label_values(&[claim.spec.pool_ref.as_str(), "released"])
        .inc();

    if status.phase == LeasePhase::Pending {
        info!(lease_id = %id, "Pending lease cancelled");
    } else {
        info!(lease_id = %id, "Bound lease released");
    }

    StatusCode::NO_CONTENT.into_response()
}

#[tracing::instrument(skip_all)]
async fn extend_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    Json(req): Json<ExtendLeaseRequest>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    match leases_api.get(&id).await {
        Ok(claim) => {
            if claim.spec.requester.identity != identity.identity {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Lease not found".to_string(),
                        detail: None,
                    }),
                )
                    .into_response();
            }
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Lease not found".to_string(),
                    detail: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get lease".to_string(),
                    detail: Some(e.to_string()),
                }),
            )
                .into_response();
        }
    }

    match extend_lease_ttl(
        &state.client,
        &state.namespace,
        &id,
        &req.extend_ttl,
        &state.authenticator,
    )
    .await
    {
        Ok(new_expiry) => (
            StatusCode::OK,
            Json(ExtendLeaseResponse {
                expires_at: new_expiry,
            }),
        )
            .into_response(),
        Err(crate::controllers::claim::LeaseError::Lifecycle(e)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
                detail: None,
            }),
        )
            .into_response(),
        Err(crate::controllers::claim::LeaseError::Kube(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to extend lease".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip_all)]
async fn get_diagnostics<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    match leases_api.get(&id).await {
        Ok(claim) => {
            if claim.spec.requester.identity != identity.identity {
                return StatusCode::NOT_FOUND.into_response();
            }

            let status = claim.status.unwrap_or_default();
            if let Some(url) = status.diagnostics_url {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "url": url,
                        "lease_id": id,
                    })),
                )
                    .into_response()
            } else {
                let message = if matches!(
                    status.phase,
                    LeasePhase::Released | LeasePhase::Expired | LeasePhase::Recycling
                ) {
                    "Diagnostics are being captured, try again shortly"
                } else {
                    "No diagnostics available for this lease"
                };
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: message.to_string(),
                        detail: None,
                    }),
                )
                    .into_response()
            }
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to look up lease".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip_all)]
async fn list_pools<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
) -> Response {
    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);

    match profiles_api.list(&ListParams::default()).await {
        Ok(profiles) => {
            let policy = policy_for(&identity);
            let response: Vec<ProfileResponse> = profiles
                .iter()
                .filter(|p| is_pool_allowed(&p.name_any(), &policy))
                .map(|p| {
                    let status = p.status.clone().unwrap_or_default();
                    ProfileResponse {
                        name: p.name_any(),
                        ready: status.ready,
                        claimed: status.claimed,
                    }
                })
                .collect();

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list profiles".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip_all)]
async fn get_pool<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(name): Path<String>,
) -> Response {
    let policy = policy_for(&identity);
    if !is_pool_allowed(&name, &policy) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);

    match profiles_api.get(&name).await {
        Ok(profile) => {
            let status = profile.status.unwrap_or_default();
            (
                StatusCode::OK,
                Json(ProfileResponse {
                    name,
                    ready: status.ready,
                    claimed: status.claimed,
                }),
            )
                .into_response()
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Profile not found".to_string(),
                detail: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get profile".to_string(),
                detail: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

/// GET /v1/status — public endpoint, no auth required.
/// Returns version, auth methods, active sessions (if token provided), and accessible pools.
async fn status<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let methods = state.authenticator.auth_methods().await;

    // Try to authenticate if a token is provided (optional)
    let session = if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                match state.authenticator.validate(token).await {
                    Ok(identity) => {
                        let pools = accessible_pools(&state, &identity).await;
                        Some(StatusSession {
                            method: "oidc".to_string(),
                            identity: identity.identity,
                            pools,
                            expires_at: None,
                        })
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let sessions = session.into_iter().collect::<Vec<_>>();

    // Pools — only show pools the caller can access
    let pool_infos = if sessions.is_empty() {
        vec![]
    } else {
        let pools = state.pools.read().await;
        pools
            .iter()
            .map(|(name, pool_state)| {
                let counts = count_states(pool_state);
                StatusPool {
                    name: name.clone(),
                    ready: counts.ready,
                    claimed: counts.claimed,
                    total: counts.ready + counts.claimed + counts.creating,
                }
            })
            .filter(|p| {
                sessions
                    .iter()
                    .any(|s| s.pools.iter().any(|pattern| pool_matches(&p.name, pattern)))
            })
            .collect()
    };

    Json(StatusResponse {
        version: std::env::var("BUILD_VERSION")
            .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string()),
        auth: AuthStatusBlock { methods, sessions },
        pools: pool_infos,
    })
    .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    version: String,
    auth: AuthStatusBlock,
    pools: Vec<StatusPool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthStatusBlock {
    methods: Vec<crate::api::auth::AuthMethodInfo>,
    sessions: Vec<StatusSession>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSession {
    method: String,
    identity: String,
    pools: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusPool {
    name: String,
    ready: u32,
    claimed: u32,
    total: u32,
}

/// Get the list of pool name patterns this identity can access.
async fn accessible_pools<B: ClusterBackend>(
    state: &AppState<B>,
    identity: &AuthIdentity,
) -> Vec<String> {
    if let Some(policy) = state
        .authenticator
        .policy_for_requester_type(&identity.requester_type)
        .await
    {
        policy.allowed_pools
    } else {
        vec![]
    }
}

/// Check if a pool name matches a pattern.
fn pool_matches(pool: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return pool.starts_with(prefix);
    }
    pool == pattern
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn metrics_handler<B: ClusterBackend>(State(state): State<AppState<B>>) -> Response {
    let pools = state.pools.read().await;
    metrics::POOL_CLUSTERS.reset();
    metrics::QUEUE_DEPTH.reset();

    for (profile, pool_state) in pools.iter() {
        let counts = count_states(pool_state);
        metrics::POOL_CLUSTERS
            .with_label_values(&[profile.as_str(), "creating"])
            .set(counts.creating as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[profile.as_str(), "ready"])
            .set(counts.ready as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[profile.as_str(), "claimed"])
            .set(counts.claimed as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[profile.as_str(), "unhealthy"])
            .set(counts.unhealthy as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[profile.as_str(), "recycling"])
            .set(counts.recycling as i64);
    }
    drop(pools);

    let body = metrics::gather();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

// --- Helpers ---

async fn count_active_leases(
    leases_api: &Api<ClusterLease>,
    identity: &str,
) -> Result<u32, kube::Error> {
    let label_hash = hash_identity(identity);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/requester-hash={label_hash}"));
    let claims = leases_api.list(&lp).await?;
    Ok(claims
        .iter()
        .filter(|c| c.spec.requester.identity == identity)
        .filter(|c| {
            let status = c.status.clone().unwrap_or_default();
            matches!(status.phase, LeasePhase::Pending | LeasePhase::Bound)
        })
        .count() as u32)
}

fn build_lease_crd(
    lease_id: &str,
    namespace: &str,
    profile: &str,
    ttl: &str,
    identity: &AuthIdentity,
    priority: u32,
) -> ClusterLease {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/profile".to_string(), profile.to_string());
    labels.insert(
        "kobe.kunobi.ninja/requester-hash".to_string(),
        hash_identity(&identity.identity),
    );

    ClusterLease {
        metadata: ObjectMeta {
            name: Some(lease_id.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: ClusterLeaseSpec {
            pool_ref: profile.to_string(),
            ttl: ttl.to_string(),
            requester: Requester {
                requester_type: identity.requester_type.clone(),
                identity: identity.identity.clone(),
            },
            priority,
        },
        status: None,
    }
}

fn hash_identity(identity: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET;
    for byte in identity.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_identity_deterministic() {
        let id = "repo:zondax/kunobi:ref:refs/heads/main";
        let h1 = hash_identity(id);
        let h2 = hash_identity(id);
        assert_eq!(h1, h2, "Hash must be deterministic");
    }

    #[test]
    fn test_hash_identity_stable_values() {
        assert_eq!(hash_identity("test"), "f9e6e6ef197c2b25");
        assert_eq!(hash_identity(""), "cbf29ce484222325");
    }

    #[test]
    fn test_hash_identity_is_valid_label() {
        let hash = hash_identity("user_12345@example.com");
        assert!(hash.len() <= 63);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_identity_different_inputs() {
        assert_ne!(hash_identity("alice"), hash_identity("bob"));
        assert_ne!(hash_identity("a"), hash_identity("b"));
    }

    // --- build_lease_crd tests ---

    fn test_identity() -> AuthIdentity {
        AuthIdentity {
            requester_type: "github-actions:ci".to_string(),
            identity: "repo:org/repo:ref:refs/heads/main".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            policy: crate::api::policy::Policy {
                allowed_pools: vec!["e2e-*".to_string()],
                max_ttl: chrono::Duration::hours(2),
                max_concurrent_leases: 5,
                default_priority: 100,
                max_extensions: 2,
            },
        }
    }

    #[test]
    fn test_build_lease_crd_basic() {
        let identity = test_identity();
        let claim = build_lease_crd("lease-abc123", "test-ns", "e2e-basic", "1h", &identity, 80);

        assert_eq!(claim.spec.pool_ref, "e2e-basic");
        assert_eq!(claim.spec.ttl, "1h");
        assert_eq!(claim.spec.priority, 80);
        assert_eq!(
            claim.spec.requester.identity,
            "repo:org/repo:ref:refs/heads/main"
        );
        assert_eq!(claim.spec.requester.requester_type, "github-actions:ci");

        // Metadata
        assert_eq!(claim.metadata.name.as_deref(), Some("lease-abc123"));
        assert_eq!(claim.metadata.namespace.as_deref(), Some("test-ns"));
    }

    #[test]
    fn test_build_lease_crd_labels() {
        let identity = test_identity();
        let claim = build_lease_crd("lease-xyz", "ns1", "e2e-full", "30m", &identity, 50);

        let labels = claim
            .metadata
            .labels
            .as_ref()
            .expect("labels should be set");
        assert_eq!(
            labels.get("kobe.kunobi.ninja/profile"),
            Some(&"e2e-full".to_string())
        );
        // The requester-hash label should match hash_identity of the identity string
        let expected_hash = hash_identity(&identity.identity);
        assert_eq!(
            labels.get("kobe.kunobi.ninja/requester-hash"),
            Some(&expected_hash)
        );
    }

    #[test]
    fn test_build_lease_crd_status_is_none() {
        let identity = test_identity();
        let claim = build_lease_crd("lease-001", "ns", "dev", "2h", &identity, 100);

        // The CRD is created without status; the controller sets it later
        assert!(
            claim.status.is_none(),
            "Initial lease CRD should have no status"
        );
    }

    #[test]
    fn test_build_lease_crd_different_priority() {
        let identity = test_identity();
        let claim_low = build_lease_crd("c1", "ns", "p", "1h", &identity, 10);
        let claim_high = build_lease_crd("c2", "ns", "p", "1h", &identity, 200);

        assert_eq!(claim_low.spec.priority, 10);
        assert_eq!(claim_high.spec.priority, 200);
    }

    // --- Router / handler tests using tower::ServiceExt::oneshot ---

    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Helper: build an axum Router backed by MockBackend and wiremock.
    async fn test_app() -> (Router, wiremock::MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let pools = Arc::new(RwLock::new(HashMap::new()));
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new());

        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            pools,
            authenticator,
        };

        (build_router(state), server)
    }

    #[tokio::test]
    async fn test_healthz_returns_200() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_returns_200() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify content-type header
        let ct = resp
            .headers()
            .get("content-type")
            .expect("metrics should have content-type header")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/plain"),
            "Expected text/plain content-type, got: {ct}"
        );
    }

    // --- Auth-protected endpoints return 401 without Authorization header ---

    #[tokio::test]
    async fn test_create_lease_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .method("POST")
            .uri("/v1/leases")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"profile":"e2e-basic"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST /v1/leases without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_list_leases_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/leases")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /v1/leases without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_list_pools_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/pools")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /v1/pools without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_get_lease_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/leases/lease-123")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /v1/leases/:id without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_delete_claim_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .method("DELETE")
            .uri("/v1/leases/lease-123")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE /v1/leases/:id without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_extend_lease_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .method("PATCH")
            .uri("/v1/leases/lease-123")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"extend_ttl":"30m"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "PATCH /v1/leases/:id without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_get_pool_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/pools/e2e-basic")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /v1/pools/:name without auth should return 401"
        );
    }

    #[tokio::test]
    async fn test_get_diagnostics_requires_auth() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/leases/lease-123/diagnostics")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /v1/leases/:id/diagnostics without auth should return 401"
        );
    }

    // --- Invalid Bearer token returns 401 ---

    #[tokio::test]
    async fn test_invalid_bearer_token_returns_401() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/leases")
            .header("Authorization", "Bearer invalid-token")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Invalid Bearer token should return 401"
        );
    }

    // --- Non-Bearer Authorization header returns 401 ---

    #[tokio::test]
    async fn test_non_bearer_auth_returns_401() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/v1/leases")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Non-Bearer auth scheme should return 401"
        );
    }

    // --- count_active_leases tests ---

    #[tokio::test]
    async fn test_count_active_leases_empty() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        // Mock K8s LIST returning empty list
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let empty_list = crate::testutil::k8s_list_response::<serde_json::Value>(vec![]);
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&empty_list))
            .mount(&server)
            .await;

        let leases_api: kube::api::Api<ClusterLease> =
            kube::api::Api::namespaced(client, "test-ns");
        let count = count_active_leases(&leases_api, "test-identity")
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_count_active_leases_filters_correctly() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        let identity = "repo:org/repo:ref:refs/heads/main";

        // Build claims in various phases
        let claims = vec![
            // Pending — should count
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "c1", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "e2e-basic",
                    "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": identity },
                    "priority": 50
                },
                "status": { "phase": "Pending" }
            }),
            // Bound — should count
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "c2", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "e2e-basic",
                    "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": identity },
                    "priority": 50
                },
                "status": { "phase": "Bound" }
            }),
            // Released — should NOT count
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "c3", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "e2e-basic",
                    "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": identity },
                    "priority": 50
                },
                "status": { "phase": "Released" }
            }),
            // Expired — should NOT count
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "c4", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "e2e-basic",
                    "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": identity },
                    "priority": 50
                },
                "status": { "phase": "Expired" }
            }),
            // Different identity — should NOT count
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "c5", "namespace": "test-ns" },
                "spec": {
                    "poolRef": "e2e-basic",
                    "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": "repo:other/repo:ref:refs/heads/main" },
                    "priority": 50
                },
                "status": { "phase": "Pending" }
            }),
        ];

        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let list_resp = crate::testutil::k8s_list_response(claims);
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&list_resp))
            .mount(&server)
            .await;

        let leases_api: kube::api::Api<ClusterLease> =
            kube::api::Api::namespaced(client, "test-ns");
        let count = count_active_leases(&leases_api, identity).await.unwrap();
        // Only c1 (Pending) and c2 (Bound) for the matching identity
        assert_eq!(count, 2);
    }

    // --- Unknown route returns 404 ---

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/nonexistent")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // --- is_zero helper ---

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&0));
        assert!(!is_zero(&1));
        assert!(!is_zero(&100));
    }
}
