use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::body::{self, Body};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post};
use axum::{Json, Router};
use futures::TryStreamExt;
use http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST};
use kube::api::{Api, ListParams, ObjectMeta, Patch as KubePatch, PatchParams, PostParams};
use kube::{Client, ResourceExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::api::auth::{AuthIdentity, JwtAuthenticator};
use crate::api::connect::{
    backend_access_from_kubeconfig, build_connect_kubeconfig, ensure_lease_connect_token,
    validate_lease_connect_token,
};
use crate::api::policy::{self, format_duration, is_pool_allowed, policy_for};
use crate::backend::{BackendFactory, ClusterBackend};
use crate::controllers::lease::extend_lease_ttl;
use crate::crd::{ClusterLease, ClusterLeaseSpec, ClusterPool, LeasePhase, Requester};
use crate::metrics;
use crate::pool::{is_valid_k8s_name, parse_duration};
use kunobi_auth::server::{AuthnProvider, OptionalAuth};

/// Shared application state for axum routes.
#[derive(Clone)]
pub struct AppState<B: ClusterBackend> {
    pub client: Client,
    pub authenticator: Arc<JwtAuthenticator>,
    pub namespace: String,
    pub backend: B,
    pub factory: Option<BackendFactory>,
    /// Shared PostgreSQL pool when one is configured; `None` in
    /// embedded-datastore mode. Consulted by the `/readyz` probe.
    pub pg_pool: Option<sqlx::PgPool>,
}

/// Implement kunobi-auth's AuthnProvider so that RequiredAuth/OptionalAuth extractors work.
///
/// This bridges kobe's multi-provider JwtAuthenticator into kunobi-auth's generic auth model.
/// Kobe-specific policy resolution is NOT included here — it stays in kobe's own AuthIdentity extractor.
impl<B: ClusterBackend + Clone + Send + Sync + 'static> AuthnProvider for AppState<B> {
    async fn authenticate(
        &self,
        token: &str,
    ) -> Result<kunobi_auth::AuthIdentity, kunobi_auth::AuthError> {
        let kobe_identity = self
            .authenticator
            .validate(token)
            .await
            .map_err(|e| kunobi_auth::AuthError::Unauthorized(e.to_string()))?;

        let method = if kobe_identity.issuer == "token" {
            "token"
        } else {
            "oidc"
        };

        Ok(kunobi_auth::AuthIdentity {
            provider: kobe_identity.requester_type,
            identity: kobe_identity.identity,
            method: method.to_string(),
            claims: std::collections::HashMap::new(),
        })
    }
}

/// Maximum concurrent API requests. Provides application-level DoS protection.
/// For per-client rate limiting, configure at the ingress controller level.
const MAX_CONCURRENT_API_REQUESTS: usize = 200;
const CONNECT_PROXY_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const CONNECT_PROXY_LOG_BODY_LIMIT: usize = 256;
const CONNECT_PROXY_LOG_HEADER_LIMIT: usize = 12;
const REQUEST_ID_HEADER: &str = "x-request-id";

static API_SEMAPHORE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut rendered = err.to_string();
    let mut current = err.source();
    while let Some(source) = current {
        rendered.push_str(": ");
        rendered.push_str(&source.to_string());
        current = source.source();
    }
    rendered
}

/// Build the axum router with all API routes.
///
/// API routes have a concurrency limit for DoS protection.
/// Infrastructure routes (/livez, /readyz, /healthz, /metrics) are exempt.
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
        .route("/v1/pools/{name}/leases", get(list_pool_leases::<B>))
        .layer(axum::middleware::from_fn(concurrency_limit));

    let connect_routes = Router::new()
        .route("/connect/{id}", any(connect_proxy_root::<B>))
        .route("/connect/{id}/{*path}", any(connect_proxy::<B>));

    // Non-limited infrastructure routes
    Router::new()
        .merge(api_routes)
        .merge(connect_routes)
        .route("/v1/status", get(status::<B>))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz::<B>))
        // Back-compat alias for liveness — kept so external monitoring
        // pointed at the old path keeps working. New probes use /livez.
        .route("/healthz", get(livez))
        .route("/metrics", get(metrics_handler::<B>))
        .layer(axum::middleware::from_fn(request_logging))
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

async fn request_logging(mut request: axum::extract::Request, next: Next) -> Response {
    let request_id = request_id_from_headers(request.headers())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let started = Instant::now();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    let mut response = next.run(request).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let status = response.status();

    if !matches!(
        path.as_str(),
        "/livez" | "/readyz" | "/healthz" | "/metrics"
    ) {
        if status.is_server_error() {
            warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                latency_ms,
                "HTTP request completed with server error"
            );
        } else {
            info!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                latency_ms,
                "HTTP request completed"
            );
        }
    }

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    response
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
    cluster_name: Option<String>,
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
    cluster_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    queue_position: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics_url: Option<String>,
    /// Requester identity (included in pool lease listings).
    #[serde(skip_serializing_if = "Option::is_none")]
    requester: Option<String>,
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
#[serde(rename_all = "camelCase")]
struct PoolPolicyResponse {
    mode: String,
    ttl: String,
    warm_target: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_clusters: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scale_up_threshold: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scale_down_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_timeout: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileResponse {
    name: String,
    ready: u32,
    leased: u32,
    creating: u32,
    recycling: u32,
    unhealthy: u32,
    queue_depth: u32,
    policy: PoolPolicyResponse,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn pool_policy_response(profile: &ClusterPool) -> PoolPolicyResponse {
    if let Some(scaling) = &profile.spec.scaling {
        PoolPolicyResponse {
            mode: "autoscaled".to_string(),
            ttl: profile.spec.ttl.clone(),
            warm_target: scaling.min_ready,
            max_clusters: Some(scaling.max_clusters),
            scale_up_threshold: Some(scaling.scale_up_threshold),
            scale_down_after: Some(scaling.scale_down_after.clone()),
            queue_timeout: Some(scaling.queue_timeout.clone()),
        }
    } else {
        PoolPolicyResponse {
            mode: "fixed".to_string(),
            ttl: profile.spec.ttl.clone(),
            warm_target: profile.spec.size,
            max_clusters: None,
            scale_up_threshold: None,
            scale_down_after: None,
            queue_timeout: None,
        }
    }
}

fn profile_response(profile: &ClusterPool) -> ProfileResponse {
    let status = profile.status.clone().unwrap_or_default();
    ProfileResponse {
        name: profile.name_any(),
        ready: status.ready,
        leased: status.leased,
        creating: status.creating,
        recycling: status.recycling,
        unhealthy: status.unhealthy,
        queue_depth: status.queue_depth,
        policy: pool_policy_response(profile),
    }
}

fn connect_error(status: StatusCode, message: impl Into<String>) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(message.into()))
        .expect("connect error response")
}

fn request_id_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers.get(REQUEST_ID_HEADER).and_then(|v| v.to_str().ok())
}

fn summarize_response_body(bytes: &bytes::Bytes) -> String {
    let body = String::from_utf8_lossy(bytes);
    let mut snippet = String::with_capacity(body.len().min(CONNECT_PROXY_LOG_BODY_LIMIT));
    let mut used = 0usize;

    for ch in body.chars() {
        let ch = if ch.is_control() && ch != '\n' && ch != '\t' {
            ' '
        } else {
            ch
        };
        let ch_len = ch.len_utf8();
        if used + ch_len > CONNECT_PROXY_LOG_BODY_LIMIT {
            snippet.push_str("...");
            break;
        }
        snippet.push(ch);
        used += ch_len;
    }

    snippet.replace('\n', "\\n")
}

fn summarize_headers(headers: &HeaderMap) -> String {
    let mut rendered = headers
        .iter()
        .take(CONNECT_PROXY_LOG_HEADER_LIMIT)
        .map(|(name, value)| {
            let value = value
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!(
                "{name}={}",
                summarize_response_body(&bytes::Bytes::from(value))
            )
        })
        .collect::<Vec<_>>();

    if headers.len() > CONNECT_PROXY_LOG_HEADER_LIMIT {
        rendered.push(format!(
            "...+{} more",
            headers.len() - CONNECT_PROXY_LOG_HEADER_LIMIT
        ));
    }

    rendered.join(", ")
}

fn verbose_connect_proxy_logging(path: &str, status_code: StatusCode) -> bool {
    matches!(path, "/api" | "/apis" | "/version") || !status_code.is_success()
}

fn header_value<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn connect_server_url(headers: &HeaderMap, lease_id: &str) -> anyhow::Result<String> {
    let host = header_value(headers, "x-forwarded-host")
        .or_else(|| header_value(headers, HOST.as_str()))
        .ok_or_else(|| anyhow::anyhow!("Missing Host header"))?;
    let scheme = header_value(headers, "x-forwarded-proto").unwrap_or_else(|| {
        if host.starts_with("localhost")
            || host.starts_with("127.0.0.1")
            || host.starts_with("[::1]")
        {
            "http"
        } else {
            "https"
        }
    });
    Ok(format!("{scheme}://{host}/connect/{lease_id}"))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn should_skip_request_header(name: &HeaderName) -> bool {
    name == HOST || name == AUTHORIZATION || name == CONTENT_LENGTH || name == CONNECTION
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn backend_request_url(
    base_server: &str,
    proxied_path: &str,
    raw_query: Option<&str>,
) -> anyhow::Result<String> {
    let mut url = url::Url::parse(base_server)
        .with_context(|| format!("Invalid backend server URL: {base_server}"))?;
    let base_path = url.path().trim_end_matches('/');
    let normalized_path = proxied_path.trim_start_matches('/');
    let new_path = if normalized_path.is_empty() {
        if base_path.is_empty() {
            "/".to_string()
        } else {
            base_path.to_string()
        }
    } else if base_path.is_empty() {
        format!("/{normalized_path}")
    } else {
        format!("{base_path}/{normalized_path}")
    };
    url.set_path(&new_path);
    url.set_query(raw_query);
    Ok(url.to_string())
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

    let lease = build_lease_crd(
        &lease_id,
        &state.namespace,
        &req.profile,
        &ttl_formatted,
        &identity,
        policy.default_priority,
    );

    if let Err(e) = leases_api.create(&PostParams::default(), &lease).await {
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
        cluster_name: None,
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
                        cluster_name: status.cluster_name,
                        expires_at: status.expires_at,
                        queue_position: status.queue_position,
                        diagnostics_url: status.diagnostics_url,
                        requester: None,
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
    headers: HeaderMap,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    match leases_api.get(&id).await {
        Ok(lease) => {
            if lease.spec.requester.identity != identity.identity {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Lease not found".to_string(),
                        detail: None,
                    }),
                )
                    .into_response();
            }

            let status = lease.status.clone().unwrap_or_default();

            let kubeconfig = if status.phase == LeasePhase::Bound {
                if let Some(ref cluster_name) = status.cluster_name {
                    match connect_server_url(&headers, &id) {
                        Ok(server_url) => match ensure_lease_connect_token(
                            &state.client,
                            &state.namespace,
                            &lease,
                        )
                        .await
                        {
                            Ok(connect_token) => {
                                match build_connect_kubeconfig(
                                    &server_url,
                                    &id,
                                    Some(cluster_name),
                                    &connect_token,
                                ) {
                                    Ok(kubeconfig) => Some(kubeconfig),
                                    Err(err) => {
                                        return (
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            Json(ErrorResponse {
                                                error: "Failed to build lease kubeconfig"
                                                    .to_string(),
                                                detail: Some(err.to_string()),
                                            }),
                                        )
                                            .into_response();
                                    }
                                }
                            }
                            Err(err) => {
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "Failed to provision lease access token".to_string(),
                                        detail: Some(err.to_string()),
                                    }),
                                )
                                    .into_response();
                            }
                        },
                        Err(_) => {
                            // A missing/oddly-proxied Host header is a client/proxy
                            // problem, not a server outage — no amount of retry
                            // fixes it, so return 400 rather than 503 (which would
                            // trip availability alerting and retry loops).
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    error: "Failed to determine public connect endpoint"
                                        .to_string(),
                                    detail: Some(
                                        "The request did not include a usable Host header"
                                            .to_string(),
                                    ),
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
                    cluster_name: status.cluster_name,
                    expires_at: status.expires_at,
                    phase: status.phase.to_string(),
                    profile: lease.spec.pool_ref,
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
async fn connect_proxy_root<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    raw_query: RawQuery,
    body: Body,
) -> Response {
    connect_proxy_inner(state, id, String::new(), method, headers, raw_query, body).await
}

#[tracing::instrument(skip_all)]
async fn connect_proxy<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    Path((id, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    raw_query: RawQuery,
    body: Body,
) -> Response {
    connect_proxy_inner(state, id, path, method, headers, raw_query, body).await
}

async fn connect_proxy_inner<B: ClusterBackend>(
    state: AppState<B>,
    lease_id: String,
    path: String,
    method: Method,
    headers: HeaderMap,
    raw_query: RawQuery,
    body: Body,
) -> Response {
    let request_id = request_id_from_headers(&headers).unwrap_or("-");
    let request_path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path)
    };

    debug!(
        request_id = %request_id,
        lease_id = %lease_id,
        method = %method,
        path = %request_path,
        "Connect proxy request received"
    );

    let Some(connect_token) = extract_bearer_token(&headers) else {
        warn!(
            request_id = %request_id,
            lease_id = %lease_id,
            method = %method,
            path = %request_path,
            "Connect proxy rejected request without bearer token"
        );
        return connect_error(StatusCode::UNAUTHORIZED, "Missing Bearer token");
    };

    let token_is_valid = match validate_lease_connect_token(
        &state.client,
        &state.namespace,
        &lease_id,
        connect_token,
    )
    .await
    {
        Ok(valid) => valid,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                error = %err,
                "Connect proxy failed to validate lease token"
            );
            return connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to validate lease token: {err}"),
            );
        }
    };

    if !token_is_valid {
        warn!(
            request_id = %request_id,
            lease_id = %lease_id,
            method = %method,
            path = %request_path,
            "Connect proxy rejected invalid lease token"
        );
        return connect_error(StatusCode::UNAUTHORIZED, "Invalid lease token");
    }

    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let lease = match leases_api.get(&lease_id).await {
        Ok(lease) => lease,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                "Connect proxy lease not found"
            );
            return connect_error(StatusCode::NOT_FOUND, "Lease not found");
        }
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                error = %err,
                "Connect proxy failed to load lease"
            );
            return connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load lease: {err}"),
            );
        }
    };

    let status = lease.status.clone().unwrap_or_default();
    if status.phase != LeasePhase::Bound {
        warn!(
            request_id = %request_id,
            lease_id = %lease_id,
            phase = %status.phase,
            "Connect proxy rejected lease outside Bound phase"
        );
        return connect_error(
            StatusCode::CONFLICT,
            format!("Lease is not active (phase {})", status.phase),
        );
    }

    let Some(cluster_name) = status.cluster_name.as_deref() else {
        warn!(
            request_id = %request_id,
            lease_id = %lease_id,
            "Connect proxy found bound lease without cluster name"
        );
        return connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Lease is bound without a cluster name",
        );
    };

    let mut chosen_backend = "fallback".to_string();
    let raw_kubeconfig = if let Some(factory) = state.factory.as_ref() {
        let pools_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
        match pools_api.get(&lease.spec.pool_ref).await {
            Ok(pool) => {
                chosen_backend = format!("{:?}", pool.spec.backend.backend_type);
                match factory.backend_for(&pool) {
                    Ok(backend) => match backend
                        .extract_kubeconfig(cluster_name, &state.namespace)
                        .await
                    {
                        Ok(kubeconfig) => kubeconfig,
                        Err(err) => {
                            warn!(
                                request_id = %request_id,
                                lease_id = %lease_id,
                                pool = %lease.spec.pool_ref,
                                cluster = %cluster_name,
                                backend = %chosen_backend,
                                error = %err,
                                "Connect proxy failed to extract backend kubeconfig"
                            );
                            return connect_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                format!("Failed to extract backend kubeconfig: {err}"),
                            );
                        }
                    },
                    Err(err) => {
                        warn!(
                            request_id = %request_id,
                            lease_id = %lease_id,
                            pool = %lease.spec.pool_ref,
                            cluster = %cluster_name,
                            error = %err,
                            "Connect proxy failed to resolve backend for pool, falling back"
                        );
                        chosen_backend = "fallback".to_string();
                        match state
                            .backend
                            .extract_kubeconfig(cluster_name, &state.namespace)
                            .await
                        {
                            Ok(kubeconfig) => kubeconfig,
                            Err(err) => {
                                warn!(
                                    request_id = %request_id,
                                    lease_id = %lease_id,
                                    cluster = %cluster_name,
                                    error = %err,
                                    "Connect proxy failed to extract backend kubeconfig"
                                );
                                return connect_error(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    format!("Failed to extract backend kubeconfig: {err}"),
                                );
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    pool = %lease.spec.pool_ref,
                    cluster = %cluster_name,
                    error = %err,
                    "Connect proxy failed to load pool for backend resolution, falling back"
                );
                match state
                    .backend
                    .extract_kubeconfig(cluster_name, &state.namespace)
                    .await
                {
                    Ok(kubeconfig) => kubeconfig,
                    Err(err) => {
                        warn!(
                            request_id = %request_id,
                            lease_id = %lease_id,
                            cluster = %cluster_name,
                            error = %err,
                            "Connect proxy failed to extract backend kubeconfig"
                        );
                        return connect_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("Failed to extract backend kubeconfig: {err}"),
                        );
                    }
                }
            }
        }
    } else {
        match state
            .backend
            .extract_kubeconfig(cluster_name, &state.namespace)
            .await
        {
            Ok(kubeconfig) => kubeconfig,
            Err(err) => {
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    cluster = %cluster_name,
                    error = %err,
                    "Connect proxy failed to extract backend kubeconfig"
                );
                return connect_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Failed to extract backend kubeconfig: {err}"),
                );
            }
        }
    };

    let backend = match backend_access_from_kubeconfig(&raw_kubeconfig) {
        Ok(backend) => backend,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                cluster = %cluster_name,
                error = %err,
                "Connect proxy failed to parse backend kubeconfig"
            );
            return connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse backend kubeconfig: {err}"),
            );
        }
    };

    let request_url = match backend_request_url(&backend.server, &path, raw_query.0.as_deref()) {
        Ok(url) => url,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                cluster = %cluster_name,
                error = %err,
                "Connect proxy failed to build backend request URL"
            );
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    };

    info!(
        request_id = %request_id,
        lease_id = %lease_id,
        pool = %lease.spec.pool_ref,
        cluster = %cluster_name,
        backend = %chosen_backend,
        upstream = %backend.server,
        method = %method,
        path = %request_path,
        query = raw_query.0.as_deref().unwrap_or(""),
        "Connect proxy forwarding request upstream"
    );

    let body_bytes = match body::to_bytes(body, CONNECT_PROXY_MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                cluster = %cluster_name,
                error = %err,
                "Connect proxy failed to read request body"
            );
            return connect_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Failed to read request body: {err}"),
            );
        }
    };

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                method = %method,
                path = %request_path,
                error = %err,
                "Connect proxy received unsupported HTTP method"
            );
            return connect_error(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("Unsupported method: {err}"),
            );
        }
    };

    let mut request = backend
        .client
        .request(reqwest_method, request_url)
        .body(body_bytes.clone());
    for (name, value) in &headers {
        if should_skip_request_header(name) {
            continue;
        }
        request = request.header(name, value.clone());
    }
    if let Some(token) = backend.bearer_token.as_deref() {
        request = request.bearer_auth(token);
    }

    let backend_response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            warn!(
                request_id = %request_id,
                lease_id = %lease_id,
                cluster = %cluster_name,
                upstream = %backend.server,
                method = %method,
                path = %request_path,
                error = %error_chain(&err),
                "Connect proxy failed to reach leased cluster"
            );
            return connect_error(
                StatusCode::BAD_GATEWAY,
                format!("Failed to reach leased cluster: {err}"),
            );
        }
    };

    let status_code = backend_response.status();
    let response_headers = backend_response.headers().clone();
    let response_header_summary = summarize_headers(&response_headers);

    let mut response = Response::builder().status(status_code);
    let mut stripped_headers = Vec::new();
    let mut forwarded_headers = Vec::new();
    if let Some(headers_mut) = response.headers_mut() {
        for (name, value) in &response_headers {
            if should_skip_response_header(name) {
                stripped_headers.push(name.to_string());
                continue;
            }
            headers_mut.append(name, value.clone());
            forwarded_headers.push(name.to_string());
        }
    }

    // Server errors are bounded and useful to log as full bodies. Stream every
    // other response so long-poll endpoints (Kubernetes watches, SSE) are not
    // buffered — buffering here would hang `kubectl -w` / helm's ListAndWatch.
    if status_code.is_server_error() {
        let response_bytes = match backend_response.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    cluster = %cluster_name,
                    error = %err,
                    "Connect proxy failed to read leased cluster response"
                );
                return connect_error(
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to read leased cluster response: {err}"),
                );
            }
        };

        let response_body_summary = summarize_response_body(&response_bytes);
        let response_body_len = response_bytes.len();

        if verbose_connect_proxy_logging(&request_path, status_code) {
            info!(
                request_id = %request_id,
                lease_id = %lease_id,
                cluster = %cluster_name,
                upstream = %backend.server,
                method = %method,
                path = %request_path,
                status = status_code.as_u16(),
                body_bytes = response_body_len,
                upstream_headers = %response_header_summary,
                response_body = %response_body_summary,
                "Connect proxy received upstream response"
            );
        }

        warn!(
            request_id = %request_id,
            lease_id = %lease_id,
            cluster = %cluster_name,
            upstream = %backend.server,
            method = %method,
            path = %request_path,
            status = status_code.as_u16(),
            response_body = %response_body_summary,
            "Connect proxy received upstream server error"
        );

        return response
            .body(Body::from(response_bytes))
            .expect("connect proxy response");
    }

    if verbose_connect_proxy_logging(&request_path, status_code) {
        info!(
            request_id = %request_id,
            lease_id = %lease_id,
            cluster = %cluster_name,
            upstream = %backend.server,
            method = %method,
            path = %request_path,
            status = status_code.as_u16(),
            upstream_headers = %response_header_summary,
            "Connect proxy streaming upstream response"
        );
    }

    info!(
        request_id = %request_id,
        lease_id = %lease_id,
        cluster = %cluster_name,
        upstream = %backend.server,
        method = %method,
        path = %request_path,
        status = status_code.as_u16(),
        stripped_headers = %stripped_headers.join(","),
        forwarded_headers = %forwarded_headers.join(","),
        "Connect proxy forwarding response downstream"
    );

    let response_stream = backend_response
        .bytes_stream()
        .map_err(std::io::Error::other);

    response
        .body(Body::from_stream(response_stream))
        .expect("connect proxy response")
}

#[tracing::instrument(skip_all)]
async fn release_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    let lease = match leases_api.get(&id).await {
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

    if lease.spec.requester.identity != identity.identity {
        return StatusCode::NOT_FOUND.into_response();
    }

    let status = lease.status.clone().unwrap_or_default();

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
        .with_label_values(&[lease.spec.pool_ref.as_str(), "released"])
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
        Ok(lease) => {
            if lease.spec.requester.identity != identity.identity {
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
        Err(crate::controllers::lease::LeaseError::Lifecycle(e)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
                detail: None,
            }),
        )
            .into_response(),
        Err(crate::controllers::lease::LeaseError::Kube(e)) => (
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
        Ok(lease) => {
            if lease.spec.requester.identity != identity.identity {
                return StatusCode::NOT_FOUND.into_response();
            }

            let status = lease.status.unwrap_or_default();
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
                .map(profile_response)
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
        Ok(profile) => (StatusCode::OK, Json(profile_response(&profile))).into_response(),
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

/// GET /v1/pools/{name}/leases — list all leases for a pool.
#[tracing::instrument(skip_all)]
async fn list_pool_leases<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(pool_name): Path<String>,
) -> Response {
    let policy = policy_for(&identity);
    if !is_pool_allowed(&pool_name, &policy) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/profile={pool_name}"));

    match leases_api.list(&lp).await {
        Ok(leases) => {
            let summaries: Vec<LeaseSummary> = leases
                .iter()
                .filter(|c| {
                    let status = c.status.clone().unwrap_or_default();
                    matches!(status.phase, LeasePhase::Pending | LeasePhase::Bound)
                })
                .map(|c| {
                    let status = c.status.clone().unwrap_or_default();
                    LeaseSummary {
                        id: c.name_any(),
                        phase: status.phase.to_string(),
                        profile: c.spec.pool_ref.clone(),
                        cluster_name: status.cluster_name,
                        expires_at: status.expires_at,
                        queue_position: status.queue_position,
                        diagnostics_url: None,
                        requester: Some(c.spec.requester.identity.clone()),
                    }
                })
                .collect();

            (StatusCode::OK, Json(summaries)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list pool leases".to_string(),
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
    OptionalAuth(maybe_identity): OptionalAuth,
) -> Response {
    let methods = state.authenticator.auth_methods().await;

    // If a valid token was provided, build a session with accessible pools
    let session = if let Some(identity) = maybe_identity {
        let pools = accessible_pools_for_provider(&state, &identity.provider).await;
        Some(StatusSession {
            method: identity.method,
            identity: identity.identity,
            pools,
            expires_at: None,
        })
    } else {
        None
    };

    let sessions = session.into_iter().collect::<Vec<_>>();

    // Pools — read CRD status so every replica reports the same view.
    let pool_infos = if sessions.is_empty() {
        vec![]
    } else {
        accessible_pool_statuses(&state, &sessions).await
    };

    Json(StatusResponse {
        version: std::env::var("BUILD_VERSION")
            .ok()
            .or_else(|| option_env!("BUILD_VERSION").map(str::to_string))
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
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
    leased: u32,
    total: u32,
}

/// Get accessible pools by provider/requester_type string.
async fn accessible_pools_for_provider<B: ClusterBackend>(
    state: &AppState<B>,
    provider: &str,
) -> Vec<String> {
    if let Some(policy) = state
        .authenticator
        .policy_for_requester_type(provider)
        .await
    {
        policy.allowed_pools
    } else {
        vec![]
    }
}

async fn accessible_pool_statuses<B: ClusterBackend>(
    state: &AppState<B>,
    sessions: &[StatusSession],
) -> Vec<StatusPool> {
    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let profiles = match profiles_api.list(&ListParams::default()).await {
        Ok(profiles) => profiles,
        Err(e) => {
            tracing::warn!("Failed to list profiles for status endpoint: {e}");
            return vec![];
        }
    };

    profiles
        .iter()
        .map(|profile| {
            let status = profile.status.clone().unwrap_or_default();
            StatusPool {
                name: profile.name_any(),
                ready: status.ready,
                leased: status.leased,
                total: status.ready + status.leased + status.creating,
            }
        })
        .filter(|p| {
            sessions
                .iter()
                .any(|s| s.pools.iter().any(|pattern| pool_matches(&p.name, pattern)))
        })
        .collect()
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

/// Liveness + startup probe target — answers only "is the process
/// wedged? restart it." Unconditionally `200` and cheap: it must NOT
/// check external dependencies. If it did, a dependency blip would fail
/// liveness on every replica, the kubelet would kill them all, and the
/// restart storm would crashloop while the dependency stayed down.
///
/// `/healthz` is wired to this same handler as a back-compat alias.
async fn livez() -> StatusCode {
    StatusCode::OK
}

/// Per-check timeout for `/readyz`, so a hung dependency yields a `503`
/// instead of blocking the probe until the kubelet's own timeout fires.
const READYZ_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Readiness probe target — answers "can this pod serve right now?" by
/// checking the dependencies kobe needs to do useful work. On failure it
/// returns `503` so the pod is pulled out of the Service (traffic stops)
/// without being restarted; a restart would not fix an external outage.
async fn readyz<B: ClusterBackend>(State(state): State<AppState<B>>) -> Response {
    let mut failures = Vec::new();

    // Kubernetes API — kobe is an operator; no request path works without it.
    if let Err(e) = readyz_check_kubernetes(&state.client).await {
        failures.push(format!("kubernetes: {e}"));
    }

    // PostgreSQL — only when a pool is configured. In embedded-datastore
    // mode `pg_pool` is `None` and there is nothing to check.
    if let Some(pool) = &state.pg_pool
        && let Err(e) = readyz_check_postgres(pool).await
    {
        failures.push(format!("postgres: {e}"));
    }

    if failures.is_empty() {
        (StatusCode::OK, "ok").into_response()
    } else {
        let detail = failures.join("; ");
        warn!(detail = %detail, "Readiness check failed");
        (StatusCode::SERVICE_UNAVAILABLE, detail).into_response()
    }
}

/// Probe the Kubernetes API with a cheap `GET /version`.
async fn readyz_check_kubernetes(client: &Client) -> Result<(), String> {
    match tokio::time::timeout(READYZ_CHECK_TIMEOUT, client.apiserver_version()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_string()),
    }
}

/// Probe PostgreSQL with a `SELECT 1` round-trip.
async fn readyz_check_postgres(pool: &sqlx::PgPool) -> Result<(), String> {
    let ping = sqlx::query("SELECT 1").execute(pool);
    match tokio::time::timeout(READYZ_CHECK_TIMEOUT, ping).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_string()),
    }
}

async fn metrics_handler<B: ClusterBackend>(State(state): State<AppState<B>>) -> Response {
    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let profiles = match profiles_api.list(&ListParams::default()).await {
        Ok(profiles) => profiles,
        Err(e) => {
            tracing::warn!("Failed to list profiles for metrics endpoint: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "failed to list profiles").into_response();
        }
    };

    metrics::POOL_CLUSTERS.reset();
    metrics::QUEUE_DEPTH.reset();

    for profile in profiles.iter() {
        let name = profile.name_any();
        let status = profile.status.clone().unwrap_or_default();
        metrics::POOL_CLUSTERS
            .with_label_values(&[name.as_str(), "creating"])
            .set(status.creating as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[name.as_str(), "ready"])
            .set(status.ready as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[name.as_str(), "leased"])
            .set(status.leased as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[name.as_str(), "unhealthy"])
            .set(status.unhealthy as i64);
        metrics::POOL_CLUSTERS
            .with_label_values(&[name.as_str(), "recycling"])
            .set(0);
        metrics::QUEUE_DEPTH
            .with_label_values(&[name.as_str()])
            .set(status.queue_depth as i64);
    }

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

    use base64::Engine;

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

    use tower::ServiceExt;

    /// Helper: build an axum Router backed by MockBackend and wiremock.
    async fn test_app() -> (Router, wiremock::MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));

        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
            pg_pool: None,
        };

        (build_router(state), server)
    }

    fn lease_object_json(
        name: &str,
        requester_identity: &str,
        phase: &str,
        cluster_name: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
            },
            "spec": {
                "poolRef": "ci-small",
                "ttl": "1h",
                "requester": {
                    "type": "github-actions:ci",
                    "identity": requester_identity,
                },
                "priority": 50
            },
            "status": {
                "phase": phase,
                "clusterName": cluster_name,
                "expiresAt": "2026-04-13T18:00:00Z",
                "queuePosition": 0
            }
        })
    }

    fn secret_object_json(name: &str, token: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
            },
            "data": {
                "token": base64::engine::general_purpose::STANDARD.encode(token)
            },
            "type": "Opaque"
        })
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn response_text(response: Response) -> String {
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_healthz_returns_200() {
        // Back-compat alias — still serves liveness unconditionally.
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_livez_returns_200() {
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/livez")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_ok_when_kubernetes_reachable() {
        let (app, server) = test_app().await;

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "major": "1",
                "minor": "31",
                "gitVersion": "v1.31.3",
                "gitCommit": "abcdef",
                "gitTreeState": "clean",
                "buildDate": "2026-01-01T00:00:00Z",
                "goVersion": "go1.22",
                "compiler": "gc",
                "platform": "linux/amd64"
            })))
            .mount(&server)
            .await;

        let req = http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // No pg_pool configured, so only the Kubernetes check runs.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_503_when_kubernetes_unreachable() {
        // `/version` is left unmocked: wiremock answers 404, the kube
        // client surfaces an error, and readiness must report 503.
        let (app, _server) = test_app().await;

        let req = http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response_text(resp).await.contains("kubernetes"));
    }

    #[tokio::test]
    async fn test_metrics_returns_200() {
        let (app, server) = test_app().await;

        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let empty_list = crate::testutil::k8s_list_response::<serde_json::Value>(vec![]);
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/clusterpools",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(&empty_list))
            .mount(&server)
            .await;

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

    #[tokio::test]
    async fn test_get_lease_rewrites_bound_kubeconfig_for_connect_proxy() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        backend.set_kubeconfig("raw-backend-kubeconfig");
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
            pg_pool: None,
        };

        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/clusterleases/lease-abc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_object_json(
                "lease-abc",
                &test_identity().identity,
                "Bound",
                Some("pool-ci-small-6"),
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/namespaces/.*/secrets/lease-abc-connect-token",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/api/v1/namespaces/.*/secrets"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(secret_object_json("lease-abc-connect-token", "lease-token")),
            )
            .mount(&server)
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(HOST, "kobe.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());

        let response = get_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Path("lease-abc".to_string()),
            headers,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let kubeconfig = body["kubeconfig"].as_str().unwrap();
        assert!(kubeconfig.contains("server: https://kobe.example/connect/lease-abc"));
        assert!(kubeconfig.contains("current-context: lease-abc"));
        assert!(kubeconfig.contains("cluster: pool-ci-small-6"));
        assert!(kubeconfig.contains("user: lease-abc"));
        assert!(!kubeconfig.contains("current-context: default"));
    }

    #[tokio::test]
    async fn test_connect_proxy_forwards_to_backend_cluster() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        backend.set_kubeconfig(&format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: {}\nusers:\n- name: default\n  user:\n    token: backend-token\n",
            server.uri()
        ));
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
            pg_pool: None,
        };

        use wiremock::matchers::{header, method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/namespaces/.*/secrets/lease-abc-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_object_json("lease-abc-connect-token", "lease-token")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/clusterleases/lease-abc",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_object_json(
                "lease-abc",
                &test_identity().identity,
                "Bound",
                Some("pool-ci-small-6"),
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/version"))
            .and(header("authorization", "Bearer backend-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_raw(r#"{"gitVersion":"v1.32.0"}"#, "application/json"),
            )
            .mount(&server)
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer lease-token".parse().unwrap());

        let response = connect_proxy::<crate::testutil::MockBackend>(
            State(state),
            Path(("lease-abc".to_string(), "version".to_string())),
            Method::GET,
            headers,
            RawQuery(None),
            Body::empty(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_text(response).await, r#"{"gitVersion":"v1.32.0"}"#);
    }

    #[tokio::test]
    async fn test_connect_proxy_requires_bearer_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
            pg_pool: None,
        };

        let response = connect_proxy::<crate::testutil::MockBackend>(
            State(state),
            Path(("lease-abc".to_string(), "version".to_string())),
            Method::GET,
            HeaderMap::new(),
            RawQuery(None),
            Body::empty(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_text(response).await, "Missing Bearer token");
    }

    #[test]
    fn test_connect_proxy_skips_hop_by_hop_response_headers() {
        for header in [
            CONNECTION,
            CONTENT_LENGTH,
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-authenticate"),
            HeaderName::from_static("proxy-authorization"),
            HeaderName::from_static("te"),
            HeaderName::from_static("trailer"),
            HeaderName::from_static("transfer-encoding"),
            HeaderName::from_static("upgrade"),
        ] {
            assert!(
                should_skip_response_header(&header),
                "expected {header} to be stripped from proxied responses"
            );
        }
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
