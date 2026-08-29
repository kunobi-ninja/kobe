use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::body::{self, Body};
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post};
use axum::{Json, Router};
use futures::TryStreamExt;
use http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, UPGRADE};
use kube::api::{Api, ListParams, ObjectMeta, Patch as KubePatch, PatchParams, PostParams};
use kube::{Client, ResourceExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::api::auth::{AuthIdentity, JwtAuthenticator};
use crate::api::connect::{
    BackendAccess, backend_access_from_kubeconfig, build_backend_tls_config,
    build_connect_kubeconfig, ensure_lease_connect_token, validate_lease_connect_token,
};
use crate::api::policy::{self, format_duration, is_pool_allowed, is_sandbox_allowed, policy_for};
use crate::backend::{BackendFactory, ClusterBackend};
use crate::controllers::lease::extend_lease_ttl;
use crate::crd::{
    CIDRClaim, CIDRClaimPhase, ClusterInstance, ClusterInstancePhase, ClusterLease,
    ClusterLeaseCondition, ClusterLeaseSpec, ClusterPool, LeaseBinding, LeasePhase, Requester,
    SandboxPool, SandboxVerb,
};
use crate::lease_binding::{BindingResolutionError, BindingResolveMode, resolve_lease_binding};
use crate::metrics;
use crate::pool::{is_valid_k8s_name, parse_duration};
use kunobi_auth::server::{AuthnProvider, OptionalAuth};

/// Shared application state for axum routes.
#[derive(Clone)]
pub struct AppState<B: ClusterBackend> {
    pub client: Client,
    pub authenticator: Arc<JwtAuthenticator>,
    pub namespace: String,
    /// Dedicated namespace containing only Sandbox quota/alias coordination
    /// Leases. Keeping this separate lets the chart enforce operator-only
    /// writes and a hard object quota without affecting unrelated leader
    /// elections in the control-plane namespace.
    pub sandbox_reservation_namespace: String,
    /// Exact process identity used by the distributed Sandbox access ledger.
    /// Present only when Sandbox routes are enabled; downward-API Pod identity
    /// plus a fresh boot id make crash recovery distinguish a replacement
    /// process from a still-live replica.
    pub sandbox_serving_replica: Option<crate::sandbox_access_ledger::ServingReplica>,
    /// Ambient default backend. **Never an authorization or dispatch input.**
    ///
    /// Before #79 the connect proxy fell back to this when pool/backend
    /// resolution failed, which let a deleted or reconfigured pool silently
    /// redirect tenant traffic. Dispatch now comes exclusively from the
    /// immutable `BackendProvenance` recorded on the binding, so nothing reads
    /// this field. Retained only so the `B: ClusterBackend` plumbing keeps
    /// compiling; dropping the type parameter is follow-up cleanup.
    #[allow(dead_code)]
    pub backend: B,
    pub factory: Option<BackendFactory>,
    /// Shared PostgreSQL datastore when one is configured; empty in
    /// embedded-datastore mode. Consulted by the `/readyz` probe.
    pub datastore: crate::backend::datastore::SharedDatastore,
    /// Short-TTL per-lease validation/connection cache for the connect proxy.
    /// Lets a burst of requests through one lease (e.g. a single `kubectl`,
    /// which fans out into dozens of API calls) skip the per-request token
    /// validate + lease GET + kubeconfig Secret read + reqwest client build.
    pub connect_cache: ConnectCache,
    /// Per-principal admission budget for the Sandbox create path. Shared
    /// across requests because a limiter rebuilt per request would bound
    /// nothing; see [`crate::api::sandbox_rate_limit`] for why it is charged
    /// per attempt rather than per admitted lease.
    pub sandbox_admission_limiter: crate::api::sandbox_rate_limit::AdmissionRateLimiter,
    /// Process-wide shutdown signal. Admission resolution selects on this so
    /// an ambiguous Kubernetes response cannot hold Axum graceful shutdown
    /// open indefinitely. The durable SandboxLease remains the handoff to the
    /// next supervised admission-reaper instance.
    pub shutdown: tokio_util::sync::CancellationToken,
    /// Whether the upstream Agent Sandbox runtime was explicitly enabled and
    /// validated at startup. Disabled deployments do not mount Sandbox HTTP
    /// routes, so they cannot admit leases that no controller will reconcile.
    pub sandbox_enabled: bool,
}

/// Per-lease connect-proxy context cache. Newtype over a shared, mutex-guarded
/// map keyed by the lease name plus the exact lease and instance UIDs. `std`
/// only — entries are tiny and short-lived (5s TTL), so a coarse `Mutex` around
/// a `HashMap` is more than enough and avoids pulling in an external cache
/// crate.
#[derive(Clone, Default)]
pub struct ConnectCache(
    Arc<std::sync::Mutex<std::collections::HashMap<ConnectCacheKey, ConnectCtx>>>,
);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectCacheKey {
    lease_name: String,
    lease_uid: String,
    instance_uid: String,
}

/// One cached connect-proxy context for a lease. Everything here was validated
/// fresh at `cached_at`; on a hit we re-enforce the security gates (token match,
/// phase, expiry) before reusing the cached backend.
#[derive(Clone)]
struct ConnectCtx {
    cached_at: std::time::Instant,
    /// The connect token that was validated as correct when this entry was
    /// populated. Compared against the presented token with a constant-time
    /// `secret_eq` on every hit; a mismatch is a cache MISS (full revalidate).
    token: String,
    cluster_name: String,
    /// Complete fence validated when this context was populated. Cache hits
    /// re-run the shared resolver and require byte-for-byte identity before
    /// reusing the credential-bearing backend context.
    binding: LeaseBinding,
    /// reqwest client + server + bearer — cheap to clone (Arc-internal client).
    backend: BackendAccess,
    /// Raw backend kubeconfig, retained for the upgrade path's
    /// `build_backend_tls_config` (the rustls config can't be cloned cheaply).
    raw_kubeconfig: String,
}

/// Revocation-staleness tradeoff: a cached context is reused for up to this
/// long without re-reading the connect-token Secret or re-fetching the lease.
/// At 5s, revoking a token (deleting the Secret) or releasing a lease takes up
/// to 5s to fully cut off in-flight cache holders. Expiry is the exception —
/// it is ALWAYS re-evaluated against the wall clock on every request and an
/// expired hit is evicted, so TTL never extends a lease past `expires_at`.
const CONNECT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Outcome of a connect-cache lookup. On a `Hit` the caller skips the full
/// validate/get/extract/build path; on a `Miss` it runs the full path and
/// repopulates the entry.
enum CacheLookup {
    // `ConnectCtx` carries a reqwest client and the raw kubeconfig (~500
    // bytes); boxing it keeps `Miss` — by far the hotter variant on a cold
    // cache — from paying for that on every lookup.
    Hit(ConnectCacheKey, Box<ConnectCtx>),
    Miss,
}

impl ConnectCache {
    /// Look up `lease_id` and decide hit vs miss WITHOUT mutating phase/expiry
    /// gates (the caller re-enforces those). A hit requires, in order:
    /// the entry exists, it is within TTL, and the presented token matches the
    /// cached token via a constant-time `secret_eq`. A token mismatch is a
    /// MISS so a wrong/revoked token can never ride a cached context — it is
    /// forced back through full revalidation.
    fn lookup(&self, lease_id: &str, presented_token: &str) -> CacheLookup {
        let map = self.0.lock().expect("connect cache mutex poisoned");
        match map.iter().find(|(key, entry)| {
            key.lease_name == lease_id
                && entry.cached_at.elapsed() < CONNECT_CACHE_TTL
                    // Constant-time compare: never short-circuit on the first
                    // differing byte, and never serve a cached backend to a
                    // token that doesn't match what we validated.
                    && kunobi_auth::secret_eq(&entry.token, presented_token)
        }) {
            Some((key, entry)) => CacheLookup::Hit(key.clone(), Box::new(entry.clone())),
            _ => CacheLookup::Miss,
        }
    }

    /// Remove a lease's cached entry (e.g. on an expired-on-hit eviction).
    fn evict(&self, lease_id: &str) {
        self.0
            .lock()
            .expect("connect cache mutex poisoned")
            .retain(|key, _| key.lease_name != lease_id);
    }

    /// Insert/refresh a lease's entry after a full revalidation. Opportunistically
    /// prunes stale entries while we hold the lock (the map only ever holds
    /// active leases, so this stays cheap).
    fn insert(&self, lease_id: String, ctx: ConnectCtx) {
        let mut map = self.0.lock().expect("connect cache mutex poisoned");
        map.retain(|_, entry| entry.cached_at.elapsed() < CONNECT_CACHE_TTL);
        // A binding is immutable for one lease UID. Remove any stale name-keyed
        // context before inserting the exact UID-fenced key.
        map.retain(|key, _| key.lease_name != lease_id);
        let key = ConnectCacheKey {
            lease_name: lease_id,
            lease_uid: ctx
                .binding
                .lease
                .uid
                .clone()
                .expect("resolver accepted a binding without lease UID"),
            instance_uid: ctx.binding.instance.uid.clone(),
        };
        map.insert(key, ctx);
    }
}

/// RAII timer for `kobe_connect_proxy_request_duration_seconds`. Observes once
/// on `Drop`, so every early-return path through `connect_proxy_inner` (and the
/// upgrade hand-off) is timed without sprinkling `observe` at each return. The
/// `kind` label defaults to `buffered`; the upgrade branch flips it via
/// [`ConnectProxyTimer::set_kind`] right before it tunnels.
struct ConnectProxyTimer {
    started: Instant,
    kind: &'static str,
}

impl ConnectProxyTimer {
    fn start() -> Self {
        Self {
            started: Instant::now(),
            kind: "buffered",
        }
    }

    fn set_kind(&mut self, kind: &'static str) {
        self.kind = kind;
    }
}

impl Drop for ConnectProxyTimer {
    fn drop(&mut self) {
        metrics::CONNECT_PROXY_REQUEST_DURATION
            .with_label_values(&[self.kind])
            .observe(self.started.elapsed().as_secs_f64());
    }
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
/// Serve the Kunobi auth-discovery document at `/.well-known/kunobi-auth` so the
/// CLI (`kobe login`) can discover the OIDC issuer / client_id / audience to
/// authenticate against. Returns 404 when no AccessPolicy configures interactive
/// login (no OIDC provider sets a `clientId`).
async fn kunobi_auth_discovery<B: ClusterBackend>(State(state): State<AppState<B>>) -> Response {
    match state.authenticator.discovery_metadata().await {
        Some(doc) => Json(doc).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub fn build_router<B: ClusterBackend + Clone + 'static>(state: AppState<B>) -> Router {
    // Concurrency-limited API routes
    let mut api_routes = Router::new()
        .route("/v1/leases", post(create_lease::<B>))
        .route("/v1/leases", get(list_leases::<B>))
        .route("/v1/leases/{id}", get(get_lease::<B>))
        .route("/v1/leases/{id}", delete(release_lease::<B>))
        .route("/v1/leases/{id}", patch(extend_lease::<B>))
        .route("/v1/leases/{id}/diagnostics", get(get_diagnostics::<B>))
        .route("/v1/pools", get(list_pools::<B>))
        .route("/v1/pools/{name}", get(get_pool::<B>))
        .route("/v1/pools/{name}/leases", get(list_pool_leases::<B>));
    if state.sandbox_enabled {
        api_routes = api_routes.merge(crate::api::sandbox::routes::<B>());
    }
    let api_routes = api_routes.layer(axum::middleware::from_fn(concurrency_limit));

    let connect_routes = Router::new()
        .route("/connect/{id}", any(connect_proxy_root::<B>))
        .route("/connect/{id}/{*path}", any(connect_proxy::<B>));

    // Non-limited infrastructure routes
    Router::new()
        .merge(api_routes)
        .merge(connect_routes)
        .route("/v1/status", get(status::<B>))
        // OIDC auth discovery for `kobe login` (unauthenticated, like /v1/status).
        .route(
            kunobi_auth::server::KUNOBI_AUTH_DISCOVERY_PATH,
            get(kunobi_auth_discovery::<B>),
        )
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
                    reason: None,
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

#[derive(Deserialize, Default)]
pub(crate) struct CreateLeaseRequest {
    /// Cluster-lease historical field. Sandbox clients send `pool`. Either is
    /// accepted; if both are set they must match.
    #[serde(default)]
    pub(crate) profile: Option<String>,
    #[serde(default)]
    pub(crate) pool: Option<String>,
    #[serde(default)]
    pub(crate) ttl: Option<String>,
    /// Optional caller-supplied alias (#107 P2). Stored as the label
    /// `kobe.kunobi.ninja/alias`; unique among the requester's ACTIVE leases so
    /// it can name "which lease" in scripts (`kobe extend pr-106 30m`).
    #[serde(default)]
    pub(crate) alias: Option<String>,
    /// Optional caller-supplied descriptive JSON. This is stored verbatim but
    /// has no authorization, scheduling, or lifecycle semantics. Rejected for
    /// Sandbox pools.
    #[serde(default)]
    pub(crate) metadata: Option<serde_json::Value>,
    /// Sandbox create idempotency key. Ignored for Cluster pools.
    #[serde(default, rename = "idempotencyKey", alias = "idempotency_key")]
    pub(crate) idempotency_key: Option<String>,
}

impl CreateLeaseRequest {
    fn pool_name(&self) -> Result<String, Response> {
        let profile = self
            .profile
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        let pool = self
            .pool
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        match (profile, pool) {
            (Some(profile), Some(pool)) if profile != pool => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "profile and pool must name the same pool".to_string(),
                    detail: None,
                    reason: None,
                }),
            )
                .into_response()),
            (Some(name), _) | (_, Some(name)) => Ok(name.to_string()),
            (None, None) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Pool name is required".to_string(),
                    detail: Some("Provide `profile` or `pool`".to_string()),
                    reason: None,
                }),
            )
                .into_response()),
        }
    }
}

#[derive(Serialize)]
struct LeaseResponse {
    id: String,
    #[serde(rename = "resourceKind")]
    resource_kind: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<&'static str>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    /// Caller-supplied descriptive metadata. Present only on the owner's lease
    /// responses; shared pool listings redact it for other tenants.
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    /// Human-readable explanation of the lease's current state (#189), echoed
    /// from `ClusterLeaseStatus.message` — primarily why a Pending lease has
    /// not bound yet (pool health). Omitted when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Structured K8s-style status conditions (#189), echoed from
    /// `ClusterLeaseStatus.conditions` — `Bound` and `Satisfiable`. The
    /// machine-readable companion to `message`. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<ClusterLeaseCondition>,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

const MAX_LEASE_METADATA_BYTES: usize = 8 * 1024;
const MAX_LEASE_METADATA_TOP_LEVEL_KEYS: usize = 32;
const MAX_LEASE_METADATA_DEPTH: usize = 4;
const MAX_LEASE_METADATA_NODES: usize = 128;

/// Validate the caller-controlled lease metadata envelope before persisting it.
///
/// The byte bound protects the CRD and API responses; the shape bounds keep a
/// small payload from becoming pathologically nested. Values remain opaque and
/// untrusted after validation: no controller may derive behavior from them.
fn validate_lease_metadata(metadata: &serde_json::Value) -> Result<(), String> {
    let object = metadata
        .as_object()
        .ok_or_else(|| "Metadata must be a JSON object".to_string())?;

    if object.len() > MAX_LEASE_METADATA_TOP_LEVEL_KEYS {
        return Err(format!(
            "Metadata may contain at most {MAX_LEASE_METADATA_TOP_LEVEL_KEYS} top-level keys"
        ));
    }

    let encoded_len = serde_json::to_vec(metadata)
        .map_err(|error| format!("Metadata could not be encoded: {error}"))?
        .len();
    if encoded_len > MAX_LEASE_METADATA_BYTES {
        return Err(format!(
            "Metadata may be at most {MAX_LEASE_METADATA_BYTES} bytes when encoded as JSON"
        ));
    }

    fn visit(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
        if depth > MAX_LEASE_METADATA_DEPTH {
            return Err(format!(
                "Metadata may be nested at most {MAX_LEASE_METADATA_DEPTH} levels deep"
            ));
        }
        *nodes += 1;
        if *nodes > MAX_LEASE_METADATA_NODES {
            return Err(format!(
                "Metadata may contain at most {MAX_LEASE_METADATA_NODES} JSON values"
            ));
        }
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, nodes)?;
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    visit(value, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut nodes = 0;
    visit(metadata, 1, &mut nodes)
}

#[derive(Serialize)]
struct LeaseSummary {
    id: String,
    phase: String,
    #[serde(rename = "resourceKind")]
    resource_kind: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<&'static str>,
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
    /// Caller-supplied alias, if any (#107 P2).
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    /// Caller-supplied descriptive metadata. Redacted alongside `requester`
    /// and `alias` when a shared-pool listing contains another tenant's lease.
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Query parameters for `GET /v1/leases` (#107 P2).
#[derive(Deserialize, Default)]
struct ListLeasesParams {
    /// Restrict to the lease carrying this alias (scoped to the caller's
    /// identity by the handler). Lets scripts resolve "which lease" by name.
    #[serde(default)]
    alias: Option<String>,
}

#[derive(Deserialize)]
struct ExtendLeaseRequest {
    /// `extend_ttl` is this endpoint's historical spelling. `extendTtl` is
    /// accepted too so a client can send one body shape to both this and the
    /// Sandbox extend endpoint, which follows the newer camelCase convention.
    #[serde(alias = "extendTtl")]
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
    resource_kind: &'static str,
    capabilities: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<String>,
    ready: u32,
    leased: u32,
    creating: u32,
    recycling: u32,
    unhealthy: u32,
    quarantined: u32,
    queue_depth: u32,
    policy: PoolPolicyResponse,
}

/// Bounded, machine-readable reason for a lease-creation rejection (#189), so a
/// client can branch on *why* without parsing the human `error` string. Only
/// the lease pre-flight path sets it today; everything else leaves it None.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum ErrorReason {
    /// Pool phase is `Failing` — it will not satisfy the lease without
    /// operator attention.
    PoolExhausted,
    /// Pool is in a backoff window with no schedulable headroom.
    CapacityBlocked,
    /// Pool is otherwise degraded.
    Degraded,
    /// Healthy-but-empty warm pool: still coming up. (Carried on a 202, not a
    /// 503 — the lease is expected to bind shortly.)
    Warming,
    /// Release was refused because verified teardown remains quarantined.
    TeardownQuarantined,
    /// The pool name exists as the other resource kind (Cluster vs Sandbox).
    WrongResourceKind,
}

impl From<crate::metrics::LeaseUnsatisfiableReason> for ErrorReason {
    fn from(r: crate::metrics::LeaseUnsatisfiableReason) -> Self {
        use crate::metrics::LeaseUnsatisfiableReason as R;
        match r {
            R::PoolExhausted => Self::PoolExhausted,
            R::CapacityBlocked => Self::CapacityBlocked,
            R::Degraded => Self::Degraded,
            R::Warming => Self::Warming,
        }
    }
}

#[derive(Serialize, Default)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// Bounded machine-readable reason (#189). Omitted unless set by the lease
    /// pre-flight path.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<ErrorReason>,
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

fn cluster_lease_capabilities(policy: &policy::Policy) -> Vec<&'static str> {
    let mut capabilities = vec!["lease", "kubeconfig", "release"];
    if policy.max_extensions > 0 {
        capabilities.push("extend");
    }
    capabilities
}

fn sandbox_lease_capabilities(pool: &str, policy: &policy::Policy) -> Vec<&'static str> {
    let mut capabilities = vec!["lease"];
    if is_sandbox_allowed(pool, SandboxVerb::Exec, policy) {
        capabilities.extend(["exec", "cancel", "attach"]);
    }
    if is_sandbox_allowed(pool, SandboxVerb::Logs, policy) {
        capabilities.push("logs");
    }
    if is_sandbox_allowed(pool, SandboxVerb::PortForward, policy) {
        capabilities.push("port-forward");
    }
    if is_sandbox_allowed(pool, SandboxVerb::Release, policy) {
        capabilities.push("release");
    }
    if policy
        .sandbox
        .as_ref()
        .is_some_and(|grant| grant.max_extensions > 0)
    {
        capabilities.push("extend");
    }
    capabilities
}

fn profile_response(profile: &ClusterPool, policy: &policy::Policy) -> ProfileResponse {
    let status = profile.status.clone().unwrap_or_default();
    ProfileResponse {
        name: profile.name_any(),
        resource_kind: "Cluster",
        capabilities: cluster_lease_capabilities(policy),
        phase: status.phase.map(|phase| format!("{phase:?}")),
        ready: status.ready,
        leased: status.leased,
        creating: status.creating,
        recycling: status.recycling,
        unhealthy: status.unhealthy,
        quarantined: status.quarantined,
        queue_depth: status.queue_depth,
        policy: pool_policy_response(profile),
    }
}

fn sandbox_pool_response(pool: &SandboxPool, policy: &policy::Policy) -> ProfileResponse {
    let status = pool.status.clone().unwrap_or_default();
    let phase = if crate::sandbox::require_current_sandbox_pool_ready(pool).is_ok() {
        "Ready"
    } else {
        "NotReady"
    };
    ProfileResponse {
        name: pool.name_any(),
        resource_kind: "Sandbox",
        capabilities: sandbox_lease_capabilities(&pool.name_any(), policy),
        phase: Some(phase.to_string()),
        ready: status.ready,
        leased: status.allocated,
        creating: 0,
        recycling: 0,
        unhealthy: 0,
        quarantined: status.quarantined,
        queue_depth: 0,
        policy: PoolPolicyResponse {
            mode: "sandbox".to_string(),
            ttl: pool.spec.default_ttl.clone(),
            warm_target: pool.spec.warm_capacity,
            max_clusters: None,
            scale_up_threshold: None,
            scale_down_after: None,
            queue_timeout: Some(pool.spec.provisioning_timeout.clone()),
        },
    }
}

fn connect_error(status: StatusCode, message: impl Into<String>) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(message.into()))
        .expect("connect error response")
}

/// Connect-proxy analogue of `infra_error`: logs the raw kube/transport error
/// server-side and returns ONLY the generic `message` to the client, never the
/// raw string (which leaks operator namespaces, in-cluster endpoints, and CRD
/// details to a low-trust caller — possibly before lease-token validation).
fn connect_infra_error(
    status: StatusCode,
    message: &str,
    err: impl std::fmt::Display,
    reason: metrics::ConnectErrorReason,
) -> Response {
    warn!(error = %err, reason = reason.as_str(), "{message}");
    metrics::CONNECT_PROXY_REQUEST_OUTCOME_TOTAL
        .with_label_values(&[metrics::ConnectOutcome::BackendError.as_str()])
        .inc();
    // Alongside, never instead: the outcome counter keeps its existing shape so
    // dashboards and alerts built on it are unaffected (#106).
    metrics::CONNECT_PROXY_ERROR_REASON_TOTAL
        .with_label_values(&[reason.as_str()])
        .inc();
    connect_error(status, message)
}

/// Increment `kobe_connect_proxy_request_outcome_total{outcome}` then build the
/// rejection response. Used at every non-infra rejection return in
/// `connect_proxy_inner` so the cold and cached paths classify identically.
/// (Infra/backend failures go through `connect_infra_error`, which records
/// `outcome="backend_error"` itself.)
fn connect_reject(
    outcome: metrics::ConnectOutcome,
    status: StatusCode,
    message: impl Into<String>,
) -> Response {
    connect_reject_with_reason(outcome, status, message, None)
}

/// As `connect_reject`, but also records WHY when the outcome is
/// `backend_error`.
///
/// Every `backend_error` exit must supply a reason: the enum's contract is
/// "why a connect-proxy request produced backend_error", and a path that skips
/// it silently stays in the opaque bucket #106 exists to break up.
fn connect_reject_with_reason(
    outcome: metrics::ConnectOutcome,
    status: StatusCode,
    message: impl Into<String>,
    reason: Option<metrics::ConnectErrorReason>,
) -> Response {
    metrics::CONNECT_PROXY_REQUEST_OUTCOME_TOTAL
        .with_label_values(&[outcome.as_str()])
        .inc();
    if let Some(reason) = reason {
        metrics::CONNECT_PROXY_ERROR_REASON_TOTAL
            .with_label_values(&[reason.as_str()])
            .inc();
    }
    connect_error(status, message)
}

/// Convert a typed exact-binding denial into the stable public connect
/// contract. Details stay in the bounded resolver reason code logged by the
/// caller; clients never receive UIDs, provenance, object internals, or raw
/// Kubernetes errors.
fn binding_resolution_response(err: BindingResolutionError) -> Response {
    match err {
        BindingResolutionError::LeaseNotFound => connect_reject(
            metrics::ConnectOutcome::LeaseNotFound,
            StatusCode::NOT_FOUND,
            "Lease not found",
        ),
        BindingResolutionError::LeaseNotBound => connect_reject(
            metrics::ConnectOutcome::PhaseNotBound,
            StatusCode::CONFLICT,
            "Lease is not active",
        ),
        BindingResolutionError::Expired => connect_reject(
            metrics::ConnectOutcome::Expired,
            StatusCode::GONE,
            "Lease has expired",
        ),
        BindingResolutionError::LeaseLookup(_)
        | BindingResolutionError::InstanceLookup(_)
        | BindingResolutionError::PoolLookup(_) => connect_reject_with_reason(
            metrics::ConnectOutcome::BackendError,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to resolve lease binding",
            Some(metrics::ConnectErrorReason::BindingResolution),
        ),
        _ => connect_reject_with_reason(
            metrics::ConnectOutcome::BackendError,
            StatusCode::SERVICE_UNAVAILABLE,
            "Lease binding is unavailable",
            Some(metrics::ConnectErrorReason::BindingResolution),
        ),
    }
}

/// Build an error response for an internal/infrastructure failure (kube API,
/// transport, etc.). Logs the underlying error server-side (correlated with the
/// request by `request_logging`) and returns ONLY a generic `message` to the
/// caller — never the raw error, which leaks operator namespaces, in-cluster
/// DNS/API endpoints, and CRD details to authenticated low-trust clients.
/// Reserve a non-null `detail` for client-actionable validation messages.
fn infra_error(status: StatusCode, message: &str, err: impl std::fmt::Display) -> Response {
    warn!(error = %err, "{message}");
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
            detail: None,
            reason: None,
        }),
    )
        .into_response()
}

/// Default `Retry-After` (seconds) for a lease pre-flight 503 when the pool's
/// backoff `next_attempt_at` is absent or already in the past. A `Failing` pool
/// needs operator attention, so this is a "don't hammer us" pace, not a promise
/// the next retry will succeed.
const LEASE_PREFLIGHT_DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// #189 lease-create pre-flight. Returns `Some(503 response)` when the pool
/// cannot satisfy a new lease right now — a `Failing` pool with zero Ready
/// members, or a `Backoff` pool with no schedulable headroom (zero Ready and
/// already at its capacity bound). Returns `None` when a Ready member exists
/// (bindable regardless of pool phase) or for a healthy-but-empty / warming
/// pool, so the caller proceeds to the normal 202 Pending path.
///
/// The 503 carries a `Retry-After` header (derived from the pool's backoff
/// `next_attempt_at` when present, else a sane default) and a bounded
/// machine-readable `reason`. Increments `kobe_lease_unsatisfiable_total`.
fn pool_preflight_rejection(profile: &str, pool: &ClusterPool) -> Option<Response> {
    use crate::crd::ClusterPoolPhase;
    use crate::metrics::LeaseUnsatisfiableReason as R;

    let status = pool.status.clone();
    let phase = status.as_ref().and_then(|s| s.phase);
    let ready = status.as_ref().map(|s| s.ready).unwrap_or(0);

    // Capacity bound: the most clusters this pool will ever run. Prefer the
    // autoscaler ceiling; fall back to the fixed size.
    let capacity = pool
        .spec
        .scaling
        .as_ref()
        .map(|s| s.max_clusters)
        .unwrap_or(pool.spec.size)
        .max(pool.spec.size);
    let in_flight = status
        .as_ref()
        .map(|s| s.ready + s.leased + s.creating + s.recycling + s.unhealthy + s.quarantined)
        .unwrap_or(0);
    let at_capacity = in_flight >= capacity;

    let reject_reason = match phase {
        // Sustained failures AND nothing Ready to hand out — won't bind
        // without operator action. A Failing pool that still has Ready
        // members must keep serving them: replacement provisioning being
        // broken doesn't invalidate the clusters that already came up, and
        // rejecting those leases turns a background provisioning problem
        // into a full CI outage (2026-07-20: 5 Ready / 0 leased, every
        // claim 503'd for hours).
        Some(ClusterPoolPhase::Failing) if ready == 0 => Some(R::PoolExhausted),
        // In a backoff window AND no headroom to create or hand out a cluster.
        Some(ClusterPoolPhase::Backoff) if ready == 0 && at_capacity => Some(R::CapacityBlocked),
        // Quarantine is deliberately capacity-holding. With no Ready member,
        // accepting another lease would create a queue that cannot advance
        // until teardown evidence is repaired.
        Some(ClusterPoolPhase::Quarantined) if ready == 0 => Some(R::CapacityBlocked),
        // Failing/Backoff with Ready members, healthy-but-empty, scaling up,
        // idle, etc.: bindable now or a transient warm-up — proceed to the
        // normal 202 path.
        _ => None,
    };

    let reason = reject_reason?;

    // Build the human message from the pool's health (shared classifier).
    let (message, _) = crate::controllers::lease::unsatisfiable_status(profile, &status);

    // Retry-After: seconds until the pool's next provision attempt, if known
    // and in the future; otherwise a sane default.
    let retry_after = status
        .as_ref()
        .and_then(|s| s.next_attempt_at.as_deref())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| (t.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds())
        .filter(|secs| *secs > 0)
        .map(|secs| secs as u64)
        .unwrap_or(LEASE_PREFLIGHT_DEFAULT_RETRY_AFTER_SECS);

    metrics::LEASE_UNSATISFIABLE_TOTAL
        .with_label_values(&[profile, reason.as_str()])
        .inc();

    warn!(
        profile = %profile,
        reason = reason.as_str(),
        retry_after_secs = retry_after,
        "Rejecting lease create: pool cannot satisfy it ({message})"
    );

    let body = Json(ErrorResponse {
        error: "Pool cannot satisfy a new lease".to_string(),
        detail: Some(message),
        reason: Some(reason.into()),
    });
    let mut resp = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut()
            .insert(HeaderName::from_static("retry-after"), value);
    }
    Some(resp)
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

/// True if these request headers negotiate an HTTP Upgrade (RFC 7230 §6.7):
/// a `Connection: upgrade` token (case-insensitive list) *and* an `Upgrade`
/// header. kubectl exec / attach / port-forward use this to switch to SPDY or
/// websocket — which the buffered connect proxy cannot tunnel (see #85).
fn headers_request_upgrade(headers: &HeaderMap) -> bool {
    if !headers.contains_key(UPGRADE) {
        return false;
    }
    headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// The requested upgrade protocol token (e.g. `spdy/3.1`, `websocket`),
/// lowercased. None if the `Upgrade` header is absent or invalid UTF-8.
fn requested_upgrade_protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
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

/// Derive the upstream request path+query (everything after the backend
/// authority) for the upgrade tunnel, which addresses the apiserver by
/// path-and-query rather than a full URL.
///
/// Prefers parsing the already-built `request_url` (so it inherits any base
/// path on the backend server URL). Falls back to reconstructing from the
/// proxied path + raw query if the URL can't be parsed.
fn upstream_path_and_query(
    request_url: &str,
    request_path: &str,
    raw_query: &Option<String>,
) -> String {
    if let Ok(url) = url::Url::parse(request_url) {
        let mut pq = url.path().to_string();
        if let Some(q) = url.query() {
            pq.push('?');
            pq.push_str(q);
        }
        return pq;
    }
    // Fallback: request_path already starts with '/'.
    match raw_query {
        Some(q) if !q.is_empty() => format!("{request_path}?{q}"),
        _ => request_path.to_string(),
    }
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

pub(crate) enum CreatePoolKind {
    Cluster,
    Sandbox,
    Ambiguous,
    Missing,
}

pub(crate) async fn resolve_create_pool_kind<B: ClusterBackend>(
    state: &AppState<B>,
    name: &str,
) -> Result<CreatePoolKind, kube::Error> {
    let clusters: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let cluster = clusters.get_opt(name).await?;
    let sandbox = if state.sandbox_enabled {
        let sandboxes: Api<SandboxPool> = Api::namespaced(state.client.clone(), &state.namespace);
        sandboxes.get_opt(name).await?
    } else {
        None
    };
    Ok(match (cluster.is_some(), sandbox.is_some()) {
        (true, true) => CreatePoolKind::Ambiguous,
        (true, false) => CreatePoolKind::Cluster,
        (false, true) => CreatePoolKind::Sandbox,
        (false, false) => CreatePoolKind::Missing,
    })
}

#[tracing::instrument(skip_all)]
pub(crate) async fn create_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Json(req): Json<CreateLeaseRequest>,
) -> Response {
    let profile = match req.pool_name() {
        Ok(name) => name,
        Err(response) => return response,
    };

    if !is_valid_k8s_name(&profile) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid profile name".to_string(),
                detail: Some(
                    "Profile name must be a valid DNS label (lowercase alphanumeric and hyphens, 1-63 chars)"
                        .to_string(),
                ),
                reason: None,
            }),
        )
            .into_response();
    }

    if let Some(metadata) = req.metadata.as_ref()
        && let Err(detail) = validate_lease_metadata(metadata)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid lease metadata".to_string(),
                detail: Some(detail),
                reason: None,
            }),
        )
            .into_response();
    }

    // Kind is server-owned. The client POSTs `/v1/leases`; we look up the pool
    // and admit the matching CRD. Two HTTP trees made old/buggy clients create
    // a ClusterLease for a Sandbox pool that then queued forever.
    match resolve_create_pool_kind(&state, &profile).await {
        Err(error) => {
            return infra_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to read pool",
                error,
            );
        }
        Ok(CreatePoolKind::Ambiguous) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!(
                        "Pool name '{profile}' is ambiguous across Cluster and Sandbox resources"
                    ),
                    detail: Some("Pool names must be unique across resource kinds".to_string()),
                    reason: Some(ErrorReason::WrongResourceKind),
                }),
            )
                .into_response();
        }
        Ok(CreatePoolKind::Missing) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Pool '{profile}' not found"),
                    detail: None,
                    reason: None,
                }),
            )
                .into_response();
        }
        Ok(CreatePoolKind::Sandbox) => {
            if req.metadata.is_some() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Sandbox leases do not accept metadata".to_string(),
                        detail: None,
                        reason: None,
                    }),
                )
                    .into_response();
            }
            return crate::api::sandbox::create_sandbox_lease(
                State(state),
                identity,
                Json(crate::api::sandbox::CreateSandboxLeaseRequest {
                    pool: profile,
                    ttl: req.ttl,
                    alias: req.alias,
                    idempotency_key: req.idempotency_key,
                }),
            )
            .await;
        }
        Ok(CreatePoolKind::Cluster) => {}
    }

    let policy = policy_for(&identity);

    if !is_pool_allowed(&profile, &policy) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Profile '{profile}' not allowed for your identity type"),
                detail: None,
                reason: None,
            }),
        )
            .into_response();
    }

    // #107 P2: validate the optional alias as a DNS label (a strict, safe subset
    // of allowed k8s label values) so it can be carried as a label and echoed
    // into scripts without injection surprises.
    if let Some(alias) = req.alias.as_deref()
        && !is_valid_k8s_name(alias)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid lease alias".to_string(),
                detail: Some(
                    "Alias must be a valid DNS label (lowercase alphanumeric and hyphens, 1-63 chars)"
                        .to_string(),
                ),
                reason: None,
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
                    reason: None,
                }),
            )
                .into_response();
        }
    };
    let effective_ttl = policy::clamp_ttl(ttl_str, &policy);
    // A TTL that clamps to (effectively) zero is a client error: the lease
    // would either be born already-expired or, worse, fall through to the
    // lease controller's 1h fallback and silently last far longer than asked
    // (see `format_duration`). Reject it explicitly rather than papering over
    // the requested value.
    if effective_ttl.num_seconds() <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "TTL too short".to_string(),
                detail: Some(format!(
                    "Requested TTL '{ttl_str}' resolves to a zero-length lease; request at least 1 second"
                )),
                reason: None,
            }),
        )
            .into_response();
    }
    let was_clamped = effective_ttl < requested_ttl;
    let ttl_formatted = format_duration(&effective_ttl);

    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let active_count = match count_active_leases(&leases_api, &identity.identity).await {
        Ok(count) => count,
        Err(e) => {
            return infra_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to verify lease quota",
                e,
            );
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
                reason: None,
            }),
        )
            .into_response();
    }

    // #107 P2: an alias names exactly one of the requester's active leases.
    // Fast-fail if it's already taken (the post-create check below closes the
    // concurrent-create race).
    if let Some(alias) = req.alias.as_deref() {
        match active_alias_holders_sorted(&leases_api, &identity.identity, alias).await {
            Ok(holders) if !holders.is_empty() => {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: format!("Alias '{alias}' is already in use by an active lease"),
                        detail: Some(format!(
                            "Lease '{}' already holds this alias; release it or extend that lease instead",
                            holders[0]
                        )),
                        reason: None,
                    }),
                )
                    .into_response();
            }
            Ok(_) => {}
            Err(e) => {
                return infra_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to verify lease alias",
                    e,
                );
            }
        }
    }

    // #189 pre-flight: GET the target pool and refuse up-front when it cannot
    // satisfy the lease, instead of creating a ClusterLease that hangs Pending
    // forever (fixed-size pools have no queue_timeout). A `Failing` pool — or a
    // `Backoff` pool with no schedulable headroom (zero Ready and at capacity) —
    // returns 503 + Retry-After + a machine-readable `reason`; a healthy-but-
    // empty warm pool keeps the 202 Pending below. Missing pools are rejected
    // above in `resolve_create_pool_kind`.
    {
        let pools_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
        match pools_api.get(&profile).await {
            Ok(pool) => {
                if let Some(unavailable) = pool_preflight_rejection(&profile, &pool) {
                    return unavailable;
                }
            }
            Err(e) => {
                return infra_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to read Cluster pool",
                    e,
                );
            }
        }
    }

    let lease_id = format!(
        "lease-{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );

    let lease = build_lease_crd(
        &lease_id,
        &state.namespace,
        &profile,
        &ttl_formatted,
        &identity,
        policy.default_priority,
        req.alias.as_deref(),
        req.metadata.clone(),
    );

    if let Err(e) = leases_api.create(&PostParams::default(), &lease).await {
        return infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create lease",
            e,
        );
    }

    // The pre-create count check is advisory: N concurrent requests for one
    // identity can each observe the same sub-limit count and all create,
    // overshooting max_concurrent_leases. Re-list the identity's active leases in
    // a deterministic order and self-delete this one if it ranks beyond the cap,
    // so concurrent creates converge to exactly the cap instead of overshooting.
    // (Bounded mitigation; the lease reconciler remains the authoritative quota
    // enforcer for the residual list-cache race.)
    if let Ok(active) = active_lease_names_sorted(&leases_api, &identity.identity).await
        && lease_exceeds_quota(&active, &lease_id, policy.max_concurrent_leases)
    {
        let _ = leases_api.delete(&lease_id, &Default::default()).await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!(
                    "Concurrent lease limit ({}) reached",
                    policy.max_concurrent_leases
                ),
                detail: Some("A concurrent request won the quota race; please retry".to_string()),
                reason: None,
            }),
        )
            .into_response();
    }

    // #107 P2: alias-uniqueness concurrent-create race. Like the quota check
    // above, the pre-check is advisory — two requests with the same alias can
    // both pass it. Re-list the alias holders deterministically; if this lease
    // isn't the oldest, it lost the race, so self-delete and 409.
    if let Some(alias) = req.alias.as_deref()
        && let Ok(holders) =
            active_alias_holders_sorted(&leases_api, &identity.identity, alias).await
        && holders.first().map(|n| n.as_str()) != Some(lease_id.as_str())
    {
        // This lease lost the race; remove it so it can't linger as a second
        // active holder of the alias. There is NO alias reconciler backstop, so a
        // swallowed delete error would leave an orphaned duplicate (breaking the
        // uniqueness the CLI's `--ensure`/alias-select rely on). Surface a failed
        // cleanup as a retryable error rather than a clean-looking 409.
        if let Err(e) = leases_api.delete(&lease_id, &Default::default()).await {
            error!(
                lease_id = %lease_id,
                alias = %alias,
                error = %e,
                "Failed to delete alias-race-loser lease; it may linger as a duplicate alias holder until its TTL expires"
            );
            return infra_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Lost the alias race and failed to clean up the duplicate; please retry",
                e,
            );
        }
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("Alias '{alias}' is already in use by an active lease"),
                detail: Some("A concurrent request won the alias race; please retry".to_string()),
                reason: None,
            }),
        )
            .into_response();
    }

    metrics::CLAIMS_TOTAL
        .with_label_values(&[profile.as_str(), "created"])
        .inc();

    info!(
        lease_id = %lease_id,
        profile = %profile,
        identity = %identity.identity,
        priority = policy.default_priority,
        "Lease created, queued for binding"
    );

    let mut resp = LeaseResponse {
        id: lease_id,
        resource_kind: "Cluster",
        capabilities: cluster_lease_capabilities(&policy),
        kubeconfig: None,
        cluster_name: None,
        expires_at: None,
        phase: "Pending".to_string(),
        profile,
        queue_position: 0,
        diagnostics_url: None,
        effective_ttl: None,
        alias: req.alias.clone(),
        metadata: req.metadata,
        message: None,
        conditions: Vec::new(),
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
    Query(params): Query<ListLeasesParams>,
) -> Response {
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let label_hash = hash_identity(&identity.identity);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/requester-hash={label_hash}"));

    match leases_api.list(&lp).await {
        Ok(claims) => {
            let policy = policy_for(&identity);
            let mut my_claims: Vec<LeaseSummary> = claims
                .iter()
                .filter(|c| c.spec.requester.identity == identity.identity)
                // #107 P2: optional ?alias= filter (exact match on the alias label).
                .filter(|c| match &params.alias {
                    Some(alias) => lease_alias(c).as_deref() == Some(alias.as_str()),
                    None => true,
                })
                .map(|c| {
                    let alias = lease_alias(c);
                    let status = c.status.clone().unwrap_or_default();
                    LeaseSummary {
                        id: c.name_any(),
                        phase: status.phase.to_string(),
                        resource_kind: "Cluster",
                        capabilities: cluster_lease_capabilities(&policy),
                        profile: c.spec.pool_ref.clone(),
                        cluster_name: status.cluster_name,
                        expires_at: status.expires_at,
                        queue_position: status.queue_position,
                        diagnostics_url: status.diagnostics_url,
                        requester: None,
                        alias,
                        metadata: c.spec.metadata.as_deref().cloned(),
                    }
                })
                .collect();

            if state.sandbox_enabled {
                match crate::api::sandbox::caller_sandbox_summaries(&state, &identity).await {
                    Ok(sandboxes) => {
                        my_claims.extend(sandboxes.into_iter().filter_map(|lease| {
                            if params
                                .alias
                                .as_ref()
                                .is_some_and(|alias| lease.alias.as_deref() != Some(alias.as_str()))
                            {
                                return None;
                            }
                            Some(LeaseSummary {
                                id: lease.id,
                                phase: lease.phase,
                                resource_kind: "Sandbox",
                                capabilities: sandbox_lease_capabilities(&lease.pool, &policy),
                                profile: lease.pool,
                                cluster_name: None,
                                expires_at: lease.expires_at,
                                queue_position: 0,
                                diagnostics_url: None,
                                requester: None,
                                alias: lease.alias,
                                metadata: None,
                            })
                        }));
                    }
                    Err(error) => {
                        return infra_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to list Sandbox leases",
                            error,
                        );
                    }
                }
            }
            my_claims.sort_by(|left, right| left.id.cmp(&right.id));

            (StatusCode::OK, Json(my_claims)).into_response()
        }
        Err(e) => infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list leases",
            e,
        ),
    }
}

#[tracing::instrument(skip_all)]
async fn get_lease<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if state.sandbox_enabled && crate::api::sandbox_access::looks_like_lease_id(&id) {
        return crate::api::sandbox::get_sandbox_lease(State(state), identity, Path(id)).await;
    }
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    match leases_api.get(&id).await {
        Ok(lease) => {
            if lease.spec.requester.identity != identity.identity {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Lease not found".to_string(),
                        detail: None,
                        reason: None,
                    }),
                )
                    .into_response();
            }

            let mut status = lease.status.clone().unwrap_or_default();

            let kubeconfig = if status.phase == LeasePhase::Bound {
                let lease_uid = lease.metadata.uid.as_deref();
                let resolved = match lease_uid {
                    Some(uid) => {
                        resolve_lease_binding(
                            &state.client,
                            &state.namespace,
                            &id,
                            uid,
                            BindingResolveMode::Access,
                        )
                        .await
                    }
                    None => Err(BindingResolutionError::LeaseUidMismatch),
                };
                if let Ok(resolved) = resolved {
                    let cluster_name = resolved.binding.instance.name.clone();
                    match connect_server_url(&headers, &id) {
                        Ok(server_url) => match ensure_lease_connect_token(
                            &state.client,
                            &state.namespace,
                            &lease,
                            &resolved.binding,
                        )
                        .await
                        {
                            Ok(connect_token) => {
                                match build_connect_kubeconfig(
                                    &server_url,
                                    &id,
                                    Some(&cluster_name),
                                    &connect_token,
                                ) {
                                    Ok(kubeconfig) => Some(kubeconfig),
                                    Err(err) => {
                                        return infra_error(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            "Failed to build lease kubeconfig",
                                            err,
                                        );
                                    }
                                }
                            }
                            Err(err) => {
                                return infra_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to provision lease access token",
                                    err,
                                );
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
                                    reason: None,
                                }),
                            )
                                .into_response();
                        }
                    }
                } else {
                    let reason = resolved.unwrap_err().reason_code();
                    state.connect_cache.evict(&id);
                    warn!(lease_id = %id, reason, "Owned lease binding is unavailable; kubeconfig withheld");
                    status.message = Some(format!("binding unavailable: {reason}"));
                    None
                }
            } else {
                None
            };

            let alias = lease_alias(&lease);
            (
                StatusCode::OK,
                Json(LeaseResponse {
                    id,
                    resource_kind: "Cluster",
                    capabilities: cluster_lease_capabilities(&policy_for(&identity)),
                    kubeconfig,
                    cluster_name: status.cluster_name,
                    expires_at: status.expires_at,
                    phase: status.phase.to_string(),
                    profile: lease.spec.pool_ref,
                    queue_position: status.queue_position,
                    diagnostics_url: status.diagnostics_url,
                    effective_ttl: None,
                    alias,
                    metadata: lease.spec.metadata.map(|metadata| *metadata),
                    // #189: surface why a Pending lease isn't binding (pool health).
                    message: status.message,
                    // #189: structured conditions companion to `message`.
                    conditions: status.conditions,
                }),
            )
                .into_response()
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Lease not found".to_string(),
                detail: None,
                reason: None,
            }),
        )
            .into_response(),
        Err(e) => infra_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get lease", e),
    }
}

#[tracing::instrument(skip_all)]
async fn connect_proxy_root<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> Response {
    connect_proxy_inner(state, id, String::new(), request).await
}

#[tracing::instrument(skip_all)]
async fn connect_proxy<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    Path((id, path)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    connect_proxy_inner(state, id, path, request).await
}

async fn connect_proxy_inner<B: ClusterBackend>(
    state: AppState<B>,
    lease_id: String,
    path: String,
    request: axum::extract::Request,
) -> Response {
    // RAII latency timer: observes `kobe_connect_proxy_request_duration_seconds`
    // on Drop so every early return (and the upgrade hand-off) is timed. Defaults
    // to kind=buffered; flipped to kind=upgrade just before tunneling.
    let mut timer = ConnectProxyTimer::start();

    // Decompose the raw request: method / headers / query are needed by both
    // the buffered and the upgrade path. The body / OnUpgrade live in
    // `request`, which we keep intact and hand to `tunnel_upgrade` for the
    // streaming case (it needs `hyper::upgrade::on(&mut request)`).
    let method = request.method().clone();
    let headers = request.headers().clone();
    let raw_query = RawQuery(request.uri().query().map(str::to_string));

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
        return connect_reject(
            metrics::ConnectOutcome::MissingToken,
            StatusCode::UNAUTHORIZED,
            "Missing Bearer token",
        );
    };

    // ── Per-lease connect-context cache ──────────────────────────────────
    //
    // A single `kubectl` fans out into dozens of API calls through one lease.
    // The cache avoids repeated kubeconfig Secret extraction/parsing and client
    // construction, but it never caches authorization: every hit re-runs the
    // exact resolver and compares the complete immutable binding before the
    // credential-bearing backend context is reused. Phase, expiry, lease UID,
    // instance UID/generation, reciprocal binding, pool UID, and provenance are
    // therefore fresh on every request.
    //
    // These are owned so both the hit and miss branches converge on the same
    // bindings (a hit has no `lease` object to borrow from).
    let cluster_name: String;
    let chosen_backend: String;
    let pool_ref: String;
    let raw_kubeconfig: String;
    let backend: BackendAccess;

    match state.connect_cache.lookup(&lease_id, connect_token) {
        CacheLookup::Hit(cache_key, ctx) => {
            metrics::CONNECT_PROXY_CACHE_TOTAL
                .with_label_values(&["hit"])
                .inc();

            // Cache the expensive backend context, never the authorization.
            // The Secret may have been deleted or recreated under the same
            // name since this entry was built.
            let live_token = match validate_lease_connect_token(
                &state.client,
                &state.namespace,
                &lease_id,
                connect_token,
            )
            .await
            {
                Ok(Some(token)) => token,
                Ok(None) => {
                    state.connect_cache.evict(&lease_id);
                    return connect_reject(
                        metrics::ConnectOutcome::InvalidToken,
                        StatusCode::UNAUTHORIZED,
                        "Invalid lease token",
                    );
                }
                Err(error) => {
                    state.connect_cache.evict(&lease_id);
                    return connect_infra_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to validate lease token",
                        &error,
                        metrics::ConnectErrorReason::LeaseLookup,
                    );
                }
            };

            let resolved = match resolve_lease_binding(
                &state.client,
                &state.namespace,
                &lease_id,
                &live_token.lease_uid,
                BindingResolveMode::Access,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        reason = err.reason_code(),
                        "Connect proxy exact binding resolution failed (cached entry evicted)"
                    );
                    return binding_resolution_response(err);
                }
            };

            if live_token.lease_uid != cache_key.lease_uid
                || resolved
                    .binding
                    .connect_token
                    .as_ref()
                    .is_some_and(|identity| identity != &live_token.identity)
                || (resolved.binding.cleanup_mode.requires_receipt()
                    && resolved.binding.connect_token.is_none())
                || resolved.binding != ctx.binding
                || resolved.binding.instance.uid != cache_key.instance_uid
            {
                state.connect_cache.evict(&lease_id);
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    reason = "cache_fence_mismatch",
                    "Connect proxy cache fence changed (entry evicted)"
                );
                return connect_reject_with_reason(
                    metrics::ConnectOutcome::BackendError,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Lease binding is unavailable",
                    Some(metrics::ConnectErrorReason::CacheFence),
                );
            }

            cluster_name = ctx.cluster_name;
            chosen_backend = "cached".to_string();
            pool_ref = resolved.pool.name_any();
            raw_kubeconfig = ctx.raw_kubeconfig;
            backend = ctx.backend;
        }
        CacheLookup::Miss => {
            metrics::CONNECT_PROXY_CACHE_TOTAL
                .with_label_values(&["miss"])
                .inc();

            // ── Full cold path: authenticate the token to its owner lease UID,
            // run exact resolution, dispatch from immutable provenance, then
            // extract/build/cache the backend context. ─────────────────────
            let authenticated_token = match validate_lease_connect_token(
                &state.client,
                &state.namespace,
                &lease_id,
                connect_token,
            )
            .await
            {
                Ok(Some(token)) => token,
                Ok(None) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        method = %method,
                        path = %request_path,
                        "Connect proxy rejected invalid lease token"
                    );
                    return connect_reject(
                        metrics::ConnectOutcome::InvalidToken,
                        StatusCode::UNAUTHORIZED,
                        "Invalid lease token",
                    );
                }
                Err(err) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        error = %err,
                        "Connect proxy failed to validate lease token"
                    );
                    return connect_infra_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to validate lease token",
                        &err,
                        metrics::ConnectErrorReason::LeaseLookup,
                    );
                }
            };

            let resolved = match resolve_lease_binding(
                &state.client,
                &state.namespace,
                &lease_id,
                &authenticated_token.lease_uid,
                BindingResolveMode::Access,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        reason = err.reason_code(),
                        "Connect proxy exact binding resolution failed"
                    );
                    return binding_resolution_response(err);
                }
            };
            if resolved
                .binding
                .connect_token
                .as_ref()
                .is_some_and(|identity| identity != &authenticated_token.identity)
                || (resolved.binding.cleanup_mode.requires_receipt()
                    && resolved.binding.connect_token.is_none())
            {
                state.connect_cache.evict(&lease_id);
                return connect_reject_with_reason(
                    metrics::ConnectOutcome::BackendError,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Lease connect-token identity changed",
                    Some(metrics::ConnectErrorReason::CacheFence),
                );
            }
            let cluster = resolved.binding.instance.name.as_str();
            let resolved_backend = format!("{:?}", resolved.binding.backend.backend_type);
            let Some(factory) = state.factory.as_ref() else {
                state.connect_cache.evict(&lease_id);
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    reason = "backend_factory_unavailable",
                    "Connect proxy cannot reconstruct provenance-pinned backend"
                );
                return connect_reject_with_reason(
                    metrics::ConnectOutcome::BackendError,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Lease backend provenance is unavailable",
                    Some(metrics::ConnectErrorReason::BackendReconstruct),
                );
            };
            let dispatch = match factory.backend_for_provenance(&resolved.binding.backend) {
                Ok(dispatch) => dispatch,
                Err(err) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        reason = "backend_dispatch_invalid",
                        error = %err,
                        "Connect proxy failed to reconstruct provenance-pinned backend"
                    );
                    return connect_reject_with_reason(
                        metrics::ConnectOutcome::BackendError,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Lease backend provenance is unavailable",
                        Some(metrics::ConnectErrorReason::BackendReconstruct),
                    );
                }
            };
            let raw = match dispatch.extract_kubeconfig(cluster, &state.namespace).await {
                Ok(kubeconfig) => kubeconfig,
                Err(err) => {
                    state.connect_cache.evict(&lease_id);
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        pool = %resolved.binding.pool.name,
                        cluster = %cluster,
                        backend = %resolved_backend,
                        error = %err,
                        "Connect proxy failed to extract backend kubeconfig"
                    );
                    return connect_infra_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Failed to extract backend kubeconfig",
                        &err,
                        metrics::ConnectErrorReason::KubeconfigUnavailable,
                    );
                }
            };

            let built = match backend_access_from_kubeconfig(&raw) {
                Ok(b) => b,
                Err(err) => {
                    warn!(
                        request_id = %request_id,
                        lease_id = %lease_id,
                        cluster = %cluster,
                        error = %err,
                        "Connect proxy failed to parse backend kubeconfig"
                    );
                    return connect_infra_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to parse backend kubeconfig",
                        &err,
                        metrics::ConnectErrorReason::KubeconfigParse,
                    );
                }
            };

            // Populate the cache with the now-validated context. `connect_token`
            // is the token we just confirmed correct via `validate_lease_connect_token`.
            state.connect_cache.insert(
                lease_id.clone(),
                ConnectCtx {
                    cached_at: Instant::now(),
                    token: connect_token.to_string(),
                    cluster_name: cluster.to_string(),
                    binding: resolved.binding.clone(),
                    backend: built.clone(),
                    raw_kubeconfig: raw.clone(),
                },
            );

            cluster_name = cluster.to_string();
            chosen_backend = resolved_backend;
            pool_ref = resolved.binding.pool.name;
            raw_kubeconfig = raw;
            backend = built;
        }
    }

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
            return connect_infra_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build backend request",
                &err,
                metrics::ConnectErrorReason::UpstreamConfig,
            );
        }
    };

    // Streaming subprotocols (exec / attach / port-forward) negotiate an HTTP
    // Upgrade (SPDY or websocket). The buffered reqwest path below cannot carry
    // the 101 + hijacked socket through, so these are handled by a dedicated
    // tunnel that drives a raw hyper client over the backend TLS config and
    // splices the upgraded sockets (see api::upgrade). All lease validation has
    // already run above; from here we just need the backend's rustls config.
    if headers_request_upgrade(&headers) {
        // This request is an exec/attach/port-forward tunnel: relabel the
        // latency histogram so the upgrade path is measured separately.
        timer.set_kind("upgrade");
        let protocol =
            requested_upgrade_protocol(&headers).unwrap_or_else(|| "unknown".to_string());
        let upgrade_access = match build_backend_tls_config(&raw_kubeconfig) {
            Ok(access) => access,
            Err(err) => {
                warn!(
                    request_id = %request_id,
                    lease_id = %lease_id,
                    cluster = %cluster_name,
                    error = %err,
                    "Connect proxy failed to build backend TLS config for upgrade"
                );
                return connect_infra_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build backend TLS config",
                    &err,
                    metrics::ConnectErrorReason::UpstreamConfig,
                );
            }
        };
        // The upstream path is everything after the backend authority — i.e.
        // the already-resolved `request_url` minus its scheme+authority.
        let path_and_query = upstream_path_and_query(&request_url, &request_path, &raw_query.0);
        info!(
            request_id = %request_id,
            lease_id = %lease_id,
            cluster = %cluster_name,
            backend = %chosen_backend,
            upstream = %upgrade_access.server,
            method = %method,
            path = %request_path,
            protocol = %protocol,
            "Connect proxy tunneling HTTP upgrade (exec/attach/port-forward)"
        );
        // The outcome is recorded INSIDE tunnel_upgrade, not here.
        //
        // This used to count Ok before handing off, reasoning that "any failure
        // inside the tunnel is its own concern". That holds for failures in an
        // established tunnel — but the dial, TLS handshake and HTTP/1 handshake
        // all happen BEFORE any tunnel exists, and each returns 502/504 to the
        // caller. Counting those as successes made a real outage invisible:
        // callers saw "Failed to reach leased cluster" while the success rate
        // stayed flat (#107).
        return crate::api::upgrade::tunnel_upgrade(
            request,
            upgrade_access,
            &path_and_query,
            request_id,
            &lease_id,
        )
        .await;
    }

    info!(
        request_id = %request_id,
        lease_id = %lease_id,
        pool = %pool_ref,
        cluster = %cluster_name,
        backend = %chosen_backend,
        upstream = %backend.server,
        method = %method,
        path = %request_path,
        query = raw_query.0.as_deref().unwrap_or(""),
        "Connect proxy forwarding request upstream"
    );

    // Non-upgrade path: consume the body. `request` is still owned here (the
    // upgrade branch above returns early, taking ownership for the tunnel).
    let body = request.into_body();
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
            return connect_infra_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Failed to read request body",
                &err,
                metrics::ConnectErrorReason::RequestBody,
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
            return connect_infra_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "Unsupported method",
                &err,
                metrics::ConnectErrorReason::UnsupportedMethod,
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
            return connect_infra_error(
                StatusCode::BAD_GATEWAY,
                "Failed to reach leased cluster",
                &err,
                metrics::ConnectErrorReason::UpstreamUnreachable,
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
                return connect_infra_error(
                    StatusCode::BAD_GATEWAY,
                    "Failed to read leased cluster response",
                    &err,
                    metrics::ConnectErrorReason::UpstreamResponse,
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

        // The proxy reached the backend and is relaying its response (even a
        // 5xx FROM the leased cluster is a successful proxy outcome — the
        // rejection counter is for the proxy's own accept/reject decisions).
        metrics::CONNECT_PROXY_REQUEST_OUTCOME_TOTAL
            .with_label_values(&[metrics::ConnectOutcome::Ok.as_str()])
            .inc();
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

    // Successful proxy: response is being streamed downstream.
    metrics::CONNECT_PROXY_REQUEST_OUTCOME_TOTAL
        .with_label_values(&[metrics::ConnectOutcome::Ok.as_str()])
        .inc();
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
    if state.sandbox_enabled && crate::api::sandbox_access::looks_like_lease_id(&id) {
        return crate::api::sandbox::release_sandbox_lease(State(state), identity, Path(id)).await;
    }
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);

    let lease = match leases_api.get(&id).await {
        Ok(c) => c,
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => {
            return infra_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get lease", e);
        }
    };

    if lease.spec.requester.identity != identity.identity {
        return StatusCode::NOT_FOUND.into_response();
    }

    let status = lease.status.clone().unwrap_or_default();

    if status.phase == LeasePhase::Quarantined {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Lease is quarantined".to_string(),
                detail: Some(
                    "Verified teardown evidence is incomplete; release cannot downgrade it"
                        .to_string(),
                ),
                reason: Some(ErrorReason::TeardownQuarantined),
            }),
        )
            .into_response();
    }

    if matches!(
        status.phase,
        LeasePhase::Released | LeasePhase::Expired | LeasePhase::Recycling
    ) {
        return StatusCode::NO_CONTENT.into_response();
    }

    // Release by exact object, never by name. Between the read above and this
    // write the lease could be deleted and a same-named one recreated by
    // another requester; a merge patch would release theirs. The `test` ops
    // make the API server reject that instead.
    let (Some(uid), Some(rv)) = (lease.metadata.uid.as_deref(), lease.resource_version()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": rv },
        { "op": "test", "path": "/status/phase", "value": status.phase },
        { "op": "add", "path": "/status/phase", "value": "Released" }
    ]));
    if let Err(e) = leases_api
        .patch_status(&id, &PatchParams::default(), &KubePatch::<()>::Json(patch))
        .await
    {
        // A failed precondition means the object we authorized is no longer the
        // object on the server. Report it as gone rather than retrying blindly.
        if crate::controllers::lease::optimistic_conflict(&e) {
            return StatusCode::NOT_FOUND.into_response();
        }
        return infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to release lease",
            e,
        );
    }

    metrics::CLAIMS_TOTAL
        .with_label_values(&[lease.spec.pool_ref.as_str(), "released"])
        .inc();

    if status.phase == LeasePhase::Pending {
        // A client cancelling a still-queued claim: record how long it waited
        // before giving up (the flip side of a bind), from the object's
        // creation to now.
        if let Some(waited) = metrics::elapsed_secs_since_rfc3339(
            lease
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| ts.0.to_string())
                .as_deref(),
        ) {
            metrics::LEASE_QUEUE_WAIT_SECONDS
                .with_label_values(&[lease.spec.pool_ref.as_str(), "cancelled"])
                .observe(waited);
        }
        info!(lease_id = %id, "Pending lease cancelled");
    } else {
        // A Bound lease released by the client: record how long it was held.
        if let Some(held) = metrics::elapsed_secs_since_rfc3339(status.bound_at.as_deref()) {
            metrics::LEASE_HOLD_SECONDS
                .with_label_values(&[lease.spec.pool_ref.as_str(), "released"])
                .observe(held);
        }
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
    if state.sandbox_enabled && crate::api::sandbox_access::looks_like_lease_id(&id) {
        return crate::api::sandbox::extend_sandbox_lease(
            State(state),
            identity,
            Path(id),
            Json(crate::api::sandbox::ExtendSandboxLeaseRequest {
                extend_ttl: req.extend_ttl,
            }),
        )
        .await;
    }
    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    // Carry the UID of the object we authorized into the mutation, so the
    // extend cannot land on a same-named lease created after this check.
    let authorized_uid = match leases_api.get(&id).await {
        Ok(lease) => {
            if lease.spec.requester.identity != identity.identity {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Lease not found".to_string(),
                        detail: None,
                        reason: None,
                    }),
                )
                    .into_response();
            }
            match lease.metadata.uid.clone() {
                Some(uid) => uid,
                None => {
                    return StatusCode::NOT_FOUND.into_response();
                }
            }
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Lease not found".to_string(),
                    detail: None,
                    reason: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            return infra_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get lease", e);
        }
    };

    match extend_lease_ttl(
        &state.client,
        &state.namespace,
        &id,
        &req.extend_ttl,
        &authorized_uid,
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
                reason: None,
            }),
        )
            .into_response(),
        Err(crate::controllers::lease::LeaseError::Kube(e)) => infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to extend lease",
            e,
        ),
    }
}

#[tracing::instrument(skip_all)]
async fn get_diagnostics<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(id): Path<String>,
) -> Response {
    if crate::api::sandbox_access::looks_like_lease_id(&id) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Diagnostics are a Cluster lease capability".to_string(),
                detail: Some("This id is a Sandbox lease".to_string()),
                reason: Some(ErrorReason::WrongResourceKind),
            }),
        )
            .into_response();
    }
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
                        reason: None,
                    }),
                )
                    .into_response()
            }
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => StatusCode::NOT_FOUND.into_response(),
        Err(e) => infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to look up lease",
            e,
        ),
    }
}

#[tracing::instrument(skip_all)]
async fn list_pools<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
) -> Response {
    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let policy = policy_for(&identity);

    match profiles_api.list(&ListParams::default()).await {
        Ok(profiles) => {
            let mut response: Vec<ProfileResponse> = profiles
                .iter()
                .filter(|p| is_pool_allowed(&p.name_any(), &policy))
                .map(|profile| profile_response(profile, &policy))
                .collect();

            if state.sandbox_enabled {
                let sandbox_pools: Api<SandboxPool> =
                    Api::namespaced(state.client.clone(), &state.namespace);
                match sandbox_pools.list(&ListParams::default()).await {
                    Ok(pools) => response.extend(
                        pools
                            .iter()
                            .filter(|pool| {
                                is_sandbox_allowed(&pool.name_any(), SandboxVerb::Lease, &policy)
                            })
                            .map(|pool| sandbox_pool_response(pool, &policy)),
                    ),
                    Err(error) => {
                        return infra_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to list Sandbox pools",
                            error,
                        );
                    }
                }
            }

            response.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then(left.resource_kind.cmp(right.resource_kind))
            });

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list profiles",
            e,
        ),
    }
}

#[tracing::instrument(skip_all)]
async fn get_pool<B: ClusterBackend>(
    State(state): State<AppState<B>>,
    identity: AuthIdentity,
    Path(name): Path<String>,
) -> Response {
    let policy = policy_for(&identity);
    let profiles_api: Api<ClusterPool> = Api::namespaced(state.client.clone(), &state.namespace);
    let cluster = match profiles_api.get_opt(&name).await {
        Ok(cluster) => cluster,
        Err(error) => {
            return infra_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get Cluster pool",
                error,
            );
        }
    };
    let sandbox = if state.sandbox_enabled {
        let pools: Api<SandboxPool> = Api::namespaced(state.client.clone(), &state.namespace);
        match pools.get_opt(&name).await {
            Ok(pool) => pool,
            Err(error) => {
                return infra_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get Sandbox pool",
                    error,
                );
            }
        }
    } else {
        None
    };

    let cluster_allowed = cluster.as_ref().filter(|_| is_pool_allowed(&name, &policy));
    let sandbox_allowed = sandbox
        .as_ref()
        .filter(|_| is_sandbox_allowed(&name, SandboxVerb::Lease, &policy));
    match (cluster_allowed, sandbox_allowed) {
        (Some(_), Some(_)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!(
                    "Pool name '{name}' is ambiguous across Cluster and Sandbox resources"
                ),
                detail: Some("Pool names must be unique across resource kinds".to_string()),
                reason: None,
            }),
        )
            .into_response(),
        (Some(profile), None) => {
            (StatusCode::OK, Json(profile_response(profile, &policy))).into_response()
        }
        (None, Some(pool)) => {
            (StatusCode::OK, Json(sandbox_pool_response(pool, &policy))).into_response()
        }
        (None, None) if cluster.is_some() || sandbox.is_some() => {
            StatusCode::FORBIDDEN.into_response()
        }
        (None, None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Pool not found".to_string(),
                detail: None,
                reason: None,
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
    let sandbox_ok =
        state.sandbox_enabled && is_sandbox_allowed(&pool_name, SandboxVerb::Lease, &policy);
    if sandbox_ok && !is_pool_allowed(&pool_name, &policy) {
        match crate::api::sandbox::caller_sandbox_summaries(&state, &identity).await {
            Ok(leases) => {
                let summaries: Vec<LeaseSummary> = leases
                    .into_iter()
                    .filter(|lease| lease.pool == pool_name)
                    .map(|lease| LeaseSummary {
                        id: lease.id,
                        phase: lease.phase,
                        resource_kind: "Sandbox",
                        capabilities: sandbox_lease_capabilities(&lease.pool, &policy),
                        profile: lease.pool,
                        cluster_name: None,
                        expires_at: lease.expires_at,
                        queue_position: 0,
                        diagnostics_url: None,
                        requester: None,
                        alias: lease.alias,
                        metadata: None,
                    })
                    .collect();
                return (StatusCode::OK, Json(summaries)).into_response();
            }
            Err(error) => {
                return infra_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to list Sandbox pool leases",
                    error,
                );
            }
        }
    }
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
                .map(|c| pool_lease_summary(c, &identity.identity))
                .collect();

            (StatusCode::OK, Json(summaries)).into_response()
        }
        Err(e) => infra_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list pool leases",
            e,
        ),
    }
}

/// Summarize one active pool lease without crossing tenant boundaries.
/// Utilization fields are shared, while requester-controlled identity, alias,
/// and metadata are disclosed only when the caller owns the lease.
fn pool_lease_summary(lease: &ClusterLease, caller_identity: &str) -> LeaseSummary {
    let status = lease.status.clone().unwrap_or_default();
    let own = lease.spec.requester.identity == caller_identity;
    LeaseSummary {
        id: lease.name_any(),
        phase: status.phase.to_string(),
        resource_kind: "Cluster",
        capabilities: Vec::new(),
        profile: lease.spec.pool_ref.clone(),
        cluster_name: status.cluster_name,
        expires_at: status.expires_at,
        queue_position: status.queue_position,
        diagnostics_url: None,
        requester: own.then(|| lease.spec.requester.identity.clone()),
        alias: own.then(|| lease_alias(lease)).flatten(),
        metadata: own
            .then(|| lease.spec.metadata.as_deref().cloned())
            .flatten(),
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
    quarantined: u32,
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
                total: status.ready
                    + status.leased
                    + status.creating
                    + status.recycling
                    + status.unhealthy
                    + status.quarantined,
                quarantined: status.quarantined,
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

    // PostgreSQL — only when a datastore is configured. In embedded-datastore
    // mode there is nothing to check.
    if let Some((pool, _)) = state.datastore.current()
        && let Err(e) = readyz_check_postgres(&pool).await
    {
        failures.push(format!("postgres: {e}"));
    }

    // Surface a persistently-stale credential rotation: the mounted Secret
    // changed but the new value keeps failing to load, so the operator is still
    // on the previous credential. The postgres check above catches outright
    // revocation; this warns *before* that, so an alert can fire on the gap.
    if let Some(kunobi_reload::ReloadStatus::Stale { last_error, .. }) =
        state.datastore.reload_status()
    {
        warn!(
            last_error = %last_error,
            "PostgreSQL credential reload is stale; running on the previous credential"
        );
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

    let leases_api: Api<ClusterLease> = Api::namespaced(state.client.clone(), &state.namespace);
    let leases = match leases_api.list(&ListParams::default()).await {
        Ok(leases) => leases,
        Err(e) => {
            tracing::warn!("Failed to list leases for metrics endpoint: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "failed to list leases").into_response();
        }
    };

    let instances_api: Api<ClusterInstance> =
        Api::namespaced(state.client.clone(), &state.namespace);
    let instances = match instances_api.list(&ListParams::default()).await {
        Ok(instances) => instances,
        Err(e) => {
            tracing::warn!("Failed to list instances for metrics endpoint: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "failed to list instances").into_response();
        }
    };

    let claims_api: Api<CIDRClaim> = Api::namespaced(state.client.clone(), &state.namespace);
    let claims = match claims_api.list(&ListParams::default()).await {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!("Failed to list CIDR claims for metrics endpoint: {e}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "failed to list CIDR claims",
            )
                .into_response();
        }
    };

    metrics::POOL_CLUSTERS.reset();
    metrics::QUEUE_DEPTH.reset();
    metrics::LEASE_OLDEST_PENDING_AGE_SECONDS.reset();
    metrics::INSTANCE_OLDEST_CREATING_AGE_SECONDS.reset();

    let mut oldest_pending = std::collections::HashMap::<String, i64>::new();
    let mut oldest_creating = std::collections::HashMap::<String, i64>::new();

    for profile in profiles.iter() {
        let name = profile.name_any();
        oldest_pending.insert(name.clone(), 0);
        oldest_creating.insert(name.clone(), 0);
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

    let now_ms = chrono::Utc::now().timestamp_millis();
    for lease in leases.iter() {
        if lease.status.as_ref().map(|s| &s.phase) != Some(&LeasePhase::Pending) {
            continue;
        }
        let age = lease
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|ts| ((now_ms - ts.0.as_millisecond()).max(0)) / 1000)
            .unwrap_or(0);
        oldest_pending
            .entry(lease.spec.pool_ref.clone())
            .and_modify(|current| *current = (*current).max(age))
            .or_insert(age);
    }

    for instance in instances.iter() {
        let Some(status) = instance.status.as_ref() else {
            continue;
        };
        if status.phase != ClusterInstancePhase::Creating {
            continue;
        }
        let age = metrics::elapsed_secs_since_rfc3339(status.state_since.as_deref())
            .unwrap_or(0.0)
            .floor() as i64;
        let profile = instance
            .spec
            .pool_ref
            .as_ref()
            .map(|reference| reference.name.clone())
            .unwrap_or_else(|| "standalone".to_string());
        oldest_creating
            .entry(profile)
            .and_modify(|current| *current = (*current).max(age))
            .or_insert(age);
    }

    for (profile, age) in oldest_pending {
        metrics::LEASE_OLDEST_PENDING_AGE_SECONDS
            .with_label_values(&[profile.as_str()])
            .set(age);
    }
    for (profile, age) in oldest_creating {
        metrics::INSTANCE_OLDEST_CREATING_AGE_SECONDS
            .with_label_values(&[profile.as_str()])
            .set(age);
    }

    let allocated = claims
        .iter()
        .filter(|claim| {
            claim.status.as_ref().map(|status| &status.phase) == Some(&CIDRClaimPhase::Bound)
        })
        .count() as i64;
    metrics::IPAM_POOL_ALLOCATED
        .with_label_values(&[] as &[&str])
        .set(allocated);

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

/// Names of an identity's active (Pending|Bound) leases, in a deterministic
/// order (oldest first, then by name). The order is stable across concurrent
/// requests so they agree on which leases are "excess" over the quota.
async fn active_lease_names_sorted(
    leases_api: &Api<ClusterLease>,
    identity: &str,
) -> Result<Vec<String>, kube::Error> {
    let label_hash = hash_identity(identity);
    let lp =
        ListParams::default().labels(&format!("kobe.kunobi.ninja/requester-hash={label_hash}"));
    let leases = leases_api.list(&lp).await?;
    let mut active: Vec<(String, String)> = leases
        .iter()
        .filter(|c| c.spec.requester.identity == identity)
        .filter(|c| {
            let status = c.status.clone().unwrap_or_default();
            matches!(status.phase, LeasePhase::Pending | LeasePhase::Bound)
        })
        .map(|c| {
            let ts = c
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| t.0.to_string())
                .unwrap_or_default();
            (ts, c.name_any())
        })
        .collect();
    // RFC3339 timestamps sort chronologically as strings; the name (random lease
    // id) breaks same-second ties consistently.
    active.sort();
    Ok(active.into_iter().map(|(_, name)| name).collect())
}

/// Names of an identity's ACTIVE (Pending|Bound) leases carrying `alias`, in the
/// same deterministic order as [`active_lease_names_sorted`] (oldest first, then
/// by name). Used for alias-uniqueness enforcement (#107 P2): the first holder
/// keeps the alias; any later concurrent claimant self-deletes. Filters by the
/// alias label server-side, then by exact identity (two identities may reuse an
/// alias) and active phase in-process.
async fn active_alias_holders_sorted(
    leases_api: &Api<ClusterLease>,
    identity: &str,
    alias: &str,
) -> Result<Vec<String>, kube::Error> {
    let lp = ListParams::default().labels(&format!("{ALIAS_LABEL}={alias}"));
    let leases = leases_api.list(&lp).await?;
    let mut active: Vec<(String, String)> = leases
        .iter()
        .filter(|c| c.spec.requester.identity == identity)
        .filter(|c| {
            let status = c.status.clone().unwrap_or_default();
            matches!(status.phase, LeasePhase::Pending | LeasePhase::Bound)
        })
        .map(|c| {
            let ts = c
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| t.0.to_string())
                .unwrap_or_default();
            (ts, c.name_any())
        })
        .collect();
    active.sort();
    Ok(active.into_iter().map(|(_, name)| name).collect())
}

/// Whether `lease_id` ranks beyond the cap among the identity's deterministically
/// ordered active leases — i.e. it lost a concurrent-create race and should
/// self-delete. Unknown lease (not in the list) => not excess.
fn lease_exceeds_quota(active_sorted: &[String], lease_id: &str, cap: u32) -> bool {
    active_sorted
        .iter()
        .position(|n| n == lease_id)
        .map(|rank| rank >= cap as usize)
        .unwrap_or(false)
}

/// Label key carrying the caller-supplied lease alias (#107 P2). A label (not a
/// spec field) so leases can be filtered server-side via the label selector and
/// no CRD schema change is needed.
const ALIAS_LABEL: &str = "kobe.kunobi.ninja/alias";

/// Read the alias label off a lease, if present.
fn lease_alias(lease: &ClusterLease) -> Option<String> {
    lease.metadata.labels.as_ref()?.get(ALIAS_LABEL).cloned()
}

#[allow(clippy::too_many_arguments)]
fn build_lease_crd(
    lease_id: &str,
    namespace: &str,
    profile: &str,
    ttl: &str,
    identity: &AuthIdentity,
    priority: u32,
    alias: Option<&str>,
    metadata: Option<serde_json::Value>,
) -> ClusterLease {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/profile".to_string(), profile.to_string());
    labels.insert(
        "kobe.kunobi.ninja/requester-hash".to_string(),
        hash_identity(&identity.identity),
    );
    if let Some(alias) = alias {
        labels.insert(ALIAS_LABEL.to_string(), alias.to_string());
    }

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
            metadata: metadata.map(Box::new),
            priority,
            // Callers cannot request verified teardown: it is an internal
            // composition detail of #74's child placement, not tenant-facing
            // intent. Absent means Standard, so behaviour is unchanged.
            cleanup_mode: None,
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

    use axum::http::Method;
    use base64::Engine;

    // NOTE: the local `lease_is_expired` helper this module used to own is
    // gone. Expiry is now decided inside `resolve_lease_binding`, which is
    // strictly stricter: a missing or unparseable `expiresAt` denies instead of
    // reading as "not expired". `lease_binding::tests::expiry_gate_fails_closed`
    // pins all three outcomes.

    /// Build a `ConnectCtx` for cache tests. `age` ages `cached_at` into the
    /// past so the staleness branch can be exercised without sleeping.
    fn test_ctx(lease_name: &str, token: &str) -> ConnectCtx {
        let binding = LeaseBinding {
            binding_id: format!("binding-{lease_name}"),
            lease: crate::crd::ResourceRef {
                name: lease_name.to_string(),
                uid: Some(format!("{lease_name}-uid")),
            },
            instance: crate::crd::BoundInstanceRef {
                name: "pool-ci-small-6".to_string(),
                uid: format!("{lease_name}-instance-uid"),
                observed_generation: 1,
            },
            pool: crate::crd::ResourceRef {
                name: "ci-small".to_string(),
                uid: Some("pool-uid".to_string()),
            },
            backend: crate::crd::BackendProvenance::from_config(
                &crate::crd::BackendConfig::default(),
            )
            .unwrap(),
            instance_spec_digest: "0123456789abcdef".to_string(),
            cleanup_mode: crate::crd::CleanupMode::Standard,
            creation_manifest_digest: None,
            creation_manifest: None,
            connect_token: None,
        };
        ConnectCtx {
            cached_at: Instant::now(),
            token: token.to_string(),
            cluster_name: "pool-ci-small-6".to_string(),
            binding,
            backend: BackendAccess {
                server: "https://backend.svc:6443".to_string(),
                client: reqwest::Client::new(),
                bearer_token: Some("backend-bearer".to_string()),
            },
            raw_kubeconfig: "raw-kubeconfig".to_string(),
        }
    }

    #[test]
    fn connect_cache_hit_within_ttl_matching_token() {
        let cache = ConnectCache::default();
        cache.insert("lease-1".to_string(), test_ctx("lease-1", "good-token"));

        match cache.lookup("lease-1", "good-token") {
            CacheLookup::Hit(key, ctx) => {
                assert_eq!(key.lease_uid, "lease-1-uid");
                assert_eq!(key.instance_uid, "lease-1-instance-uid");
                assert_eq!(ctx.cluster_name, "pool-ci-small-6");
                assert_eq!(ctx.backend.server, "https://backend.svc:6443");
                assert_eq!(ctx.backend.bearer_token.as_deref(), Some("backend-bearer"));
                assert_eq!(ctx.raw_kubeconfig, "raw-kubeconfig");
            }
            CacheLookup::Miss => panic!("expected a cache hit for a fresh matching entry"),
        }
    }

    #[test]
    fn connect_cache_miss_on_token_mismatch() {
        // A presented token that does not match the cached token must MISS so it
        // is forced back through full revalidation — never served cached context.
        let cache = ConnectCache::default();
        cache.insert("lease-1".to_string(), test_ctx("lease-1", "good-token"));

        assert!(
            matches!(cache.lookup("lease-1", "wrong-token"), CacheLookup::Miss),
            "a mismatched token must be a cache miss"
        );
        // The non-matching lookup must not have evicted the valid entry.
        assert!(
            matches!(cache.lookup("lease-1", "good-token"), CacheLookup::Hit(..)),
            "the original entry should still be present after a mismatch"
        );
    }

    #[test]
    fn connect_cache_miss_when_stale() {
        let cache = ConnectCache::default();
        cache.insert("lease-1".to_string(), test_ctx("lease-1", "good-token"));
        // Age the entry past the TTL without sleeping.
        {
            let mut map = cache.0.lock().unwrap();
            let entry = map.values_mut().next().unwrap();
            entry.cached_at = Instant::now()
                .checked_sub(CONNECT_CACHE_TTL + std::time::Duration::from_secs(1))
                .expect("instant underflow");
        }

        assert!(
            matches!(cache.lookup("lease-1", "good-token"), CacheLookup::Miss),
            "an entry older than the TTL must be a cache miss"
        );
    }

    #[test]
    fn connect_cache_miss_when_absent() {
        let cache = ConnectCache::default();
        assert!(matches!(cache.lookup("nope", "token"), CacheLookup::Miss));
    }

    #[test]
    fn connect_cache_evict_removes_entry() {
        // Mirrors the expired-on-hit path: a hit that is then found expired
        // evicts the entry so a stale context can't be served again.
        let cache = ConnectCache::default();
        cache.insert("lease-1".to_string(), test_ctx("lease-1", "good-token"));

        let CacheLookup::Hit(_, _) = cache.lookup("lease-1", "good-token") else {
            panic!("expected a hit");
        };
        cache.evict("lease-1");

        assert!(
            matches!(cache.lookup("lease-1", "good-token"), CacheLookup::Miss),
            "an evicted entry must no longer hit"
        );
    }

    #[test]
    fn connect_cache_insert_prunes_stale_entries() {
        // `insert` opportunistically prunes entries older than the TTL while it
        // holds the lock, so the map only ever retains active leases.
        let cache = ConnectCache::default();
        cache.insert("stale".to_string(), test_ctx("stale", "t"));
        {
            let mut map = cache.0.lock().unwrap();
            let entry = map.values_mut().next().unwrap();
            entry.cached_at = Instant::now()
                .checked_sub(CONNECT_CACHE_TTL + std::time::Duration::from_secs(1))
                .expect("instant underflow");
        }

        // Inserting a fresh, unrelated lease should prune the stale one.
        cache.insert("fresh".to_string(), test_ctx("fresh", "t2"));

        let map = cache.0.lock().unwrap();
        assert!(
            !map.keys().any(|key| key.lease_name == "stale"),
            "stale entry should be pruned"
        );
        assert!(
            map.keys().any(|key| key.lease_name == "fresh"),
            "fresh entry should remain"
        );
    }

    #[test]
    fn connect_cache_replaces_same_name_when_uid_fence_changes() {
        let cache = ConnectCache::default();
        cache.insert("lease-1".to_string(), test_ctx("lease-1", "old-token"));
        let mut replacement = test_ctx("lease-1", "new-token");
        replacement.binding.lease.uid = Some("replacement-lease-uid".to_string());
        replacement.binding.instance.uid = "replacement-instance-uid".to_string();
        cache.insert("lease-1".to_string(), replacement);

        assert!(matches!(
            cache.lookup("lease-1", "old-token"),
            CacheLookup::Miss
        ));
        let CacheLookup::Hit(key, _) = cache.lookup("lease-1", "new-token") else {
            panic!("replacement fence should be cached");
        };
        assert_eq!(key.lease_uid, "replacement-lease-uid");
        assert_eq!(key.instance_uid, "replacement-instance-uid");
        assert_eq!(cache.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_lease_exceeds_quota() {
        let active = vec![
            "lease-a".to_string(),
            "lease-b".to_string(),
            "lease-c".to_string(),
        ];
        // cap 2: ranks 0,1 survive; rank 2 (lease-c) is excess.
        assert!(!lease_exceeds_quota(&active, "lease-a", 2));
        assert!(!lease_exceeds_quota(&active, "lease-b", 2));
        assert!(lease_exceeds_quota(&active, "lease-c", 2));
        // cap >= len: nothing is excess.
        assert!(!lease_exceeds_quota(&active, "lease-c", 3));
        // unknown lease (e.g. already deleted): not excess.
        assert!(!lease_exceeds_quota(&active, "lease-z", 1));
    }

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
            provider: "github-actions".to_string(),
            requester_type: "github-actions:ci".to_string(),
            identity: "repo:org/repo:ref:refs/heads/main".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            policy: crate::api::policy::Policy {
                allowed_pools: vec!["e2e-*".to_string()],
                max_ttl: chrono::Duration::hours(2),
                max_concurrent_leases: 5,
                default_priority: 100,
                max_extensions: 2,
                sandbox: None,
            },
        }
    }

    #[test]
    fn test_build_lease_crd_basic() {
        let identity = test_identity();
        let claim = build_lease_crd(
            "lease-abc123",
            "test-ns",
            "e2e-basic",
            "1h",
            &identity,
            80,
            None,
            None,
        );

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

        // #107 P2: no alias label when none is supplied.
        assert_eq!(lease_alias(&claim), None);
    }

    // #107 P2: an alias is stamped as the `kobe.kunobi.ninja/alias` label and
    // round-trips through `lease_alias`, which is what the list filter and the
    // uniqueness check key off.
    #[test]
    fn test_build_lease_crd_stamps_alias_label() {
        let identity = test_identity();
        let claim = build_lease_crd(
            "lease-1",
            "ns",
            "p",
            "1h",
            &identity,
            50,
            Some("pr-106"),
            None,
        );
        assert_eq!(
            claim
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("kobe.kunobi.ninja/alias"))
                .map(String::as_str),
            Some("pr-106"),
        );
        assert_eq!(lease_alias(&claim).as_deref(), Some("pr-106"));
    }

    #[test]
    fn test_build_lease_crd_labels() {
        let identity = test_identity();
        let claim = build_lease_crd(
            "lease-xyz",
            "ns1",
            "e2e-full",
            "30m",
            &identity,
            50,
            None,
            None,
        );

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
    fn lease_metadata_is_preserved_without_becoming_a_kubernetes_label() {
        let identity = test_identity();
        let metadata = serde_json::json!({
            "github": {"actor": "lenij", "pullRequest": 3835, "runId": 123456789},
            "purpose": "e2e"
        });
        let lease = build_lease_crd(
            "lease-metadata",
            "ns",
            "ci",
            "1h",
            &identity,
            50,
            None,
            Some(metadata.clone()),
        );

        assert_eq!(lease.spec.metadata.as_deref(), Some(&metadata));
        assert_eq!(
            lease.metadata.labels.as_ref().map(|labels| labels.len()),
            Some(2)
        );
    }

    #[test]
    fn lease_metadata_validation_accepts_bounded_json_objects() {
        let metadata = serde_json::json!({
            "github": {"actor": "lenij", "pr": 3835},
            "tags": ["e2e", "pull-request"]
        });
        assert_eq!(validate_lease_metadata(&metadata), Ok(()));
        assert_eq!(validate_lease_metadata(&serde_json::json!({})), Ok(()));
    }

    #[test]
    fn lease_metadata_validation_rejects_unbounded_or_non_object_values() {
        assert!(validate_lease_metadata(&serde_json::json!(["not", "an", "object"])).is_err());

        let too_deep = serde_json::json!({"a": {"b": {"c": {"d": true}}}});
        assert!(validate_lease_metadata(&too_deep).is_err());

        let too_many_values = serde_json::json!({"values": vec![0; MAX_LEASE_METADATA_NODES]});
        assert!(validate_lease_metadata(&too_many_values).is_err());

        let too_large = serde_json::json!({"value": "x".repeat(MAX_LEASE_METADATA_BYTES)});
        assert!(validate_lease_metadata(&too_large).is_err());

        let too_many_keys = serde_json::Value::Object(
            (0..=MAX_LEASE_METADATA_TOP_LEVEL_KEYS)
                .map(|index| (format!("key-{index}"), serde_json::Value::Null))
                .collect(),
        );
        assert!(validate_lease_metadata(&too_many_keys).is_err());
    }

    #[test]
    fn pool_lease_summary_redacts_foreign_metadata_with_identity_and_alias() {
        let identity = test_identity();
        let lease = build_lease_crd(
            "lease-private",
            "ns",
            "ci",
            "1h",
            &identity,
            50,
            Some("pr-3835"),
            Some(serde_json::json!({"actor": "lenij"})),
        );

        let own = pool_lease_summary(&lease, &identity.identity);
        assert_eq!(own.requester.as_deref(), Some(identity.identity.as_str()));
        assert_eq!(own.alias.as_deref(), Some("pr-3835"));
        assert_eq!(own.metadata, Some(serde_json::json!({"actor": "lenij"})));

        let foreign = pool_lease_summary(&lease, "repo:other/repo:ref:refs/heads/main");
        assert!(foreign.requester.is_none());
        assert!(foreign.alias.is_none());
        assert!(foreign.metadata.is_none());
    }

    #[test]
    fn test_build_lease_crd_status_is_none() {
        let identity = test_identity();
        let claim = build_lease_crd("lease-001", "ns", "dev", "2h", &identity, 100, None, None);

        // The CRD is created without status; the controller sets it later
        assert!(
            claim.status.is_none(),
            "Initial lease CRD should have no status"
        );
    }

    #[test]
    fn test_build_lease_crd_different_priority() {
        let identity = test_identity();
        let claim_low = build_lease_crd("c1", "ns", "p", "1h", &identity, 10, None, None);
        let claim_high = build_lease_crd("c2", "ns", "p", "1h", &identity, 200, None, None);

        assert_eq!(claim_low.spec.priority, 10);
        assert_eq!(claim_high.spec.priority, 200);
    }

    // --- Router / handler tests using tower::ServiceExt::oneshot ---

    use tower::ServiceExt;

    /// Helper: build an axum Router backed by MockBackend and wiremock.
    async fn test_app_with_sandbox(sandbox_enabled: bool) -> (Router, wiremock::MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));

        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled,
        };

        (build_router(state), server)
    }

    async fn test_app() -> (Router, wiremock::MockServer) {
        test_app_with_sandbox(true).await
    }

    /// Release is a mutation, so it must pin the exact object it authorized.
    ///
    /// Reading by name and then patching by name leaves a window: if the lease
    /// is deleted and another requester creates one with the same name, a merge
    /// patch releases *their* lease. The `test` ops make the API server refuse
    /// instead, and a rejected precondition surfaces as 404 rather than 500.
    #[tokio::test]
    async fn release_is_uid_fenced() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let state = AppState {
            client,
            backend: crate::testutil::MockBackend::new(),
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator: Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string())),
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/rel-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_object_json(
                "rel-1",
                &test_identity().identity,
                "Bound",
                Some("pool-ci-small-6"),
            )))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/rel-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_object_json(
                "rel-1",
                &test_identity().identity,
                "Released",
                Some("pool-ci-small-6"),
            )))
            .mount(&server)
            .await;

        let response = release_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Path("rel-1".to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let patch = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|req| req.method == http::Method::PATCH)
            .expect("release must issue a status PATCH");
        assert_eq!(
            patch
                .headers
                .get("content-type")
                .map(|value| value.to_str().unwrap()),
            Some("application/json-patch+json"),
            "a merge patch cannot express a precondition; release must use JSON Patch"
        );
        let ops: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        let tests: Vec<(&str, &serde_json::Value)> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|op| op["op"] == "test")
            .map(|op| (op["path"].as_str().unwrap(), &op["value"]))
            .collect();
        assert!(
            tests.contains(&("/metadata/uid", &serde_json::json!("rel-1-uid"))),
            "release must pin the exact lease UID: {tests:?}"
        );
        assert!(
            tests
                .iter()
                .any(|(path, _)| *path == "/metadata/resourceVersion"),
            "release must pin the observed resourceVersion: {tests:?}"
        );
    }

    /// A rejected precondition means the authorized object is gone; report 404
    /// (the same answer an unowned lease gets) rather than a 500.
    #[tokio::test]
    async fn release_reports_precondition_failure_as_not_found() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let state = AppState {
            client,
            backend: crate::testutil::MockBackend::new(),
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator: Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string())),
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/rel-2",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_object_json(
                "rel-2",
                &test_identity().identity,
                "Bound",
                Some("pool-ci-small-6"),
            )))
            .mount(&server)
            .await;
        // What the API server returns when a JSON Patch `test` op fails.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/rel-2/status",
            ))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "message": "the object has been modified",
                "reason": "Conflict",
                "code": 409
            })))
            .mount(&server)
            .await;

        let response = release_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Path("rel-2".to_string()),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a failed precondition must not surface as a 500"
        );
    }

    fn lease_object_json(
        name: &str,
        requester_identity: &str,
        phase: &str,
        cluster_name: Option<&str>,
    ) -> serde_json::Value {
        let binding = cluster_name.map(|cluster_name| exact_connect_binding(name, cluster_name));
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
                "resourceVersion": "10",
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
                "binding": binding,
                // Future expiry so the connect proxy's TTL gate treats it as live.
                "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                "queuePosition": 0
            }
        })
    }

    fn secret_object_json(name: &str, token: &str) -> serde_json::Value {
        let lease_name = name.strip_suffix("-connect-token").unwrap_or(name);
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": format!("{name}-uid"),
                "resourceVersion": "5",
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterLease",
                    "name": lease_name,
                    "uid": format!("{lease_name}-uid")
                }]
            },
            "data": {
                "token": base64::engine::general_purpose::STANDARD.encode(token)
            },
            "type": "Opaque"
        })
    }

    fn exact_connect_binding(lease_name: &str, cluster_name: &str) -> LeaseBinding {
        LeaseBinding {
            binding_id: format!("binding-{lease_name}"),
            lease: crate::crd::ResourceRef {
                name: lease_name.to_string(),
                uid: Some(format!("{lease_name}-uid")),
            },
            instance: crate::crd::BoundInstanceRef {
                name: cluster_name.to_string(),
                uid: format!("{cluster_name}-uid"),
                observed_generation: 1,
            },
            pool: crate::crd::ResourceRef {
                name: "ci-small".to_string(),
                uid: Some("ci-small-uid".to_string()),
            },
            backend: crate::crd::BackendProvenance::from_config(
                &crate::crd::BackendConfig::default(),
            )
            .unwrap(),
            instance_spec_digest: "0123456789abcdef".to_string(),
            cleanup_mode: crate::crd::CleanupMode::Standard,
            creation_manifest_digest: None,
            creation_manifest: None,
            connect_token: None,
        }
    }

    fn exact_connect_instance_json(lease_name: &str, cluster_name: &str) -> serde_json::Value {
        let binding = exact_connect_binding(lease_name, cluster_name);
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": cluster_name,
                "namespace": "test-ns",
                "uid": format!("{cluster_name}-uid"),
                "resourceVersion": "20",
                "generation": 1,
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "ci-small",
                    "uid": "ci-small-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "ci-small", "uid": "ci-small-uid" } },
            "status": {
                "phase": "Leased",
                "provisioned": true,
                "bootstrapped": true,
                "leaseRef": { "name": lease_name, "uid": format!("{lease_name}-uid") },
                "binding": binding,
                "specHash": "0123456789abcdef",
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "ci-small-uid",
                    "backend": crate::crd::BackendProvenance::from_config(
                        &crate::crd::BackendConfig::default(),
                    ).unwrap()
                }
            }
        })
    }

    fn exact_connect_pool_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "ci-small",
                "namespace": "test-ns",
                "uid": "ci-small-uid",
                "resourceVersion": "30"
            },
            "spec": {
                "size": 1,
                "backend": { "type": "k3s" },
                "cluster": { "version": "v1.32.0" }
            }
        })
    }

    fn kubeconfig_secret_json(cluster_name: &str, kubeconfig: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": format!("{cluster_name}-kubeconfig"),
                "namespace": "test-ns",
                "uid": format!("{cluster_name}-kubeconfig-uid")
            },
            "data": {
                "kubeconfig": base64::engine::general_purpose::STANDARD.encode(kubeconfig)
            }
        })
    }

    async fn mount_exact_connect_objects(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-ci-small-6",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(exact_connect_instance_json(
                "lease-abc",
                "pool-ci-small-6",
            )))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/ci-small",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(exact_connect_pool_json()))
            .mount(server)
            .await;
    }

    async fn mount_backend_kubeconfig(
        server: &wiremock::MockServer,
        kubeconfig: &str,
        expected_reads: std::ops::RangeInclusive<u64>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/pool-ci-small-6-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(kubeconfig_secret_json("pool-ci-small-6", kubeconfig)),
            )
            .expect(expected_reads)
            .mount(server)
            .await;
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

    /// Build a raw `axum::extract::Request` for the connect-proxy handlers,
    /// which now take the whole request (so they can hand it to the upgrade
    /// tunnel). The URI here is irrelevant to the handler — it reads the path
    /// from the `Path` extractor and the query from the request URI — but we
    /// set the query so the buffered/upgrade paths see it.
    fn connect_request(
        method: Method,
        headers: HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> axum::extract::Request {
        let uri = match query {
            Some(q) => format!("/?{q}"),
            None => "/".to_string(),
        };
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        builder.body(body).unwrap()
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

    /// Disabled mode must expose no Sandbox API at all. In particular, POST
    /// cannot reserve quota for a lease when the placement and release
    /// controllers were deliberately not started.
    #[tokio::test]
    async fn disabled_mode_serves_no_sandbox_api() {
        let (app, _server) = test_app_with_sandbox(false).await;
        for (method, uri) in [
            (Method::POST, "/v1/sandbox-leases"),
            (Method::POST, "/v1/sandbox-leases/sandbox-test/executions"),
            (Method::GET, "/v1/sandbox-leases/sandbox-test/attach"),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
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
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![exact_connect_pool_json()]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/(clusterleases|clusterinstances|cidrclaims)",
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

        let body = response_text(resp).await;
        assert!(body.contains("kobe_ipam_pool_allocated 0"));
        assert!(body.contains("kobe_lease_oldest_pending_age_seconds"));
        assert!(body.contains("kobe_instance_oldest_creating_age_seconds"));
    }

    #[tokio::test]
    async fn test_metrics_exports_live_ages_and_ipam_occupancy() {
        let (app, server) = test_app().await;
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let two_minutes_ago = (chrono::Utc::now() - chrono::Duration::minutes(2)).to_rfc3339();
        let lists = [
            (
                "clusterpools",
                crate::testutil::k8s_list_response(vec![exact_connect_pool_json()]),
            ),
            (
                "clusterleases",
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterLease",
                    "metadata": { "name": "lease-waiting", "namespace": "test-ns", "creationTimestamp": two_minutes_ago },
                    "spec": {
                        "poolRef": "ci-small",
                        "ttl": "1h",
                        "requester": { "type": "test:ci", "identity": "test" }
                    },
                    "status": { "phase": "Pending" }
                })]),
            ),
            (
                "clusterinstances",
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterInstance",
                    "metadata": { "name": "ci-small-0", "namespace": "test-ns" },
                    "spec": { "poolRef": { "name": "ci-small" } },
                    "status": { "phase": "Creating", "stateSince": two_minutes_ago }
                })]),
            ),
            (
                "cidrclaims",
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "CIDRClaim",
                    "metadata": { "name": "ci-small-0", "namespace": "test-ns" },
                    "spec": {},
                    "status": { "phase": "Bound" }
                })]),
            ),
        ];
        for (resource, response) in lists {
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/.*/{resource}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&server)
                .await;
        }

        let resp = app
            .oneshot(
                http::Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_text(resp).await;

        let value = |series: &str| -> f64 {
            body.lines()
                .find(|line| line.starts_with(series))
                .and_then(|line| line.rsplit_once(' '))
                .and_then(|(_, value)| value.parse().ok())
                .unwrap_or_else(|| panic!("missing metric series {series}"))
        };
        assert_eq!(value("kobe_ipam_pool_allocated"), 1.0);
        for series in [
            "kobe_lease_oldest_pending_age_seconds{profile=\"ci-small\"}",
            "kobe_instance_oldest_creating_age_seconds{profile=\"ci-small\"}",
        ] {
            let age = value(series);
            assert!((119.0..=122.0).contains(&age), "unexpected age {age}");
        }
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
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
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
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/namespaces/.*/secrets/lease-abc-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_object_json("lease-abc-connect-token", "lease-token")),
            )
            .with_priority(2)
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
        mount_exact_connect_objects(&server).await;

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
        let backend_kubeconfig = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: {}\nusers:\n- name: default\n  user:\n    token: backend-token\n",
            server.uri()
        );
        backend.set_kubeconfig(&backend_kubeconfig);
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let datastore = crate::backend::datastore::SharedDatastore::default();
        let factory = BackendFactory::new(client.clone(), datastore.clone());
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: Some(factory),
            datastore,
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
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
        mount_exact_connect_objects(&server).await;
        mount_backend_kubeconfig(&server, &backend_kubeconfig, 1..=1).await;
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
            connect_request(Method::GET, headers, None, Body::empty()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_text(response).await, r#"{"gitVersion":"v1.32.0"}"#);
    }

    /// A miss populates the per-lease cache, and a subsequent request HITS it.
    ///
    /// The cache is a *credential* cache, never an *authorization* cache. It
    /// pins exactly which work a hit is allowed to skip:
    ///
    /// - skipped on a hit: the backend kubeconfig read (the expensive,
    ///   mintable part);
    /// - repeated on every hit: connect-token authentication and UID-fenced
    ///   binding resolution, which
    ///   re-GETs the lease (`expect(2)`) so release, expiry, or a rebind to a
    ///   different `ClusterInstance` UID is observed on the *next* request
    ///   rather than at cache-TTL expiry.
    ///
    /// wiremock fails on server drop if any count is off, so these numbers are
    /// the assertion. Dropping the lease GET to 1 would mean a released lease
    /// keeps proxying until its cache entry ages out — the exact hole #79
    /// closes.
    #[tokio::test]
    async fn test_connect_proxy_caches_lease_context_across_requests() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let backend_kubeconfig = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: {}\nusers:\n- name: default\n  user:\n    token: backend-token\n",
            server.uri()
        );
        backend.set_kubeconfig(&backend_kubeconfig);
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let datastore = crate::backend::datastore::SharedDatastore::default();
        let factory = BackendFactory::new(client.clone(), datastore.clone());
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: Some(factory),
            datastore,
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        use wiremock::matchers::{header, method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        // Token authentication runs on every request. The cache holds backend
        // context, not authorization, so deletion/replacement revokes at once.
        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/namespaces/.*/secrets/lease-abc-connect-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_object_json("lease-abc-connect-token", "lease-token")),
            )
            .expect(2)
            .mount(&server)
            .await;
        mount_exact_connect_objects(&server).await;
        mount_backend_kubeconfig(&server, &backend_kubeconfig, 1..=1).await;
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
            // Once per request: the hit re-runs `resolve_lease_binding` so the
            // UID fence is re-checked, not trusted from cache.
            .expect(2)
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

        let make_request = || {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, "Bearer lease-token".parse().unwrap());
            connect_proxy::<crate::testutil::MockBackend>(
                State(state.clone()),
                Path(("lease-abc".to_string(), "version".to_string())),
                connect_request(Method::GET, headers, None, Body::empty()),
            )
        };

        // First request: cold miss, populates the cache.
        let first = make_request().await;
        assert_eq!(first.status(), StatusCode::OK);
        assert!(
            matches!(
                state.connect_cache.lookup("lease-abc", "lease-token"),
                CacheLookup::Hit(..)
            ),
            "the miss should have populated the cache"
        );

        // Second request: backend context is cached, while the exact Secret and
        // binding are deliberately re-read.
        let second = make_request().await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(response_text(second).await, r#"{"gitVersion":"v1.32.0"}"#);
    }

    // #85: exec/attach/port-forward negotiate an HTTP upgrade. The connect proxy
    // now TUNNELS these (no longer a 501) by driving a raw hyper client over the
    // backend TLS config. This test exercises the dispatch: lease validation
    // passes, the upgrade branch is taken, and the tunnel is attempted. The
    // wiremock backend speaks plain HTTP (no TLS, no 101), so the tunnel can't
    // complete — we assert it is NOT the old 501 and that the error body is
    // generic (no raw upstream / infra leak), per the redaction policy.
    #[tokio::test]
    async fn test_connect_proxy_tunnels_http_upgrade_instead_of_501() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let backend_kubeconfig = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: {}\nusers:\n- name: default\n  user:\n    token: backend-token\n",
            server.uri()
        );
        backend.set_kubeconfig(&backend_kubeconfig);
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let datastore = crate::backend::datastore::SharedDatastore::default();
        let factory = BackendFactory::new(client.clone(), datastore.clone());
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: Some(factory),
            datastore,
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        use wiremock::matchers::{method, path_regex};
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
        mount_exact_connect_objects(&server).await;
        mount_backend_kubeconfig(&server, &backend_kubeconfig, 1..=1).await;
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

        // A SPDY exec request: Connection: Upgrade + Upgrade: SPDY/3.1.
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer lease-token".parse().unwrap());
        headers.insert(CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(UPGRADE, "SPDY/3.1".parse().unwrap());

        let response = connect_proxy::<crate::testutil::MockBackend>(
            State(state),
            Path((
                "lease-abc".to_string(),
                "api/v1/namespaces/default/pods/foo/exec".to_string(),
            )),
            connect_request(Method::GET, headers, None, Body::empty()),
        )
        .await;

        // The upgrade branch was taken (validation passed, tunnel attempted).
        // It is no longer the old 501 NOT_IMPLEMENTED guard.
        assert_ne!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "upgrade requests should be tunneled, not rejected with 501"
        );
        // wiremock can't complete a TLS upgrade -> generic gateway error.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response_text(response).await;
        // Body must be a short generic message, never a raw upstream/infra leak.
        assert!(
            !body.contains("127.0.0.1") && !body.contains(&server.uri()),
            "upgrade error body must not leak backend address: {body}"
        );
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
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        let response = connect_proxy::<crate::testutil::MockBackend>(
            State(state),
            Path(("lease-abc".to_string(), "version".to_string())),
            connect_request(Method::GET, HeaderMap::new(), None, Body::empty()),
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
    async fn list_pools_returns_mixed_kinds_with_effective_capabilities() {
        use crate::api::policy::SandboxPolicy;
        use crate::crd::{SandboxResourceCeiling, SandboxVerb};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let state = AppState {
            client,
            backend: crate::testutil::MockBackend::new(),
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator: Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string())),
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![exact_connect_pool_json()]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "SandboxPool",
                    "metadata": {
                        "name": "agent-small",
                        "namespace": "test-ns",
                        "uid": "sandbox-pool-uid",
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
                            "exposedPorts": [{
                                "name": "http",
                                "container": "agent",
                                "port": 3000
                            }]
                        },
                        "isolation": { "tier": "trusted-runc" },
                        "readiness": {
                            "canary": { "argv": ["/bin/true"], "timeout": "30s" }
                        }
                    }
                })]),
            ))
            .mount(&server)
            .await;

        let mut identity = test_identity();
        identity.policy.allowed_pools = vec!["ci-*".to_string()];
        identity.policy.sandbox = Some(SandboxPolicy {
            allowed_pools: vec!["agent-*".to_string()],
            verbs: vec![
                SandboxVerb::Lease,
                SandboxVerb::Exec,
                SandboxVerb::Logs,
                SandboxVerb::Release,
            ],
            max_ttl: chrono::Duration::hours(4),
            max_concurrent_leases: 2,
            max_extensions: 0,
            resource_ceiling: SandboxResourceCeiling {
                max_cpu: "2".to_string(),
                max_memory: "2Gi".to_string(),
            },
        });

        let response = list_pools::<crate::testutil::MockBackend>(State(state), identity).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let pools = body.as_array().unwrap();
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0]["name"], "agent-small");
        assert_eq!(pools[0]["resourceKind"], "Sandbox");
        let sandbox_capabilities = pools[0]["capabilities"].as_array().unwrap();
        for capability in ["lease", "exec", "cancel", "attach", "logs", "release"] {
            assert!(sandbox_capabilities.contains(&serde_json::json!(capability)));
        }
        assert!(!sandbox_capabilities.contains(&serde_json::json!("port-forward")));
        assert!(!sandbox_capabilities.contains(&serde_json::json!("extend")));
        assert_eq!(pools[1]["name"], "ci-small");
        assert_eq!(pools[1]["resourceKind"], "Cluster");
        assert!(
            pools[1]["capabilities"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("kubeconfig"))
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

    // #107 P2: alias-holder resolution keeps only the caller's ACTIVE leases and
    // orders them oldest-first, so the first holder deterministically keeps the
    // alias. (The alias-label match itself is a server-side label selector; here
    // every claim carries the alias so we exercise the in-process identity /
    // phase / ordering logic.)
    #[tokio::test]
    async fn test_active_alias_holders_sorted_filters_and_orders() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let identity = "repo:org/repo:ref:refs/heads/main";

        let claim = |name: &str, ts: &str, phase: &str, id: &str| {
            serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns",
                    "creationTimestamp": ts,
                    "labels": { "kobe.kunobi.ninja/alias": "pr-1" }
                },
                "spec": {
                    "poolRef": "e2e-basic", "ttl": "1h",
                    "requester": { "type": "github-actions:ci", "identity": id },
                    "priority": 50
                },
                "status": { "phase": phase }
            })
        };
        let claims = vec![
            // Newer active holder.
            claim("newer", "2026-01-02T00:00:00Z", "Bound", identity),
            // Older active holder — should sort first.
            claim("older", "2026-01-01T00:00:00Z", "Pending", identity),
            // Terminal — excluded.
            claim("gone", "2026-01-01T00:00:00Z", "Released", identity),
            // Another identity — excluded.
            claim(
                "foreign",
                "2026-01-01T00:00:00Z",
                "Bound",
                "repo:other:ref:x",
            ),
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
        let holders = active_alias_holders_sorted(&leases_api, identity, "pr-1")
            .await
            .unwrap();
        assert_eq!(holders, vec!["older".to_string(), "newer".to_string()]);
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

    // --- #189: create_lease pool pre-flight (503 vs 202) ---

    /// Build a `(state, server)` pair for direct create_lease handler calls.
    async fn preflight_state() -> (AppState<crate::testutil::MockBackend>, wiremock::MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = crate::testutil::MockBackend::new();
        let authenticator = Arc::new(crate::api::auth::JwtAuthenticator::new("test".to_string()));
        let state = AppState {
            client,
            backend,
            namespace: "test-ns".to_string(),
            sandbox_reservation_namespace: "test-ns".to_string(),
            sandbox_serving_replica: None,
            authenticator,
            factory: None,
            datastore: Default::default(),
            connect_cache: Default::default(),
            sandbox_admission_limiter: Default::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sandbox_enabled: true,
        };
        (state, server)
    }

    /// A pool JSON value with a given status block. `e2e-basic` matches the
    /// `e2e-*` pool allow-list on `test_identity()`.
    fn pool_with_status(name: &str, status: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": { "name": name, "namespace": "test-ns" },
            "spec": { "size": 3, "ttl": "2h", "cluster": { "version": "v1.31.3+k3s1" } },
            "status": status
        })
    }

    #[tokio::test]
    async fn create_lease_rejects_invalid_metadata_before_cluster_calls() {
        let (state, server) = preflight_state().await;
        let response = create_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Json(CreateLeaseRequest {
                profile: Some("e2e-basic".to_string()),
                metadata: Some(serde_json::json!(["not", "an", "object"])),
                ..CreateLeaseRequest::default()
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["error"].as_str(), Some("Invalid lease metadata"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_create_lease_against_failing_pool_returns_503_with_retry_after_and_reason() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let (state, server) = preflight_state().await;
        mount_missing_sandbox_pool(&server, "e2e-basic").await;

        // count_active_leases: the requester has no active leases.
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        // The pool is Failing, with a known next_attempt_at so Retry-After is
        // derived from it (~120s out).
        let next = (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/e2e-basic",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool_with_status(
                "e2e-basic",
                serde_json::json!({
                    "phase": "Failing",
                    "consecutiveFailures": 5,
                    "lastFailureReason": "server StatefulSet not reaching Ready",
                    "nextAttemptAt": next,
                }),
            )))
            .mount(&server)
            .await;

        // No POST mock: a 503 pre-flight must NOT create a lease.
        let response = create_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Json(CreateLeaseRequest {
                profile: Some("e2e-basic".to_string()),
                ..CreateLeaseRequest::default()
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .expect("Retry-After header present and numeric");
        assert!(
            (1..=120).contains(&retry_after),
            "Retry-After should be derived from next_attempt_at, got {retry_after}"
        );
        let body = response_json(response).await;
        assert_eq!(body["reason"].as_str(), Some("pool_exhausted"));
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("phase=Failing"),
            "detail should carry the pool health: {body:?}"
        );
    }

    #[tokio::test]
    async fn test_create_lease_against_healthy_pool_returns_202() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let (state, server) = preflight_state().await;
        mount_missing_sandbox_pool(&server, "e2e-basic").await;

        // Both the count and the post-create re-list see no active leases.
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(&server)
            .await;

        // Healthy pool with no Ready right now (warming) — must NOT 503.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/e2e-basic",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool_with_status(
                "e2e-basic",
                serde_json::json!({ "phase": "Healthy", "ready": 1 }),
            )))
            .mount(&server)
            .await;

        // The lease gets created (202 path).
        Mock::given(method("POST"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterLease",
                "metadata": { "name": "lease-xxxxxxxxxxxx", "namespace": "test-ns" },
                "spec": { "poolRef": "e2e-basic", "ttl": "1h",
                           "requester": {"type": "github-actions:ci",
                                          "identity": test_identity().identity}, "priority": 100 }
            })))
            .mount(&server)
            .await;

        let metadata = serde_json::json!({
            "github": {"actor": "lenij", "pullRequest": 3835},
            "purpose": "e2e"
        });
        let response = create_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Json(CreateLeaseRequest {
                profile: Some("e2e-basic".to_string()),
                metadata: Some(metadata.clone()),
                ..CreateLeaseRequest::default()
            }),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "a healthy pool must keep the 202 Pending behavior"
        );
        assert!(
            response.headers().get("retry-after").is_none(),
            "202 must not carry a Retry-After header"
        );
        let body = response_json(response).await;
        assert_eq!(body["phase"].as_str(), Some("Pending"));
        assert_eq!(body["metadata"], metadata);

        let create = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method == http::Method::POST)
            .expect("the accepted request must create one ClusterLease");
        let created: serde_json::Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(created["spec"]["metadata"], metadata);
    }

    fn k8s_not_found(message: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "reason": "NotFound",
            "code": 404,
            "message": message
        })
    }

    fn sandbox_pool_named(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxPool",
            "metadata": {
                "name": name,
                "namespace": "test-ns",
                "uid": "sandbox-pool-uid",
                "generation": 1
            },
            "spec": {
                "warmCapacity": 1,
                "defaultTtl": "30m",
                "maxTtl": "2h",
                "provisioningTimeout": "10m",
                "placement": { "type": "management" },
                "template": {
                    "defaultContainer": "workspace",
                    "containers": [{
                        "name": "workspace",
                        "image": "example.invalid/busybox@sha256:abc",
                        "resources": {
                            "requests": {
                                "cpu": "50m",
                                "memory": "64Mi",
                                "ephemeralStorage": "64Mi"
                            },
                            "limits": {
                                "cpu": "250m",
                                "memory": "256Mi",
                                "ephemeralStorage": "256Mi"
                            }
                        }
                    }]
                },
                "isolation": { "tier": "trusted-runc" },
                "readiness": { "canary": { "argv": ["/bin/true"], "timeout": "30s" } }
            }
        })
    }

    async fn mount_missing_sandbox_pool(server: &wiremock::MockServer, name: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/{name}"
            )))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found(&format!("sandboxpools \"{name}\" not found"))),
            )
            .mount(server)
            .await;
    }

    async fn mount_empty_cluster_leases(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new()),
            ))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn create_lease_dispatches_a_sandbox_pool_without_creating_a_cluster_lease() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (state, server) = preflight_state().await;
        mount_empty_cluster_leases(&server).await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/e2e-agent",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("clusterpools \"e2e-agent\" not found")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/e2e-agent",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(sandbox_pool_named("e2e-agent")))
            .mount(&server)
            .await;

        let response = create_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Json(CreateLeaseRequest {
                profile: Some("e2e-agent".to_string()),
                ..CreateLeaseRequest::default()
            }),
        )
        .await;

        assert_ne!(
            response.status(),
            StatusCode::CONFLICT,
            "a Sandbox pool name must not 409 on POST /v1/leases"
        );
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a Sandbox pool that exists must not 404 on POST /v1/leases"
        );
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method == http::Method::POST)
            .count();
        assert_eq!(posts, 0, "must not create a ClusterLease");
    }

    #[tokio::test]
    async fn create_lease_returns_404_when_no_pool_exists() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (state, server) = preflight_state().await;
        mount_empty_cluster_leases(&server).await;

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/e2e-missing",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("clusterpools \"e2e-missing\" not found")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/e2e-missing",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("sandboxpools \"e2e-missing\" not found")),
            )
            .mount(&server)
            .await;

        let response = create_lease::<crate::testutil::MockBackend>(
            State(state),
            test_identity(),
            Json(CreateLeaseRequest {
                profile: Some("e2e-missing".to_string()),
                ..CreateLeaseRequest::default()
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("e2e-missing"),
            "error should name the pool: {body}"
        );
    }

    #[test]
    fn pool_preflight_rejection_passes_through_healthy_and_missing_status() {
        // No status → warming → no rejection (proceed to 202).
        let pool: ClusterPool =
            serde_json::from_value(pool_with_status("e2e-basic", serde_json::json!({}))).unwrap();
        assert!(pool_preflight_rejection("e2e-basic", &pool).is_none());

        // Healthy → no rejection.
        let pool: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Healthy" }),
        ))
        .unwrap();
        assert!(pool_preflight_rejection("e2e-basic", &pool).is_none());
    }

    #[tokio::test]
    async fn pool_preflight_rejection_rejects_failing_pool() {
        let pool: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Failing", "consecutiveFailures": 3 }),
        ))
        .unwrap();
        let resp =
            pool_preflight_rejection("e2e-basic", &pool).expect("a Failing pool must be rejected");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // Absent next_attempt_at → the default Retry-After.
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some(
                LEASE_PREFLIGHT_DEFAULT_RETRY_AFTER_SECS
                    .to_string()
                    .as_str()
            )
        );
    }

    #[tokio::test]
    async fn pool_preflight_rejection_serves_failing_pool_with_ready_members() {
        // A Failing pool that still has Ready clusters must NOT be rejected:
        // broken replacement provisioning doesn't invalidate the members that
        // already came up, and the bind path serves Ready clusters regardless
        // of pool phase (2026-07-20 incident: 5 Ready / 0 leased, every CI
        // claim 503'd until an operator intervened).
        let pool: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Failing", "consecutiveFailures": 10, "ready": 5 }),
        ))
        .unwrap();
        assert!(
            pool_preflight_rejection("e2e-basic", &pool).is_none(),
            "Failing pool with ready>0 must proceed to the 202 path"
        );

        // Same for Backoff: ready>0 already bypasses via the existing guard.
        let pool: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Backoff", "consecutiveFailures": 2, "ready": 1 }),
        ))
        .unwrap();
        assert!(pool_preflight_rejection("e2e-basic", &pool).is_none());
    }

    #[test]
    fn pool_preflight_holds_quarantined_capacity_but_serves_ready_members() {
        let held: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Quarantined", "quarantined": 1, "ready": 0 }),
        ))
        .unwrap();
        let response = pool_preflight_rejection("e2e-basic", &held)
            .expect("quarantined-only capacity cannot advance a lease queue");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let mixed: ClusterPool = serde_json::from_value(pool_with_status(
            "e2e-basic",
            serde_json::json!({ "phase": "Quarantined", "quarantined": 1, "ready": 1 }),
        ))
        .unwrap();
        assert!(pool_preflight_rejection("e2e-basic", &mixed).is_none());
    }
}
